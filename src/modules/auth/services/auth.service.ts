import {
  ConflictException,
  Inject,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import * as bcrypt from 'bcryptjs';
import { randomBytes } from 'crypto';
import * as jwt from 'jsonwebtoken';
import { Db, ObjectId } from 'mongodb';
import { DATABASE_CONNECTION } from '../../../common/providers/mongo.provider';
import { MailerService } from '../../../common/services/mailer.service';
import { getI18nText } from '../../../common/utils/i18n';
import { SigninDto } from '../dto/signin.dto';
import { SignupDto } from '../dto/signup.dto';
import { EmailVerification } from '../entities/email-verification.entity';
import { User } from '../entities/user.entity';

const JWT_SECRET = process.env.JWT_SECRET || 'changeme';
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'refreshchangeme';

const RATE_LIMIT_WINDOW_MS = 10 * 60 * 1000; // 10 minutes
const RATE_LIMIT_MAX = 3;
const rateLimitMap = new Map<string, { count: number; last: number }>();

@Injectable()
export class AuthService {
  constructor(
    @Inject(DATABASE_CONNECTION) private readonly db: Db,
    private readonly mailer: MailerService,
  ) {}

  private async sendVerificationEmail(user: User, email: string) {
    const userId = user._id
      ? user._id.toString()
      : (() => {
          throw new Error('User _id is required for verification email');
        })();
    // Clean up expired tokens for this user
    await this.db
      .collection<EmailVerification>('emailVerifications')
      .deleteMany({
        userId,
        expiresAt: { $lt: new Date() },
      });
    // Remove any existing tokens for this user
    await this.db
      .collection<EmailVerification>('emailVerifications')
      .deleteMany({
        userId,
      });
    // Generate new token
    const token = randomBytes(32).toString('hex');
    await this.db
      .collection<EmailVerification>('emailVerifications')
      .insertOne({
        userId,
        token,
        expiresAt: new Date(Date.now() + 1000 * 60 * 60), // 1 hour
      });
    // Send i18n email
    const verifyUrl = `${process.env.FRONTEND_URL}/auth/verify-email?token=${token}`;
    const subject = getI18nText('email.verify_subject', user);
    const html = getI18nText('email.verify_body', user, { verifyUrl });
    await this.mailer.sendMail(email, subject, html);
  }

  async signup(dto: SignupDto) {
    const existing = await this.db
      .collection<User>('users')
      .findOne({ email: dto.email });
    if (existing) throw new ConflictException('Email already in use');

    const hashed = await bcrypt.hash(dto.password, 10);

    const user: User = {
      email: dto.email,
      password: hashed,
      name: dto.name || '',
      role: 'member',
      createdAt: new Date(),
      isValidated: false, // ✅ not verified yet
      isActive: true,
    };

    const result = await this.db.collection<User>('users').insertOne(user);
    const createdUser = { ...user, _id: result.insertedId };

    // ✅ Send verification email (modular)
    await this.sendVerificationEmail(createdUser, dto.email);

    return {
      message:
        'User created successfully. Please check your email to verify your account.',
    };
  }

  async verifyEmail(token: string) {
    const record = await this.db
      .collection<EmailVerification>('emailVerifications')
      .findOne({ token });

    if (!record || record.expiresAt < new Date()) {
      throw new UnauthorizedException('Invalid or expired verification token');
    }

    // Get the user
    const user = await this.db
      .collection<User>('users')
      .findOne({ _id: new ObjectId(record.userId) });

    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    // Mark email as verified
    await this.db
      .collection<User>('users')
      .updateOne(
        { _id: new ObjectId(record.userId) },
        { $set: { isValidated: true } },
      );

    // ✅ delete token after use
    await this.db
      .collection('emailVerifications')
      .deleteOne({ _id: record._id });

    // Generate authentication tokens
    const payload = { sub: user._id, email: user.email, role: user.role };
    const accessToken = jwt.sign(payload, JWT_SECRET, { expiresIn: '15m' });
    const refreshToken = jwt.sign(payload, JWT_REFRESH_SECRET, {
      expiresIn: '7d',
    });

    return {
      message: 'Email verified successfully. You are now logged in.',
      accessToken,
      refreshToken,
      user: {
        id: user._id,
        email: user.email,
        fullName: user.name,
        role: user.role,
        isVerified: true,
        isOnBoarded: false, // Will be set during onboarding
      },
    };
  }

  async signin(dto: SigninDto) {
    const user = await this.db
      .collection<User>('users')
      .findOne({ email: dto.email });
    if (!user) throw new UnauthorizedException('Invalid credentials');

    // ✅ block login until email verified
    if (!user.isValidated) {
      throw new UnauthorizedException(
        'Please verify your email before logging in',
      );
    }

    const valid = await bcrypt.compare(dto.password, user.password);
    if (!valid) throw new UnauthorizedException('Invalid credentials');

    const payload = { sub: user._id, email: user.email, role: user.role };
    const accessToken = jwt.sign(payload, JWT_SECRET, { expiresIn: '15m' });
    const refreshToken = jwt.sign(payload, JWT_REFRESH_SECRET, {
      expiresIn: '7d',
    });

    return {
      accessToken,
      refreshToken,
      user: {
        id: user._id,
        email: user.email,
        fullName: user.name,
        role: user.role,
      },
    };
  }

  async refresh(refreshToken: string) {
    try {
      const payload = jwt.verify(refreshToken, JWT_REFRESH_SECRET) as any;
      const user = await this.db
        .collection<User>('users')
        .findOne({ _id: new ObjectId(payload.sub) });

      if (!user) {
        throw new UnauthorizedException('User not found');
      }

      const newPayload = { sub: user._id, email: user.email, role: user.role };
      const newAccessToken = jwt.sign(newPayload, JWT_SECRET, {
        expiresIn: '15m',
      });

      return { accessToken: newAccessToken };
    } catch (error) {
      throw new UnauthorizedException('Invalid refresh token');
    }
  }

  async logout(userId: string) {
    try {
      // In a more sophisticated system, you might want to:
      // 1. Add the refresh token to a blacklist
      // 2. Clear any session data
      // 3. Log the logout event

      // For now, we'll just return success
      // The frontend will clear cookies, and the backend will reject expired tokens

      return { message: 'Logged out successfully' };
    } catch (error) {
      throw new UnauthorizedException('Logout failed');
    }
  }

  async getMeFromPayload(payload: any) {
    const { sub } = payload;
    const user = await this.db
      .collection('users')
      .findOne({ _id: new ObjectId(sub) }, { projection: { password: 0 } });
    if (!user) throw new UnauthorizedException('User not found');
    return user;
  }

  async resendVerification(email: string, ip: string) {
    const key = `${email}:${ip}`;
    const now = Date.now();
    const entry = rateLimitMap.get(key) || { count: 0, last: 0 };
    if (now - entry.last > RATE_LIMIT_WINDOW_MS) {
      entry.count = 0;
      entry.last = now;
    }
    entry.count++;
    entry.last = now;
    rateLimitMap.set(key, entry);
    if (entry.count > RATE_LIMIT_MAX) {
      throw new UnauthorizedException(
        'Too many requests. Please try again later.',
      );
    }

    const user = await this.db.collection<User>('users').findOne({ email });
    if (!user) throw new UnauthorizedException('User not found');
    if (user.isValidated) {
      return { message: getI18nText('email.already_verified', user) };
    }

    // Modular: send verification email
    await this.sendVerificationEmail(user, email);

    return { message: getI18nText('email.resent', user) };
  }
}
