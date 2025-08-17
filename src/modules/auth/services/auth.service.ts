import {
  ConflictException,
  Inject,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import * as bcrypt from 'bcryptjs';
import * as jwt from 'jsonwebtoken';
import { Db, ObjectId } from 'mongodb';
import { DATABASE_CONNECTION } from '../../../common/providers/mongo.provider';
import { SigninDto } from '../dto/signin.dto';
import { SignupDto } from '../dto/signup.dto';
import { User } from '../entities/user.entity';

const JWT_SECRET = process.env.JWT_SECRET || 'changeme';
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'refreshchangeme';

@Injectable()
export class AuthService {
  constructor(@Inject(DATABASE_CONNECTION) private readonly db: Db) {}

  async signup(dto: SignupDto) {
    const existing = await this.db
      .collection('users')
      .findOne({ email: dto.email });
    if (existing) throw new ConflictException('Email already in use');
    const hashed = await bcrypt.hash(dto.password, 10);
    const user = {
      email: dto.email,
      password: hashed,
      name: dto.fullName || '',
      createdAt: new Date(),
    };
    const result = await this.db.collection<User>('users').insertOne(user);
    const payload = { sub: result.insertedId, email: user.email };
    const accessToken = jwt.sign(payload, JWT_SECRET, { expiresIn: '15m' });
    const refreshToken = jwt.sign(payload, JWT_REFRESH_SECRET, {
      expiresIn: '7d',
    });
    return {
      accessToken,
      refreshToken,
      user: { id: result.insertedId, email: user.email, name: user.name },
    };
  }

  async signin(dto: SigninDto) {
    const user = await this.db
      .collection('users')
      .findOne({ email: dto.email });
    if (!user) throw new UnauthorizedException('Invalid credentials');
    const valid = await bcrypt.compare(dto.password, user.password);
    if (!valid) throw new UnauthorizedException('Invalid credentials');
    const payload = { sub: user._id, email: user.email };
    const accessToken = jwt.sign(payload, JWT_SECRET, { expiresIn: '15m' });
    const refreshToken = jwt.sign(payload, JWT_REFRESH_SECRET, {
      expiresIn: '7d',
    });
    return {
      accessToken,
      refreshToken,
      user: { id: user._id, email: user.email, name: user.name },
    };
  }

  async refresh(refreshToken: string) {
    try {
      const payload = jwt.verify(refreshToken, JWT_REFRESH_SECRET) as any;
      const user = await this.db
        .collection('users')
        .findOne({ _id: new ObjectId(payload.sub) });
      if (!user) throw new UnauthorizedException('User not found');
      const newPayload = { sub: user._id, email: user.email };
      const accessToken = jwt.sign(newPayload, JWT_SECRET, {
        expiresIn: '15m',
      });
      return { accessToken };
    } catch (e) {
      throw new UnauthorizedException('Invalid refresh token');
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
}
