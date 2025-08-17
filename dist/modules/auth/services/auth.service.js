"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuthService = void 0;
const common_1 = require("@nestjs/common");
const bcrypt = __importStar(require("bcryptjs"));
const jwt = __importStar(require("jsonwebtoken"));
const mongodb_1 = require("mongodb");
const mongo_provider_1 = require("../../../common/providers/mongo.provider");
const JWT_SECRET = process.env.JWT_SECRET || 'changeme';
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'refreshchangeme';
let AuthService = class AuthService {
    db;
    constructor(db) {
        this.db = db;
    }
    async signup(dto) {
        const existing = await this.db
            .collection('users')
            .findOne({ email: dto.email });
        if (existing)
            throw new common_1.ConflictException('Email already in use');
        const hashed = await bcrypt.hash(dto.password, 10);
        const user = {
            email: dto.email,
            password: hashed,
            name: dto.fullName || '',
            createdAt: new Date(),
        };
        const result = await this.db.collection('users').insertOne(user);
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
    async signin(dto) {
        const user = await this.db
            .collection('users')
            .findOne({ email: dto.email });
        if (!user)
            throw new common_1.UnauthorizedException('Invalid credentials');
        const valid = await bcrypt.compare(dto.password, user.password);
        if (!valid)
            throw new common_1.UnauthorizedException('Invalid credentials');
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
    async refresh(refreshToken) {
        try {
            const payload = jwt.verify(refreshToken, JWT_REFRESH_SECRET);
            const user = await this.db
                .collection('users')
                .findOne({ _id: new mongodb_1.ObjectId(payload.sub) });
            if (!user)
                throw new common_1.UnauthorizedException('User not found');
            const newPayload = { sub: user._id, email: user.email };
            const accessToken = jwt.sign(newPayload, JWT_SECRET, {
                expiresIn: '15m',
            });
            return { accessToken };
        }
        catch (e) {
            throw new common_1.UnauthorizedException('Invalid refresh token');
        }
    }
    async getMeFromPayload(payload) {
        const { sub } = payload;
        const user = await this.db
            .collection('users')
            .findOne({ _id: new mongodb_1.ObjectId(sub) }, { projection: { password: 0 } });
        if (!user)
            throw new common_1.UnauthorizedException('User not found');
        return user;
    }
};
exports.AuthService = AuthService;
exports.AuthService = AuthService = __decorate([
    (0, common_1.Injectable)(),
    __param(0, (0, common_1.Inject)(mongo_provider_1.DATABASE_CONNECTION)),
    __metadata("design:paramtypes", [mongodb_1.Db])
], AuthService);
//# sourceMappingURL=auth.service.js.map