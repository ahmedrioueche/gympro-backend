import { Db, ObjectId } from 'mongodb';
import { SigninDto } from '../dto/signin.dto';
import { SignupDto } from '../dto/signup.dto';
export declare class AuthService {
    private readonly db;
    constructor(db: Db);
    signup(dto: SignupDto): Promise<{
        accessToken: string;
        refreshToken: string;
        user: {
            id: ObjectId;
            email: string;
            name: string;
        };
    }>;
    signin(dto: SigninDto): Promise<{
        accessToken: string;
        refreshToken: string;
        user: {
            id: ObjectId;
            email: any;
            name: any;
        };
    }>;
    refresh(refreshToken: string): Promise<{
        accessToken: string;
    }>;
    getMeFromPayload(payload: any): Promise<import("mongodb").WithId<import("bson").Document>>;
}
