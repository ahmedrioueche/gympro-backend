import { Db, ObjectId } from 'mongodb';
export declare class AuthService {
    private readonly db;
    constructor(db: Db);
    signup(dto: {
        email: string;
        password: string;
        name?: string;
    }): Promise<{
        accessToken: string;
        refreshToken: string;
        user: {
            id: ObjectId;
            email: string;
            name: string;
        };
    }>;
    signin(dto: {
        email: string;
        password: string;
    }): Promise<{
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
    getMe(token?: string): Promise<import("mongodb").WithId<import("bson").Document>>;
}
