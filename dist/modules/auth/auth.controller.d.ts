import { AuthService } from './auth.service';
export declare class AuthController {
    private readonly authService;
    constructor(authService: AuthService);
    signup(dto: {
        email: string;
        password: string;
        name?: string;
    }): Promise<{
        accessToken: string;
        refreshToken: string;
        user: {
            id: import("bson").ObjectId;
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
            id: import("bson").ObjectId;
            email: any;
            name: any;
        };
    }>;
    refresh(dto: {
        refreshToken: string;
    }): Promise<{
        accessToken: string;
    }>;
    getMe(req: import('express').Request): Promise<import("mongodb").WithId<import("bson").Document>>;
}
