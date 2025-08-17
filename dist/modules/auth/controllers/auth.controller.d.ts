import { RefreshDto } from '../dto/refresh.dto';
import { SigninDto } from '../dto/signin.dto';
import { SignupDto } from '../dto/signup.dto';
import { AuthService } from '../services/auth.service';
export declare class AuthController {
    private readonly authService;
    constructor(authService: AuthService);
    signup(dto: SignupDto): Promise<{
        accessToken: string;
        refreshToken: string;
        user: {
            id: import("bson").ObjectId;
            email: string;
            name: string;
        };
    }>;
    signin(dto: SigninDto): Promise<{
        accessToken: string;
        refreshToken: string;
        user: {
            id: import("bson").ObjectId;
            email: any;
            name: any;
        };
    }>;
    refresh(dto: RefreshDto): Promise<{
        accessToken: string;
    }>;
    getMe(req: any): Promise<import("mongodb").WithId<import("bson").Document>>;
}
