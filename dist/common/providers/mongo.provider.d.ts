import { Db } from 'mongodb';
export declare const DATABASE_CONNECTION = "DATABASE_CONNECTION";
export declare const mongoProvider: {
    provide: string;
    useFactory: () => Promise<Db>;
};
