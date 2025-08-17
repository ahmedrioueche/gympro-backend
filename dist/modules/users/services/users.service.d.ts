import { Db } from 'mongodb';
export declare class UsersService {
    private readonly db;
    constructor(db: Db);
    findAll(): Promise<import("mongodb").WithId<import("bson").Document>[]>;
    create(user: any): Promise<import("mongodb").InsertOneResult<import("bson").Document>>;
}
