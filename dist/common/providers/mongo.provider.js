"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.mongoProvider = exports.DATABASE_CONNECTION = void 0;
const mongodb_1 = require("mongodb");
exports.DATABASE_CONNECTION = 'DATABASE_CONNECTION';
exports.mongoProvider = {
    provide: exports.DATABASE_CONNECTION,
    useFactory: async () => {
        const uri = process.env.MONGO_URI || 'mongodb://localhost:27017/gympro';
        const client = new mongodb_1.MongoClient(uri);
        await client.connect();
        return client.db();
    },
};
//# sourceMappingURL=mongo.provider.js.map