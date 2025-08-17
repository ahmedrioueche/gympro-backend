import { Db, MongoClient } from 'mongodb';

export const DATABASE_CONNECTION = 'DATABASE_CONNECTION';

export const mongoProvider = {
  provide: DATABASE_CONNECTION,
  useFactory: async (): Promise<Db> => {
    const uri = process.env.MONGO_URI || 'mongodb://localhost:27017/gympro';
    const client = new MongoClient(uri);
    await client.connect();
    return client.db();
  },
};
