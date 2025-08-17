import { Inject, Injectable } from '@nestjs/common';
import { Db } from 'mongodb';
import { DATABASE_CONNECTION } from '../../../common/providers/mongo.provider';

@Injectable()
export class UsersService {
  constructor(@Inject(DATABASE_CONNECTION) private readonly db: Db) {}

  async findAll() {
    return this.db.collection('users').find().toArray();
  }

  async create(user: any) {
    return this.db.collection('users').insertOne(user);
  }
}
