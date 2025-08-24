import { ObjectId } from 'mongodb';

export interface EmailVerification {
  _id?: ObjectId;
  userId: string;
  token: string;
  expiresAt: Date;
}
