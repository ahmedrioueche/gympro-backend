import { ObjectId } from 'mongodb';
export interface User {
    _id?: ObjectId;
    role?: UserRole;
    gym?: Gym;
    username?: string;
    email: string;
    password: string;
    fullName?: string;
    phoneNumber?: string;
    address?: string;
    city?: string;
    state?: string;
    country?: string;
    avatar?: string;
    gender?: string;
    dateOfBirth?: Date;
    isValidated?: boolean;
    isOnBoarded?: boolean;
    isActive?: boolean;
    createdAt: Date;
}
export type UserRole = 'owner' | 'manager' | 'coach' | 'member';
export interface Gym {
    _id: string;
    name: string;
    address: string;
    city: string;
    state: string;
    country: string;
    phoneNumber?: string;
    email?: string;
    website?: string;
    logo?: string;
}
