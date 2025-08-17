import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { ConfigModule } from './common/config/config.module';
import { DatabaseModule } from './common/providers/database.module';
import { AuthModule } from './modules/auth/auth.module';
import { UsersModule } from './modules/users/users.module';

const mongo_uri = process.env.MONGO_URI;

@Module({
  imports: [
    ConfigModule,
    DatabaseModule,
    MongooseModule.forRoot(mongo_uri!),
    AuthModule,
    UsersModule,
  ],
})
export class AppModule {}
