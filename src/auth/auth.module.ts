import { Module } from '@nestjs/common';
import { PassportModule } from '@nestjs/passport';
import { ConfigModule } from '@nestjs/config';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { ClientService } from './client.service';
import { TokenService } from './token.service';
import { GoogleStrategy } from './strategies/google.strategy';
import { PrismaModule } from '../prisma/prisma.module';

@Module({
  imports: [PassportModule, ConfigModule, PrismaModule],
  controllers: [AuthController],
  providers: [AuthService, ClientService, TokenService, GoogleStrategy],
})
export class AuthModule {}
