import { Module } from '@nestjs/common';
import { PassportModule } from '@nestjs/passport';
import { ConfigModule } from '@nestjs/config';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { ClientService } from './services/client.service';
import { TokenService } from './services/token.service';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { GoogleStrategy } from './strategies/google.strategy';
import { PrismaModule } from '../prisma/prisma.module';

@Module({
  imports: [PassportModule, ConfigModule, PrismaModule],
  controllers: [AuthController],
  providers: [AuthService, ClientService, TokenService, JwtAuthGuard, GoogleStrategy],
  exports: [AuthService, TokenService, JwtAuthGuard],
})
export class AuthModule {}
