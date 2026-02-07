import { Module } from '@nestjs/common';
import { PassportModule } from '@nestjs/passport';
import { ConfigModule } from '@nestjs/config';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { AuthRepository } from './auth.repository';
import { ActivityRepository } from './activity.repository';
import { LoginLogRepository } from './login-log.repository';
import { VerificationRepository } from './verification.repository';
import { SmtpModule } from '../smtp/smtp.module';
import { ClientService } from './services/client.service';
import { TokenService } from './services/token.service';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { GoogleStrategy } from './strategies/google.strategy';
import { KakaoStrategy } from './strategies/kakao.strategy';
import { PrismaModule } from '../prisma/prisma.module';

@Module({
  imports: [PassportModule, ConfigModule, PrismaModule, SmtpModule],
  controllers: [AuthController],
  providers: [
    AuthRepository,
    ActivityRepository,
    LoginLogRepository,
    VerificationRepository,
    AuthService,
    ClientService,
    TokenService,
    JwtAuthGuard,
    // Google OAuth 환경 변수가 있을 때만 GoogleStrategy 등록
    ...(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET
      ? [GoogleStrategy]
      : []),
    // Kakao OAuth 환경 변수가 있을 때만 KakaoStrategy 등록
    ...(process.env.KAKAO_CLIENT_ID ? [KakaoStrategy] : []),
  ],
  exports: [AuthService, TokenService, JwtAuthGuard],
})
export class AuthModule {}
