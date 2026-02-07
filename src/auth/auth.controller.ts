import {
  BadRequestException,
  Body,
  Controller,
  Get,
  Patch,
  Post,
  Query,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import { ApiOperation, ApiTags } from '@nestjs/swagger';
import { Request } from 'express';
import type { Response } from 'express';
import { AuthGuard } from '@nestjs/passport';
import { AuthService } from './auth.service';
import { getRefreshTokenFromRequest } from './helpers/cookie-token.helper';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { IssueTokenDto } from './dto/issue-token.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { LogoutDto } from './dto/logout.dto';
import { VerifySignupDto } from './dto/verify-signup.dto';
import { VerifySignupCodeDto } from './dto/verify-signup-code.dto';
import { SendVerificationDto } from './dto/send-verification.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { LoginDto } from './dto/login.dto';
import { UpdateProfileDto } from './dto/update-profile.dto';
import { SendEmailChangeDto } from './dto/send-email-change.dto';
import { VerifyEmailChangeDto } from './dto/verify-email-change.dto';
import { ChangePasswordDto } from './dto/change-password.dto';
import { CurrentUser } from './decorators/current-user.decorator';
import { getClientIp } from './helpers/client-ip.helper';
import { ACCESS_TOKEN_COOKIE, REFRESH_TOKEN_COOKIE } from './constants';

interface AuthenticatedRequest extends Request {
  user: { sub: string; email?: string; username?: string };
}

interface GoogleUser {
  googleId: string;
  email: string;
  firstName: string;
  lastName: string;
  accessToken: string;
  refreshToken: string;
}

interface KakaoUser {
  kakaoId: string;
  email: string;
  nickname: string;
}

@ApiTags('auth')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('send-verification-code')
  @ApiOperation({
    summary: '인증 코드 발송',
    description:
      '이메일로 6자리 인증 코드를 발송합니다. 회원가입(signup) 또는 비밀번호 찾기(password_reset) 시 사용. 3분 유효.',
  })
  async sendVerificationCode(@Body() dto: SendVerificationDto) {
    return this.authService.sendVerificationCode(
      dto.email,
      dto.purpose,
      dto.username,
      dto.name,
    );
  }

  @Post('verify-signup-code')
  @ApiOperation({
    summary: '회원가입 인증 코드 검증',
    description:
      '이메일 인증 코드의 유효성만 확인합니다. 회원가입 전에 먼저 호출하여 인증 후 회원가입을 진행하세요.',
  })
  async verifySignupCode(@Body() dto: VerifySignupCodeDto) {
    return this.authService.verifySignupCode(dto.email, dto.code);
  }

  @Post('signup')
  @ApiOperation({
    summary: '회원 가입',
    description:
      '이메일 인증 코드 검증 후 가입합니다. 먼저 send-verification-code로 인증 코드를 발송받으세요.',
  })
  async signup(@Body() dto: VerifySignupDto) {
    return this.authService.signupWithVerification(
      dto.username,
      dto.email,
      dto.password,
      dto.name,
      dto.verificationCode,
    );
  }

  @Post('reset-password')
  @ApiOperation({
    summary: '비밀번호 재설정',
    description:
      '이메일 인증 코드 검증 후 비밀번호를 재설정합니다. send-verification-code로 password_reset 용도로 코드 발송 후 사용.',
  })
  async resetPassword(@Body() dto: ResetPasswordDto) {
    return this.authService.resetPassword(
      dto.email,
      dto.verificationCode,
      dto.newPassword,
    );
  }

  @Post('login')
  @ApiOperation({
    summary: '로그인',
    description:
      'email 또는 username과 password로 인증 후 액세스/리프레시 토큰 발급. clientId/clientSecret 검증 필요. 토큰은 쿠키에 자동 설정됩니다.',
  })
  async login(
    @Body() dto: LoginDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res,
  ) {
    const emailOrUsername = dto.email || dto.username;
    if (!emailOrUsername) {
      throw new BadRequestException('이메일 또는 사용자명 중 하나는 필수입니다.');
    }
    const tokenPair = await this.authService.login(
      emailOrUsername,
      dto.password,
      dto.clientId,
      dto.clientSecret,
      getClientIp(req),
    );

    // 쿠키에 토큰 설정
    const accessTokenExpires = new Date(Date.now() + 15 * 60 * 1000); // 15분
    (res as Response).cookie(ACCESS_TOKEN_COOKIE, tokenPair.accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      expires: accessTokenExpires,
    });

    (res as Response).cookie(REFRESH_TOKEN_COOKIE, tokenPair.refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      expires: tokenPair.expiresAt,
    });

    return tokenPair;
  }

  @Post('token')
  @ApiOperation({
    summary: '토큰 발급',
    description:
      'clientId/clientSecret 검증 후 userId로 사용자 조회하여 액세스/리프레시 토큰 발급 (쿠키·클라이언트 검증용)',
  })
  async issueToken(@Body() dto: IssueTokenDto) {
    return this.authService.issueTokensByUserId(
      dto.userId,
      dto.clientId,
      dto.clientSecret,
    );
  }

  @Post('refresh')
  @ApiOperation({
    summary: '토큰 갱신',
    description:
      '리프레시 토큰: body 또는 쿠키(refreshToken). clientId/clientSecret 검증 후 새 쌍 발급.',
  })
  async refresh(@Req() req, @Body() dto: RefreshTokenDto) {
    const refreshToken = getRefreshTokenFromRequest(req as Request, dto.refreshToken);
    if (!refreshToken) {
      throw new BadRequestException(
        '리프레시 토큰이 필요합니다. body.refreshToken 또는 쿠키 refreshToken',
      );
    }
    return this.authService.refreshTokens(
      refreshToken,
      dto.clientId,
      dto.clientSecret,
    );
  }

  @Post('revoke')
  @ApiOperation({
    summary: '리프레시 토큰 무효화',
    description:
      '리프레시 토큰: body 또는 쿠키(refreshToken). clientId/clientSecret 검증 후 무효화.',
  })
  async revoke(@Req() req, @Body() dto: RefreshTokenDto) {
    const refreshToken = getRefreshTokenFromRequest(req as Request, dto.refreshToken);
    if (!refreshToken) {
      throw new BadRequestException(
        '리프레시 토큰이 필요합니다. body.refreshToken 또는 쿠키 refreshToken',
      );
    }
    await this.authService.revokeRefreshToken(
      refreshToken,
      dto.clientId,
      dto.clientSecret,
    );
    return { ok: true };
  }

  @Post('logout')
  @ApiOperation({
    summary: '로그아웃',
    description:
      '리프레시 토큰 무효화 후 accessToken/refreshToken 쿠키 삭제. clientId/clientSecret은 리프레시 토큰이 있을 때만 필요.',
  })
  async logout(
    @Req() req: Request,
    @Res() res: Response,
    @Body() dto: LogoutDto,
  ) {
    const refreshToken = getRefreshTokenFromRequest(req, dto.refreshToken);
    if (refreshToken && dto.clientId && dto.clientSecret) {
      try {
        await this.authService.revokeRefreshToken(
          refreshToken,
          dto.clientId,
          dto.clientSecret,
        );
      } catch {
        // revoke 실패해도 쿠키는 삭제
      }
    }
    const cookieOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax' as const,
      path: '/',
    };
    res.clearCookie(ACCESS_TOKEN_COOKIE, cookieOptions);
    res.clearCookie(REFRESH_TOKEN_COOKIE, cookieOptions);
    return res.status(200).json({ ok: true });
  }

  @Post('me')
  @UseGuards(JwtAuthGuard)
  @ApiOperation({
    summary: '현재 사용자',
    description:
      '액세스 토큰: 쿠키(accessToken) 또는 Authorization Bearer. public.key로 검증 후 payload 반환.',
  })
  me(@Req() req) {
    return (req as AuthenticatedRequest).user;
  }

  @Get('profile')
  @UseGuards(JwtAuthGuard)
  @ApiOperation({
    summary: '프로필 조회',
    description: '로그인한 사용자의 전체 프로필 정보 조회 (비밀번호 제외)',
  })
  getProfile(@CurrentUser('sub') userId: string) {
    return this.authService.getProfile(userId);
  }

  @Post('me/send-email-change-code')
  @UseGuards(JwtAuthGuard)
  @ApiOperation({
    summary: '이메일 변경용 인증 코드 발송',
    description:
      '변경할 새 이메일로 6자리 인증 코드를 발송합니다. 이메일 변경 시 updateProfile에서 verificationCode와 함께 사용. 3분 유효.',
  })
  sendEmailChangeCode(
    @CurrentUser('sub') userId: string,
    @Body() dto: SendEmailChangeDto,
  ) {
    return this.authService.sendEmailChangeCode(userId, dto.email);
  }

  @Post('me/verify-email-change-code')
  @UseGuards(JwtAuthGuard)
  @ApiOperation({
    summary: '이메일 변경 인증 코드 검증',
    description:
      '입력한 인증 코드가 유효한지 확인합니다. 유효하면 프로필 저장 시 이메일 변경이 가능합니다. 3분 유효.',
  })
  verifyEmailChangeCode(
    @CurrentUser('sub') _userId: string,
    @Body() dto: VerifyEmailChangeDto,
  ) {
    return this.authService.verifyEmailChangeCode(dto.email, dto.code);
  }

  @Patch('me')
  @UseGuards(JwtAuthGuard)
  @ApiOperation({
    summary: '프로필 수정',
    description: '이름, 사용자명, 이메일 수정. 이메일 변경 시 verificationCode 필수.',
  })
  updateProfile(
    @CurrentUser('sub') userId: string,
    @Body() dto: UpdateProfileDto,
  ) {
    return this.authService.updateProfile(userId, dto);
  }

  @Patch('me/password')
  @UseGuards(JwtAuthGuard)
  @ApiOperation({
    summary: '비밀번호 변경',
    description:
      '이메일 가입: currentPassword 필수. OAuth 가입: 생략 시 비밀번호 설정.',
  })
  async changePassword(
    @CurrentUser('sub') userId: string,
    @Body() dto: ChangePasswordDto,
  ) {
    await this.authService.changePassword(
      userId,
      dto.currentPassword,
      dto.newPassword,
    );
    return { ok: true };
  }

  @Get('me/login-history')
  @UseGuards(JwtAuthGuard)
  @ApiOperation({
    summary: '로그인 이력 조회',
    description: '로그인 시각, IP 주소 목록',
  })
  getLoginHistory(
    @CurrentUser('sub') userId: string,
    @Req() req: Request,
    @Query('take') take?: string,
    @Query('cursor') cursor?: string,
  ) {
    return this.authService.getLoginHistory(userId, {
      take: take ? parseInt(take, 10) : undefined,
      cursor,
      clientIp: getClientIp(req),
    });
  }

  @Get('me/activities')
  @UseGuards(JwtAuthGuard)
  @ApiOperation({
    summary: '활동 내역 조회',
    description: '로그인, 프로필 수정, 비밀번호 변경 등 계정 활동 내역',
  })
  getActivities(
    @CurrentUser('sub') userId: string,
    @Query('take') take?: string,
    @Query('cursor') cursor?: string,
  ) {
    return this.authService.getActivities(userId, {
      take: take ? parseInt(take, 10) : undefined,
      cursor,
    });
  }

  @Get('google')
  @UseGuards(AuthGuard('google'))
  @ApiOperation({ summary: 'Google OAuth 시작', description: 'Google 로그인 페이지로 리디렉트' })
  googleAuth() {
    // AuthGuard가 Google로 리디렉트
  }

  @Get('google/callback')
  @UseGuards(AuthGuard('google'))
  @ApiOperation({
    summary: 'Google OAuth 콜백',
    description: 'Google 인증 후 토큰 발급, 쿠키 설정, 프론트엔드로 리디렉트',
  })
  async googleAuthCallback(
    @Req() req: Request & { user: GoogleUser },
    @Res() res: Response,
  ) {
    const googleUser = req.user;
    if (!googleUser) {
      return res.redirect(
        `${process.env.FRONTEND_URL || 'http://localhost:3000'}/login?error=google_auth_failed`,
      );
    }

    const clientId = process.env.GOOGLE_OAUTH_CLIENT_ID ?? 'goldkiwi-front';

    try {
      const tokenPair = await this.authService.googleLoginOrSignup(
        googleUser.googleId,
        googleUser.email,
        googleUser.firstName,
        googleUser.lastName,
        clientId,
        getClientIp(req),
      );

      const accessTokenExpires = new Date(Date.now() + 15 * 60 * 1000);
      res.cookie(ACCESS_TOKEN_COOKIE, tokenPair.accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        expires: accessTokenExpires,
      });
      res.cookie(REFRESH_TOKEN_COOKIE, tokenPair.refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        expires: tokenPair.expiresAt,
      });

      const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:3000';
      return res.redirect(`${frontendUrl}?login=success`);
    } catch (err) {
      const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:3000';
      const msg = err?.message || '로그인에 실패했습니다.';
      return res.redirect(`${frontendUrl}/login?error=${encodeURIComponent(msg)}`);
    }
  }

  @Get('kakao')
  @UseGuards(AuthGuard('kakao'))
  @ApiOperation({ summary: 'Kakao OAuth 시작', description: '카카오 로그인 페이지로 리디렉트' })
  kakaoAuth() {
    // AuthGuard가 Kakao로 리디렉트
  }

  @Get('kakao/callback')
  @UseGuards(AuthGuard('kakao'))
  @ApiOperation({
    summary: 'Kakao OAuth 콜백',
    description: '카카오 인증 후 토큰 발급, 쿠키 설정, 프론트엔드로 리디렉트',
  })
  async kakaoAuthCallback(
    @Req() req: Request & { user: KakaoUser },
    @Res() res: Response,
  ) {
    const kakaoUser = req.user;
    if (!kakaoUser) {
      return res.redirect(
        `${process.env.FRONTEND_URL || 'http://localhost:3000'}/login?error=kakao_auth_failed`,
      );
    }

    const clientId = process.env.KAKAO_OAUTH_CLIENT_ID ?? 'goldkiwi-front';

    try {
      const tokenPair = await this.authService.kakaoLoginOrSignup(
        kakaoUser.kakaoId,
        kakaoUser.email,
        kakaoUser.nickname,
        clientId,
        getClientIp(req),
      );

      const accessTokenExpires = new Date(Date.now() + 15 * 60 * 1000);
      res.cookie(ACCESS_TOKEN_COOKIE, tokenPair.accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        expires: accessTokenExpires,
      });
      res.cookie(REFRESH_TOKEN_COOKIE, tokenPair.refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        expires: tokenPair.expiresAt,
      });

      const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:3000';
      return res.redirect(`${frontendUrl}?login=success`);
    } catch (err) {
      const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:3000';
      const msg = err?.message || '로그인에 실패했습니다.';
      return res.redirect(`${frontendUrl}/login?error=${encodeURIComponent(msg)}`);
    }
  }
}
