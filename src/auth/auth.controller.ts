import {
  BadRequestException,
  Body,
  Controller,
  Get,
  Post,
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
import { SignupDto } from './dto/signup.dto';
import { LoginDto } from './dto/login.dto';
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

@ApiTags('auth')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('signup')
  @ApiOperation({
    summary: '회원 가입',
    description: '새로운 사용자를 등록합니다. username과 email은 고유해야 합니다.',
  })
  async signup(@Body() dto: SignupDto) {
    return this.authService.signup(
      dto.username,
      dto.email,
      dto.password,
      dto.name,
    );
  }

  @Post('login')
  @ApiOperation({
    summary: '로그인',
    description:
      'email 또는 username과 password로 인증 후 액세스/리프레시 토큰 발급. clientId/clientSecret 검증 필요. 토큰은 쿠키에 자동 설정됩니다.',
  })
  async login(@Body() dto: LoginDto, @Res({ passthrough: true }) res) {
    const emailOrUsername = dto.email || dto.username;
    if (!emailOrUsername) {
      throw new BadRequestException('이메일 또는 사용자명 중 하나는 필수입니다.');
    }
    const tokenPair = await this.authService.login(
      emailOrUsername,
      dto.password,
      dto.clientId,
      dto.clientSecret,
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
