import {
  BadRequestException,
  Body,
  Controller,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import { ApiOperation, ApiTags } from '@nestjs/swagger';
import { Request } from 'express';
import { AuthService } from './auth.service';
import { getRefreshTokenFromRequest } from './helpers/cookie-token.helper';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { CurrentUser } from './decorators/current-user.decorator';
import { AccessTokenPayload } from './services/token.service';
import { IssueTokenDto } from './dto/issue-token.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';

@ApiTags('auth')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

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
  async refresh(@Req() req: Request, @Body() dto: RefreshTokenDto) {
    const refreshToken = getRefreshTokenFromRequest(req, dto.refreshToken);
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
  async revoke(@Req() req: Request, @Body() dto: RefreshTokenDto) {
    const refreshToken = getRefreshTokenFromRequest(req, dto.refreshToken);
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

  @Post('me')
  @UseGuards(JwtAuthGuard)
  @ApiOperation({
    summary: '현재 사용자',
    description:
      '액세스 토큰: 쿠키(accessToken) 또는 Authorization Bearer. public.key로 검증 후 payload 반환.',
  })
  me(@CurrentUser() user: AccessTokenPayload) {
    return user;
  }
}
