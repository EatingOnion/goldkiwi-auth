import { Body, Controller, Post } from '@nestjs/common';
import { ApiOperation, ApiTags } from '@nestjs/swagger';
import { AuthService } from './auth.service';
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
      'clientId/clientSecret 검증 후 리프레시 토큰으로 새 액세스/리프레시 토큰 쌍 발급 (동일 클라이언트만 허용)',
  })
  async refresh(@Body() dto: RefreshTokenDto) {
    return this.authService.refreshTokens(
      dto.refreshToken,
      dto.clientId,
      dto.clientSecret,
    );
  }

  @Post('revoke')
  @ApiOperation({
    summary: '리프레시 토큰 무효화',
    description:
      'clientId/clientSecret 검증 후 리프레시 토큰 무효화 (해당 클라이언트용 토큰만, 로그아웃 등)',
  })
  async revoke(@Body() dto: RefreshTokenDto) {
    await this.authService.revokeRefreshToken(
      dto.refreshToken,
      dto.clientId,
      dto.clientSecret,
    );
    return { ok: true };
  }
}
