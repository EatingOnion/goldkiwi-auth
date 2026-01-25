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
      'userId로 사용자 조회 후 private.key로 서명한 액세스/리프레시 토큰 발급',
  })
  async issueToken(@Body() dto: IssueTokenDto) {
    return this.authService.issueTokensByUserId(dto.userId);
  }

  @Post('refresh')
  @ApiOperation({
    summary: '토큰 갱신',
    description: '리프레시 토큰으로 새 액세스/리프레시 토큰 쌍 발급',
  })
  async refresh(@Body() dto: RefreshTokenDto) {
    return this.authService.refreshTokens(dto.refreshToken);
  }

  @Post('revoke')
  @ApiOperation({
    summary: '리프레시 토큰 무효화',
    description: '리프레시 토큰 무효화 (로그아웃 등)',
  })
  async revoke(@Body() dto: RefreshTokenDto) {
    await this.authService.revokeRefreshToken(dto.refreshToken);
    return { ok: true };
  }
}
