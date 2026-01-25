import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import {
  TokenService,
  TokenPair,
  AccessTokenPayload,
} from './token.service';

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly tokenService: TokenService,
  ) {}

  /** 사용자 정보로 액세스/리프레시 토큰 쌍 발급 (private.key 서명) */
  async issueTokenPair(user: {
    id: string;
    email?: string;
    username?: string;
  }): Promise<TokenPair> {
    return this.tokenService.issueTokenPair(user);
  }

  /** 리프레시 토큰으로 새 토큰 쌍 발급 */
  async refreshTokens(refreshToken: string): Promise<TokenPair> {
    return this.tokenService.refreshAccessToken(refreshToken);
  }

  /** userId로 사용자 조회 후 토큰 발급 (로그인/테스트용) */
  async issueTokensByUserId(userId: string): Promise<TokenPair> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });
    if (!user || user.deletedAt || !user.isActive) {
      throw new UnauthorizedException('사용자를 찾을 수 없습니다.');
    }
    return this.tokenService.issueTokenPair({
      id: user.id,
      email: user.email,
      username: user.username,
    });
  }

  /** 액세스 토큰 검증 (public.key 사용) */
  verifyAccessToken(token: string): AccessTokenPayload {
    return this.tokenService.verifyAccessToken(token);
  }

  /** 리프레시 토큰 무효화 (로그아웃 등) */
  async revokeRefreshToken(token: string): Promise<void> {
    await this.tokenService.revokeRefreshToken(token);
  }
}
