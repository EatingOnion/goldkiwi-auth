import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { ClientService } from './client.service';
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
    private readonly clientService: ClientService,
  ) {}

  /** 사용자 정보 + clientId로 액세스/리프레시 토큰 쌍 발급 (private.key 서명, 클라이언트 검증용 clientId 저장) */
  async issueTokenPair(
    user: { id: string; email?: string; username?: string },
    clientId: string,
  ): Promise<TokenPair> {
    return this.tokenService.issueTokenPair(user, clientId);
  }

  /** 리프레시 토큰으로 새 토큰 쌍 발급 (클라이언트 검증 후, 동일 clientId에서만 허용) */
  async refreshTokens(
    refreshToken: string,
    clientId: string,
    clientSecret: string,
  ): Promise<TokenPair> {
    await this.clientService.validateClient(clientId, clientSecret);
    return this.tokenService.refreshAccessToken(refreshToken, clientId);
  }

  /** userId로 사용자 조회 후 토큰 발급. clientId/clientSecret 검증 후 발급 (로그인/쿠키용). */
  async issueTokensByUserId(
    userId: string,
    clientId: string,
    clientSecret: string,
  ): Promise<TokenPair> {
    await this.clientService.validateClient(clientId, clientSecret);
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });
    if (!user || user.deletedAt != null || !user.isActive) {
      throw new UnauthorizedException('사용자를 찾을 수 없습니다.');
    }
    return this.tokenService.issueTokenPair(
      {
        id: user.id,
        email: user.email,
        username: user.username,
      },
      clientId,
    );
  }

  /** 액세스 토큰 검증 (public.key 사용) */
  verifyAccessToken(token: string): AccessTokenPayload {
    return this.tokenService.verifyAccessToken(token);
  }

  /** 리프레시 토큰 무효화 (클라이언트 검증 후, 해당 clientId용 토큰만 무효화) */
  async revokeRefreshToken(
    token: string,
    clientId: string,
    clientSecret: string,
  ): Promise<void> {
    await this.clientService.validateClient(clientId, clientSecret);
    await this.tokenService.revokeRefreshToken(token, clientId);
  }
}
