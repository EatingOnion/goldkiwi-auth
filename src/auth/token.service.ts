import {
  Injectable,
  OnModuleInit,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as jwt from 'jsonwebtoken';
import * as path from 'node:path';
import { readFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { PrismaService } from '../prisma/prisma.service';

export interface AccessTokenPayload {
  sub: string;
  email?: string;
  username?: string;
}

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
  expiresAt: Date;
}

@Injectable()
export class TokenService implements OnModuleInit {
  private privateKey: string;

  constructor(
    private readonly configService: ConfigService,
    private readonly prisma: PrismaService,
  ) {}

  onModuleInit() {
    this.privateKey = this.loadPrivateKey();
  }

  private privateKeyPath(): string {
    const keyPath =
      this.configService.get<string>('PRIVATE_KEY_PATH') ?? 'private.key';
    return path.isAbsolute(keyPath)
      ? keyPath
      : path.join(process.cwd(), keyPath);
  }

  private loadPrivateKey(): string {
    try {
      return readFileSync(this.privateKeyPath(), 'utf-8');
    } catch {
      throw new Error(
        `private.key를 읽을 수 없습니다: ${this.privateKeyPath()}. PEM 형식 RSA 비공개키를 배치하세요.`,
      );
    }
  }

  private loadPublicKey(): string {
    const keyPath =
      this.configService.get<string>('PUBLIC_KEY_PATH') ?? 'public.key';
    const absolutePath = path.isAbsolute(keyPath)
      ? keyPath
      : path.join(process.cwd(), keyPath);
    try {
      return readFileSync(absolutePath, 'utf-8');
    } catch {
      throw new Error(
        `public.key를 읽을 수 없습니다: ${absolutePath}. PEM 형식 RSA 공개키를 배치하세요.`,
      );
    }
  }

  /** 액세스 토큰 발급 (RS256, private.key 서명) */
  signAccessToken(payload: AccessTokenPayload): string {
    const expiresIn: string | number =
      this.configService.get<string>('JWT_ACCESS_EXPIRES') ?? '15m';
    return jwt.sign(
      payload as object,
      this.privateKey as jwt.Secret,
      { algorithm: 'RS256', expiresIn } as jwt.SignOptions,
    );
  }

  /** 리프레시 토큰 생성 후 DB 저장, 액세스 토큰과 쌍으로 반환 */
  async issueTokenPair(user: {
    id: string;
    email?: string;
    username?: string;
  }): Promise<TokenPair> {
    const refreshToken = randomUUID();
    const expiresInDays =
      Number(this.configService.get<string>('JWT_REFRESH_EXPIRES_DAYS')) || 7;
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + expiresInDays);

    await this.prisma.refreshToken.create({
      data: {
        token: refreshToken,
        userId: user.id,
        expiresAt,
      },
    });

    const accessToken = this.signAccessToken({
      sub: user.id,
      email: user.email,
      username: user.username,
    });

    return {
      accessToken,
      refreshToken,
      expiresAt,
    };
  }

  /** 리프레시 토큰 검증 후 새 액세스 토큰 발급 */
  async refreshAccessToken(refreshToken: string): Promise<TokenPair> {
    const stored = await this.prisma.refreshToken.findUnique({
      where: { token: refreshToken },
      include: { user: true },
    });

    if (
      !stored ||
      stored.isRevoked ||
      stored.expiresAt < new Date()
    ) {
      throw new UnauthorizedException('리프레시 토큰이 유효하지 않거나 만료되었습니다.');
    }

    await this.revokeRefreshToken(refreshToken);
    return this.issueTokenPair({
      id: stored.user.id,
      email: stored.user.email,
      username: stored.user.username,
    });
  }

  /** 리프레시 토큰 무효화 */
  async revokeRefreshToken(token: string): Promise<void> {
    await this.prisma.refreshToken.updateMany({
      where: { token },
      data: { isRevoked: true },
    });
  }

  /** 액세스 토큰 검증 (public.key 사용) */
  verifyAccessToken(token: string): AccessTokenPayload {
    const publicKey = this.loadPublicKey();
    const decoded = jwt.verify(token, publicKey, {
      algorithms: ['RS256'],
    }) as jwt.JwtPayload & AccessTokenPayload;
    return {
      sub: decoded.sub,
      email: decoded.email,
      username: decoded.username,
    };
  }
}
