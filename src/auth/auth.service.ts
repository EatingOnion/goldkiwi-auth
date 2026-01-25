import {
  Injectable,
  UnauthorizedException,
  ConflictException,
  BadRequestException,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { ClientService } from './services/client.service';
import {
  TokenService,
  TokenPair,
  AccessTokenPayload,
} from './services/token.service';
import * as bcrypt from 'bcrypt';

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

  /** 회원 가입 */
  async signup(
    username: string,
    email: string,
    password: string,
    name: string,
  ): Promise<{ id: string; username: string; email: string; name: string }> {
    // 중복 체크
    const existingUser = await this.prisma.user.findFirst({
      where: {
        OR: [{ username }, { email }],
        deletedAt: null,
      },
    });

    if (existingUser) {
      if (existingUser.username === username) {
        throw new ConflictException('이미 사용 중인 사용자명입니다.');
      }
      if (existingUser.email === email) {
        throw new ConflictException('이미 사용 중인 이메일입니다.');
      }
    }

    // 비밀번호 해싱
    const hashedPassword = await bcrypt.hash(password, 10);

    // 사용자 생성
    const user = await this.prisma.user.create({
      data: {
        username,
        email,
        password: hashedPassword,
        name,
        isActive: true,
      },
      select: {
        id: true,
        username: true,
        email: true,
        name: true,
      },
    });

    return user;
  }

  /** 로그인 (email 또는 username + password로 인증 후 토큰 발급) */
  async login(
    emailOrUsername: string | undefined,
    password: string,
    clientId: string,
    clientSecret: string,
  ): Promise<TokenPair> {
    // clientId/clientSecret 검증
    await this.clientService.validateClient(clientId, clientSecret);

    // email 또는 username으로 사용자 조회
    const user = await this.prisma.user.findFirst({
      where: {
        OR: [{ email: emailOrUsername }, { username: emailOrUsername }],
        deletedAt: null,
      },
    });

    if (!user) {
      throw new UnauthorizedException('이메일 또는 비밀번호가 올바르지 않습니다.');
    }

    // 사용자 활성화 상태 확인
    if (!user.isActive) {
      throw new UnauthorizedException('비활성화된 계정입니다.');
    }

    // 비밀번호 검증
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      throw new UnauthorizedException('이메일 또는 비밀번호가 올바르지 않습니다.');
    }

    // 토큰 발급
    return this.tokenService.issueTokenPair(
      {
        id: user.id,
        email: user.email,
        username: user.username,
      },
      clientId,
    );
  }
}
