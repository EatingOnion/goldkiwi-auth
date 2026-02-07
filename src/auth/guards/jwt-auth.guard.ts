import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Request } from 'express';
import { TokenService } from '../services/token.service';
import { ACCESS_TOKEN_COOKIE } from '../constants';

/**
 * 쿠키 또는 Authorization 헤더에서 액세스 토큰을 읽어
 * public.key로 서명 검증(verify) 후 req.user에 payload 부여.
 * JWT는 암호화가 아니라 서명이므로 "복호화"가 아닌 "검증 후 디코딩"이다.
 */
@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(private readonly tokenService: TokenService) {}

  canActivate(context: ExecutionContext): boolean {
    const req = context.switchToHttp().getRequest<Request>();
    const token = this.extractToken(req);

    if (!token) {
      throw new UnauthorizedException('액세스 토큰이 없습니다.');
    }

    try {
      const payload = this.tokenService.verifyAccessToken(token);
      (req as Request & { user: typeof payload }).user = payload;
      return true;
    } catch {
      throw new UnauthorizedException('액세스 토큰이 유효하지 않거나 만료되었습니다.');
    }
  }

  private extractToken(req: Request): string | null {
    const cookies = req.cookies as Record<string, string> | undefined;
    const fromCookie = cookies?.[ACCESS_TOKEN_COOKIE];
    if (fromCookie) return fromCookie;

    const auth = req.headers.authorization;
    if (auth?.startsWith('Bearer ')) return auth.slice(7);

    return null;
  }
}
