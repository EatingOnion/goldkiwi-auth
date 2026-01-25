import { Request } from 'express';
import { REFRESH_TOKEN_COOKIE } from '../constants';

/**
 * cookie-parser로 파싱된 쿠키에서 refreshToken 추출.
 * body.refreshToken 우선, 없으면 쿠키에서 읽는다.
 */
export function getRefreshTokenFromRequest(
  req: Request,
  fromBody: string | undefined,
): string | null {
  if (fromBody) return fromBody;
  const cookies = req.cookies as Record<string, string> | undefined;
  return cookies?.[REFRESH_TOKEN_COOKIE] ?? null;
}
