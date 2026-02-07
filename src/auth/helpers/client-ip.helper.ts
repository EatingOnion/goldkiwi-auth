import { Request } from 'express';

/** Request에서 클라이언트 IP 추출 (프록시 고려) */
export function getClientIp(req: Request): string | undefined {
  const forwarded = req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string') {
    return forwarded.split(',')[0]?.trim();
  }
  if (Array.isArray(forwarded) && forwarded[0]) {
    return forwarded[0].trim();
  }
  return req.ip ?? req.socket?.remoteAddress;
}
