import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { AccessTokenPayload } from '../services/token.service';

export const CurrentUser = createParamDecorator(
  (data: keyof AccessTokenPayload | undefined, ctx: ExecutionContext): AccessTokenPayload | unknown => {
    const req = ctx.switchToHttp().getRequest<{ user: AccessTokenPayload }>();
    const user = req.user;
    return data ? user?.[data] : user;
  },
);
