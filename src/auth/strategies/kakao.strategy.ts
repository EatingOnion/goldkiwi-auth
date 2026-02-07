import { PassportStrategy } from '@nestjs/passport';
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import Strategy from 'passport-kakao';
import { AuthService } from '../auth.service';

interface KakaoProfileJson {
  id: number;
  kakao_account?: {
    email?: string;
    profile?: { nickname?: string };
  };
  properties?: { nickname?: string };
}

interface KakaoUser {
  kakaoId: string;
  email: string;
  nickname: string;
}

@Injectable()
export class KakaoStrategy extends PassportStrategy(Strategy, 'kakao') {
  constructor(
    private configService: ConfigService,
    private authService: AuthService,
  ) {
    const clientID = configService.get<string>('KAKAO_CLIENT_ID');
    const callbackURL = configService.get<string>('KAKAO_CALLBACK_URL');

    if (!clientID) {
      throw new Error(
        'Kakao OAuth 환경 변수가 설정되지 않았습니다. KAKAO_CLIENT_ID를 설정해주세요.',
      );
    }

    super({
      clientID,
      clientSecret: configService.get<string>('KAKAO_CLIENT_SECRET') ?? 'kakao',
      callbackURL: callbackURL ?? '/auth/kakao/callback',
    });
  }

  validate(
    accessToken: string,
    refreshToken: string,
    profile: { id?: string | number; username?: string; _json?: KakaoProfileJson },
  ): KakaoUser {
    const json = profile._json as KakaoProfileJson | undefined;
    const id = String(profile.id ?? json?.id ?? '');
    const email =
      json?.kakao_account?.email ??
      (json?.kakao_account?.profile?.nickname
        ? `${json.kakao_account.profile.nickname}@kakao.user`
        : `${id}@kakao.user`);
    const nickname =
      profile.username ??
      json?.properties?.nickname ??
      json?.kakao_account?.profile?.nickname ??
      '카카오사용자';

    return {
      kakaoId: id,
      email,
      nickname,
    };
  }
}
