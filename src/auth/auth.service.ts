import {
  Injectable,
  UnauthorizedException,
  ConflictException,
  BadRequestException,
} from '@nestjs/common';
import { AuthRepository } from './auth.repository';
import { ActivityRepository } from './activity.repository';
import { LoginLogRepository } from './login-log.repository';
import { VerificationRepository } from './verification.repository';
import { SmtpService } from '../smtp/smtp.service';
import { ClientService } from './services/client.service';
import {
  TokenService,
  TokenPair,
  AccessTokenPayload,
} from './services/token.service';
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';

@Injectable()
export class AuthService {
  constructor(
    private readonly authRepository: AuthRepository,
    private readonly activityRepository: ActivityRepository,
    private readonly loginLogRepository: LoginLogRepository,
    private readonly verificationRepository: VerificationRepository,
    private readonly smtpService: SmtpService,
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
    const user = await this.authRepository.findById(userId);
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

  /** 이메일 변경용 인증 코드 발송 (로그인 사용자 전용) - 3분 유효 */
  async sendEmailChangeCode(userId: string, newEmail: string): Promise<{ ok: boolean }> {
    const user = await this.authRepository.findById(userId);
    if (!user || user.deletedAt != null || !user.isActive) {
      throw new UnauthorizedException('사용자를 찾을 수 없습니다.');
    }

    const email = newEmail.trim();
    if (email === user.email) {
      throw new BadRequestException('현재 이메일과 동일합니다.');
    }

    const existing = await this.authRepository.findByEmail(email);
    if (existing) {
      throw new ConflictException('이미 사용 중인 이메일입니다.');
    }

    const purpose = 'email_change';
    const code = crypto.randomInt(100000, 999999).toString();
    await this.verificationRepository.deleteByEmailAndPurpose(email, purpose);
    await this.verificationRepository.create(email, code, purpose);
    await this.smtpService.sendVerificationCode(email, code, purpose);
    return { ok: true };
  }

  /** 이메일 변경용 인증 코드 검증 (코드 유효성만 확인, 별도 호출용) */
  async verifyEmailChangeCode(email: string, code: string): Promise<{ ok: boolean }> {
    const isValid = await this.verificationRepository.verify(
      email.trim(),
      code.trim(),
      'email_change',
    );
    if (!isValid) {
      throw new BadRequestException(
        '인증 코드가 올바르지 않거나 만료되었습니다. (3분 유효)',
      );
    }
    return { ok: true };
  }

  /** 인증 코드 발송 (회원가입 / 비밀번호 찾기 / 아이디 찾기) - 3분 유효 */
  async sendVerificationCode(
    email: string,
    purpose: 'signup' | 'password_reset' | 'find_username',
    username?: string,
    name?: string,
  ): Promise<{ ok: boolean }> {
    if (purpose === 'signup') {
      const existing = await this.authRepository.findByEmail(email);
      if (existing) {
        throw new ConflictException('이미 사용 중인 이메일입니다.');
      }
    } else if (purpose === 'password_reset' || purpose === 'find_username') {
      const user = await this.authRepository.findByEmail(email);
      if (!user || user.googleId || user.kakaoId) {
        throw new BadRequestException(
          '이메일 가입 계정이 없거나, 소셜 로그인 계정입니다. 이메일로 가입한 계정만 찾을 수 있습니다.',
        );
      }
    }

    const code = crypto.randomInt(100000, 999999).toString();
    await this.verificationRepository.deleteByEmailAndPurpose(email, purpose);
    await this.verificationRepository.create(email, code, purpose);
    await this.smtpService.sendVerificationCode(email, code, purpose, username, name);
    return { ok: true };
  }

  /** 아이디 찾기 (이메일 인증 코드 검증 후 username 반환) */
  async findUsername(email: string, verificationCode: string): Promise<{ username: string }> {
    const isValid = await this.verificationRepository.verify(
      email.trim(),
      verificationCode.trim(),
      'find_username',
    );
    if (!isValid) {
      throw new BadRequestException(
        '인증 코드가 올바르지 않거나 만료되었습니다. (3분 유효)',
      );
    }

    const user = await this.authRepository.findByEmail(email);
    if (!user || user.googleId || user.kakaoId) {
      throw new BadRequestException('이메일 가입 계정이 아닙니다.');
    }

    await this.verificationRepository.deleteByEmailAndPurpose(email, 'find_username');
    return { username: user.username };
  }

  /** 회원가입용 인증 코드 검증 (코드 유효성만 확인, 별도 호출용) */
  async verifySignupCode(email: string, code: string): Promise<{ ok: boolean }> {
    const isValid = await this.verificationRepository.verify(
      email.trim(),
      code.trim(),
      'signup',
    );
    if (!isValid) {
      throw new BadRequestException(
        '인증 코드가 올바르지 않거나 만료되었습니다. (3분 유효)',
      );
    }
    return { ok: true };
  }

  /** 회원 가입 (이메일 인증 코드 검증 후 가입) */
  async signupWithVerification(
    username: string,
    email: string,
    password: string,
    name: string,
    verificationCode: string,
  ): Promise<{ id: string; username: string; email: string; name: string }> {
    const isValid = await this.verificationRepository.verify(
      email,
      verificationCode,
      'signup',
    );
    if (!isValid) {
      throw new BadRequestException(
        '인증 코드가 올바르지 않거나 만료되었습니다. (3분 유효)',
      );
    }

    const existingUser = await this.authRepository.findByUsernameOrEmail(
      username,
      email,
    );

    if (existingUser) {
      if (existingUser.username === username) {
        throw new ConflictException('이미 사용 중인 사용자명입니다.');
      }
      if (existingUser.email === email) {
        throw new ConflictException('이미 사용 중인 이메일입니다.');
      }
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await this.authRepository.createWithSelect({
      username,
      email,
      password: hashedPassword,
      name,
    });
    await this.verificationRepository.deleteByEmailAndPurpose(email, 'signup');
    await this.activityRepository.create(user.id, 'signup', '이메일로 회원가입');
    return user;
  }

  /** 비밀번호 재설정 (이메일 인증 코드 검증 후) */
  async resetPassword(
    email: string,
    verificationCode: string,
    newPassword: string,
  ): Promise<{ ok: boolean }> {
    const isValid = await this.verificationRepository.verify(
      email,
      verificationCode,
      'password_reset',
    );
    if (!isValid) {
      throw new BadRequestException(
        '인증 코드가 올바르지 않거나 만료되었습니다. (3분 유효)',
      );
    }

    const user = await this.authRepository.findByEmail(email);
    if (!user || user.googleId || user.kakaoId) {
      throw new BadRequestException('이메일 가입 계정이 아닙니다.');
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await this.authRepository.updatePassword(user.id, hashedPassword);
    await this.verificationRepository.deleteByEmailAndPurpose(
      email,
      'password_reset',
    );
    await this.activityRepository.create(
      user.id,
      'password_change',
      '비밀번호 재설정 (이메일 인증)',
    );
    return { ok: true };
  }

  /** 회원 가입 (레거시 - 인증 없이, 내부용 또는 테스트) */
  async signup(
    username: string,
    email: string,
    password: string,
    name: string,
  ): Promise<{ id: string; username: string; email: string; name: string }> {
    const existingUser = await this.authRepository.findByUsernameOrEmail(
      username,
      email,
    );

    if (existingUser) {
      if (existingUser.username === username) {
        throw new ConflictException('이미 사용 중인 사용자명입니다.');
      }
      if (existingUser.email === email) {
        throw new ConflictException('이미 사용 중인 이메일입니다.');
      }
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await this.authRepository.createWithSelect({
      username,
      email,
      password: hashedPassword,
      name,
    });
    await this.activityRepository.create(user.id, 'signup', '이메일로 회원가입');
    return user;
  }

  /** 로그인 (email 또는 username + password로 인증 후 토큰 발급) */
  async login(
    emailOrUsername: string | undefined,
    password: string,
    clientId: string,
    clientSecret: string,
    clientIp?: string,
  ): Promise<TokenPair> {
    await this.clientService.validateClient(clientId, clientSecret);

    const user = await this.authRepository.findByEmailOrUsername(
      emailOrUsername ?? '',
    );

    if (!user) {
      throw new UnauthorizedException('이메일 또는 비밀번호가 올바르지 않습니다.');
    }

    if (!user.isActive) {
      throw new UnauthorizedException('비활성화된 계정입니다.');
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      throw new UnauthorizedException('이메일 또는 비밀번호가 올바르지 않습니다.');
    }

    await this.activityRepository.create(user.id, 'login', '이메일/아이디로 로그인');
    await this.loginLogRepository.create(user.id, clientIp);
    return this.tokenService.issueTokenPair(
      {
        id: user.id,
        email: user.email,
        username: user.username,
      },
      clientId,
    );
  }

  /** Google OAuth 로그인/회원가입 (기존 사용자 조회 또는 신규 생성 후 토큰 발급) */
  async googleLoginOrSignup(
    googleId: string,
    email: string,
    firstName: string,
    lastName: string,
    clientId: string,
    clientIp?: string,
  ): Promise<TokenPair> {
    const name = `${firstName} ${lastName}`.trim() || email.split('@')[0];

    let user = await this.authRepository.findByGoogleId(googleId);

    if (user) {
      if (!user.isActive) {
        throw new UnauthorizedException('비활성화된 계정입니다.');
      }
      await this.activityRepository.create(user.id, 'google_login', 'Google로 로그인');
      await this.loginLogRepository.create(user.id, clientIp);
      return this.tokenService.issueTokenPair(
        { id: user.id, email: user.email, username: user.username },
        clientId,
      );
    }

    user = await this.authRepository.findByEmail(email);

    if (user) {
      await this.authRepository.updateGoogleId(user.id, googleId);
      if (!user.isActive) {
        throw new UnauthorizedException('비활성화된 계정입니다.');
      }
      await this.activityRepository.create(user.id, 'google_login', 'Google로 로그인 (계정 연동)');
      await this.loginLogRepository.create(user.id, clientIp);
      return this.tokenService.issueTokenPair(
        { id: user.id, email: user.email, username: user.username },
        clientId,
      );
    }

    let username = email.split('@')[0];
    const existingWithUsername =
      await this.authRepository.findByUsername(username);
    if (existingWithUsername) {
      username = `google_${googleId.slice(0, 12)}`;
    }
    const hashedPassword = await bcrypt.hash(
      `google_${googleId}_${Date.now()}`,
      10,
    );

    const newUser = await this.authRepository.create({
      googleId,
      username,
      email,
      password: hashedPassword,
      name,
    });

    await this.activityRepository.create(newUser.id, 'signup', 'Google로 회원가입');
    await this.loginLogRepository.create(newUser.id, clientIp);
    return this.tokenService.issueTokenPair(
      {
        id: newUser.id,
        email: newUser.email,
        username: newUser.username,
      },
      clientId,
    );
  }

  /** 현재 사용자 프로필 조회 (비밀번호 제외) */
  async getProfile(userId: string): Promise<{
    id: string;
    username: string;
    email: string;
    name: string;
    googleId: string | null;
    kakaoId: string | null;
    createdAt: Date;
  }> {
    const user = await this.authRepository.findProfileById(userId);
    if (!user) {
      throw new UnauthorizedException('사용자를 찾을 수 없습니다.');
    }
    return user;
  }

  /** 프로필 수정 (name, email). 아이디는 변경 불가. 이메일 변경 시 verificationCode 필수 */
  async updateProfile(
    userId: string,
    dto: { name?: string; email?: string; verificationCode?: string },
  ): Promise<{
    id: string;
    username: string;
    email: string;
    name: string;
  }> {
    const user = await this.authRepository.findById(userId);
    if (!user || user.deletedAt != null || !user.isActive) {
      throw new UnauthorizedException('사용자를 찾을 수 없습니다.');
    }

    const updates: { name?: string; email?: string } = {};

    if (dto.name !== undefined) {
      updates.name = dto.name.trim();
    }
    if (dto.email !== undefined) {
      const email = dto.email.trim();
      if (email !== user.email) {
        const existing = await this.authRepository.findByEmail(email);
        if (existing) {
          throw new ConflictException('이미 사용 중인 이메일입니다.');
        }
        if (!dto.verificationCode?.trim()) {
          throw new BadRequestException(
            '이메일 변경 시 인증 코드가 필요합니다. 먼저 "인증 코드 발송"을 눌러 새 이메일로 받은 코드를 입력하세요.',
          );
        }
        const isValid = await this.verificationRepository.verify(
          email,
          dto.verificationCode.trim(),
          'email_change',
        );
        if (!isValid) {
          throw new BadRequestException(
            '인증 코드가 올바르지 않거나 만료되었습니다. (3분 유효)',
          );
        }
        await this.verificationRepository.deleteByEmailAndPurpose(email, 'email_change');
        updates.email = email;
      }
    }

    if (Object.keys(updates).length === 0) {
      return {
        id: user.id,
        username: user.username,
        email: user.email,
        name: user.name,
      };
    }

    const updated = await this.authRepository.updateProfile(userId, updates);
    await this.activityRepository.create(userId, 'profile_update', '프로필 정보 수정');
    return updated;
  }

  /** 비밀번호 변경 (이메일 가입: currentPassword 필수, OAuth 가입: 생략 가능) */
  async changePassword(
    userId: string,
    currentPassword: string | undefined,
    newPassword: string,
  ): Promise<void> {
    const user = await this.authRepository.findById(userId);
    if (!user || user.deletedAt != null || !user.isActive) {
      throw new UnauthorizedException('사용자를 찾을 수 없습니다.');
    }

    const isOAuthUser = !!(user.googleId || user.kakaoId);

    if (isOAuthUser) {
      // OAuth 가입자: currentPassword 없이 비밀번호 설정 가능
    } else {
      // 이메일 가입자: 현재 비밀번호 검증 필수
      if (!currentPassword) {
        throw new BadRequestException('현재 비밀번호를 입력해주세요.');
      }
      const isValid = await bcrypt.compare(currentPassword, user.password);
      if (!isValid) {
        throw new UnauthorizedException('현재 비밀번호가 올바르지 않습니다.');
      }
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await this.authRepository.updatePassword(userId, hashedPassword);
    await this.activityRepository.create(userId, 'password_change', '비밀번호 변경');
  }

  /** Kakao OAuth 로그인/회원가입 (기존 사용자 조회 또는 신규 생성 후 토큰 발급) */
  async kakaoLoginOrSignup(
    kakaoId: string,
    email: string,
    nickname: string,
    clientId: string,
    clientIp?: string,
  ): Promise<TokenPair> {
    const name = nickname || email.split('@')[0];

    let user = await this.authRepository.findByKakaoId(kakaoId);

    if (user) {
      if (!user.isActive) {
        throw new UnauthorizedException('비활성화된 계정입니다.');
      }
      await this.activityRepository.create(user.id, 'kakao_login', '카카오로 로그인');
      await this.loginLogRepository.create(user.id, clientIp);
      return this.tokenService.issueTokenPair(
        { id: user.id, email: user.email, username: user.username },
        clientId,
      );
    }

    user = await this.authRepository.findByEmail(email);

    if (user) {
      await this.authRepository.updateKakaoId(user.id, kakaoId);
      if (!user.isActive) {
        throw new UnauthorizedException('비활성화된 계정입니다.');
      }
      await this.activityRepository.create(user.id, 'kakao_login', '카카오로 로그인 (계정 연동)');
      await this.loginLogRepository.create(user.id, clientIp);
      return this.tokenService.issueTokenPair(
        { id: user.id, email: user.email, username: user.username },
        clientId,
      );
    }

    let username = email.split('@')[0];
    const existingWithUsername =
      await this.authRepository.findByUsername(username);
    if (existingWithUsername) {
      username = `kakao_${kakaoId.slice(0, 12)}`;
    }
    const hashedPassword = await bcrypt.hash(
      `kakao_${kakaoId}_${Date.now()}`,
      10,
    );

    const newUser = await this.authRepository.create({
      kakaoId,
      username,
      email,
      password: hashedPassword,
      name,
    });

    await this.activityRepository.create(newUser.id, 'signup', '카카오로 회원가입');
    await this.loginLogRepository.create(newUser.id, clientIp);
    return this.tokenService.issueTokenPair(
      {
        id: newUser.id,
        email: newUser.email,
        username: newUser.username,
      },
      clientId,
    );
  }

  /** 로그인 이력 조회 (데이터 없으면 현재 세션 기록 생성) */
  async getLoginHistory(
    userId: string,
    options?: { take?: number; cursor?: string; clientIp?: string },
  ): Promise<{ id: string; ip: string | null; createdAt: Date }[]> {
    const list = await this.loginLogRepository.findByUserId(userId, options);
    if (list.length === 0) {
      await this.loginLogRepository.create(userId, options?.clientIp);
      return this.loginLogRepository.findByUserId(userId, options);
    }
    return list;
  }

  /** 활동 내역 조회 (데이터 없으면 최초 방문 기록 생성) */
  async getActivities(
    userId: string,
    options?: { take?: number; cursor?: string },
  ): Promise<
    { id: string; type: string; description: string | null; createdAt: Date }[]
  > {
    const list = await this.activityRepository.findByUserId(userId, options);
    if (list.length === 0) {
      await this.activityRepository.create(
        userId,
        'mypage_visit',
        '마이페이지 최초 방문',
      );
      return this.activityRepository.findByUserId(userId, options);
    }
    return list;
  }
}
