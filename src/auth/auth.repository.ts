import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

/** User 엔티티 (password 포함) */
export type UserEntity = {
  id: string;
  username: string;
  email: string;
  password: string;
  name: string;
  googleId: string | null;
  kakaoId: string | null;
  createdAt: Date;
  updatedAt: Date;
  deletedAt: Date | null;
  isActive: boolean;
};

/** 프로필 (비밀번호 제외) */
export type ProfileEntity = {
  id: string;
  username: string;
  email: string;
  name: string;
  googleId: string | null;
  kakaoId: string | null;
  createdAt: Date;
};

/** 사용자 생성 데이터 */
export type CreateUserData = {
  username: string;
  email: string;
  password: string;
  name: string;
  googleId?: string;
  kakaoId?: string;
};

@Injectable()
export class AuthRepository {
  constructor(private readonly prisma: PrismaService) {}

  /** id로 사용자 조회 (토큰 발급용) */
  findById(id: string): Promise<UserEntity | null> {
    return this.prisma.user.findUnique({
      where: { id },
    }) as Promise<UserEntity | null>;
  }

  /** id로 활성 사용자 조회 (deletedAt null, isActive true) */
  findByIdActive(id: string): Promise<UserEntity | null> {
    return this.prisma.user.findFirst({
      where: {
        id,
        deletedAt: null,
        isActive: true,
      },
    }) as Promise<UserEntity | null>;
  }

  /** id로 프로필 조회 (비밀번호 제외) */
  findProfileById(userId: string): Promise<ProfileEntity | null> {
    return this.prisma.user.findFirst({
      where: {
        id: userId,
        deletedAt: null,
        isActive: true,
      },
      select: {
        id: true,
        username: true,
        email: true,
        name: true,
        googleId: true,
        kakaoId: true,
        createdAt: true,
      },
    }) as Promise<ProfileEntity | null>;
  }

  /** username 또는 email 중복 조회 */
  findByUsernameOrEmail(
    username: string,
    email: string,
  ): Promise<UserEntity | null> {
    return this.prisma.user.findFirst({
      where: {
        OR: [{ username }, { email }],
        deletedAt: null,
      },
    }) as Promise<UserEntity | null>;
  }

  /** email 또는 username으로 사용자 조회 (로그인용) */
  findByEmailOrUsername(emailOrUsername: string): Promise<UserEntity | null> {
    return this.prisma.user.findFirst({
      where: {
        OR: [{ email: emailOrUsername }, { username: emailOrUsername }],
        deletedAt: null,
      },
    }) as Promise<UserEntity | null>;
  }

  /** googleId로 사용자 조회 */
  findByGoogleId(googleId: string): Promise<UserEntity | null> {
    return this.prisma.user.findFirst({
      where: { googleId, deletedAt: null },
    }) as Promise<UserEntity | null>;
  }

  /** kakaoId로 사용자 조회 */
  findByKakaoId(kakaoId: string): Promise<UserEntity | null> {
    return this.prisma.user.findFirst({
      where: { kakaoId, deletedAt: null },
    }) as Promise<UserEntity | null>;
  }

  /** email로 사용자 조회 */
  findByEmail(email: string): Promise<UserEntity | null> {
    return this.prisma.user.findFirst({
      where: { email, deletedAt: null },
    }) as Promise<UserEntity | null>;
  }

  /** username으로 사용자 조회 */
  findByUsername(username: string): Promise<UserEntity | null> {
    return this.prisma.user.findFirst({
      where: { username, deletedAt: null },
    }) as Promise<UserEntity | null>;
  }

  /** 사용자 생성 */
  create(data: CreateUserData): Promise<UserEntity> {
    return this.prisma.user.create({
      data: {
        ...data,
        isActive: true,
      },
    }) as Promise<UserEntity>;
  }

  /** 사용자 생성 (id, username, email, name만 반환) */
  createWithSelect(data: CreateUserData) {
    return this.prisma.user.create({
      data: {
        ...data,
        isActive: true,
      },
      select: {
        id: true,
        username: true,
        email: true,
        name: true,
      },
    });
  }

  /** googleId 연동 */
  updateGoogleId(userId: string, googleId: string): Promise<void> {
    return this.prisma.user
      .update({
        where: { id: userId },
        data: { googleId },
      })
      .then(() => undefined);
  }

  /** kakaoId 연동 */
  updateKakaoId(userId: string, kakaoId: string): Promise<void> {
    return this.prisma.user
      .update({
        where: { id: userId },
        data: { kakaoId },
      })
      .then(() => undefined);
  }

  /** 프로필 수정 (name, username, email) */
  updateProfile(
    userId: string,
    data: { name?: string; username?: string; email?: string },
  ) {
    return this.prisma.user.update({
      where: { id: userId },
      data,
      select: {
        id: true,
        username: true,
        email: true,
        name: true,
      },
    });
  }

  /** 비밀번호 변경 */
  updatePassword(userId: string, hashedPassword: string): Promise<void> {
    return this.prisma.user
      .update({
        where: { id: userId },
        data: { password: hashedPassword },
      })
      .then(() => undefined);
  }
}
