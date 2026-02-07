import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

export type LoginLogEntity = {
  id: string;
  userId: string;
  ip: string | null;
  createdAt: Date;
};

@Injectable()
export class LoginLogRepository {
  constructor(private readonly prisma: PrismaService) {}

  /** 로그인 로그 생성 */
  create(userId: string, ip?: string): Promise<LoginLogEntity> {
    return this.prisma.loginLog.create({
      data: {
        userId,
        ip: ip ?? null,
      },
    }) as Promise<LoginLogEntity>;
  }

  /** 사용자별 로그인 이력 조회 (최신순, 페이지네이션) */
  findByUserId(
    userId: string,
    options?: { take?: number; cursor?: string },
  ): Promise<LoginLogEntity[]> {
    const take = options?.take ?? 50;
    const cursor = options?.cursor ? { id: options.cursor } : undefined;

    return this.prisma.loginLog.findMany({
      where: { userId },
      orderBy: { createdAt: 'desc' },
      take,
      ...(cursor && { cursor, skip: 1 }),
    }) as Promise<LoginLogEntity[]>;
  }
}
