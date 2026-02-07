import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

export type ActivityLogEntity = {
  id: string;
  userId: string;
  type: string;
  description: string | null;
  createdAt: Date;
};

@Injectable()
export class ActivityRepository {
  constructor(private readonly prisma: PrismaService) {}

  /** 활동 로그 생성 */
  create(userId: string, type: string, description?: string): Promise<ActivityLogEntity> {
    return this.prisma.activityLog.create({
      data: {
        userId,
        type,
        description,
      },
    }) as Promise<ActivityLogEntity>;
  }

  /** 사용자별 활동 내역 조회 (최신순, 페이지네이션) */
  findByUserId(
    userId: string,
    options?: { take?: number; cursor?: string },
  ): Promise<ActivityLogEntity[]> {
    const take = options?.take ?? 50;
    const cursor = options?.cursor
      ? { id: options.cursor }
      : undefined;

    return this.prisma.activityLog.findMany({
      where: { userId },
      orderBy: { createdAt: 'desc' },
      take,
      ...(cursor && { cursor, skip: 1 }),
    }) as Promise<ActivityLogEntity[]>;
  }
}
