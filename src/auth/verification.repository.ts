import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

const VERIFICATION_EXPIRY_MINUTES = 3;

@Injectable()
export class VerificationRepository {
  constructor(private readonly prisma: PrismaService) {}

  /** 인증 코드 생성 (3분 만료) */
  async create(
    email: string,
    code: string,
    purpose: 'signup' | 'password_reset' | 'email_change',
  ): Promise<void> {
    const expiresAt = new Date(Date.now() + VERIFICATION_EXPIRY_MINUTES * 60 * 1000);
    await this.prisma.emailVerification.create({
      data: { email, code, purpose, expiresAt },
    });
  }

  /** 유효한 인증 코드 검증 (만료되지 않은 것만) */
  async verify(
    email: string,
    code: string,
    purpose: 'signup' | 'password_reset' | 'email_change',
  ): Promise<boolean> {
    const record = await this.prisma.emailVerification.findFirst({
      where: {
        email,
        code,
        purpose,
        expiresAt: { gt: new Date() },
      },
      orderBy: { createdAt: 'desc' },
    });
    return !!record;
  }

  /** 검증 후 사용된 코드 삭제 (같은 이메일·purpose) */
  async deleteByEmailAndPurpose(
    email: string,
    purpose: 'signup' | 'password_reset' | 'email_change',
  ): Promise<void> {
    await this.prisma.emailVerification.deleteMany({
      where: { email, purpose },
    });
  }

  /** 만료된 레코드 정리 (선택) */
  async deleteExpired(): Promise<void> {
    await this.prisma.emailVerification.deleteMany({
      where: { expiresAt: { lt: new Date() } },
    });
  }
}
