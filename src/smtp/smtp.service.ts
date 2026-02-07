import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as nodemailer from 'nodemailer';
import {
  getVerificationCodeMailContent,
  type VerificationPurpose,
} from './templates/verification-code.template';

@Injectable()
export class SmtpService {
  private transporter: nodemailer.Transporter | null = null;

  constructor(private readonly configService: ConfigService) {
    const host = this.configService.get<string>('SMTP_HOST');
    const user = this.configService.get<string>('SMTP_USER');
    const pass = this.configService.get<string>('SMTP_PASS');

    if (host && user && pass) {
      this.transporter = nodemailer.createTransport({
        host,
        port: this.configService.get<number>('SMTP_PORT', 587),
        secure: false,
        auth: { user, pass },
        tls: { rejectUnauthorized: false },
      });
    }
  }

  /** 인증 코드 이메일 발송 */
  async sendVerificationCode(
    to: string,
    code: string,
    purpose: VerificationPurpose,
  ): Promise<void> {
    if (!this.transporter) {
      throw new Error('SMTP가 설정되지 않았습니다. SMTP_HOST, SMTP_USER, SMTP_PASS를 확인하세요.');
    }

    const siteUrl = this.configService.get<string>('FRONTEND_URL') ?? 'https://goldkiwi.com';
    const sentAt = Date.now();
    const { subject, text, html } = getVerificationCodeMailContent(
      code,
      purpose,
      siteUrl,
      to,
      sentAt,
    );

    await this.transporter.sendMail({
      from: this.configService.get<string>('SMTP_FROM') ?? this.configService.get<string>('SMTP_USER') ?? 'noreply@example.com',
      to,
      subject,
      text,
      html,
    });
  }
}
