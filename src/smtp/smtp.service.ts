import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class SmtpService {
  constructor(private readonly configService: ConfigService) {}
}
