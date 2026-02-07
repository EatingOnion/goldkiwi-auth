import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty } from 'class-validator';

export class SendEmailChangeDto {
  @ApiProperty({ description: '변경할 이메일 (인증 코드 발송 대상)', example: 'new@example.com' })
  @IsNotEmpty({ message: '이메일은 필수입니다.' })
  @IsEmail({}, { message: '유효한 이메일 형식이 아닙니다.' })
  email!: string;
}
