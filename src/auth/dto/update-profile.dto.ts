import { ApiPropertyOptional } from '@nestjs/swagger';
import { IsEmail, IsOptional, IsString, MinLength } from 'class-validator';

export class UpdateProfileDto {
  @ApiPropertyOptional({ description: '이름', example: '홍길동' })
  @IsOptional()
  @IsString({ message: '이름은 문자열이어야 합니다.' })
  name?: string;

  @ApiPropertyOptional({
    description: '이메일 (고유). 변경 시 이메일 인증 코드 required.',
    example: 'john@example.com',
  })
  @IsOptional()
  @IsEmail({}, { message: '유효한 이메일 형식이 아닙니다.' })
  email?: string;

  @ApiPropertyOptional({
    description: '이메일 변경 시 필수. send-email-change-code로 발송받은 6자리 인증 코드',
    example: '123456',
  })
  @IsOptional()
  @IsString()
  @MinLength(6, { message: '인증 코드는 6자리입니다.' })
  verificationCode?: string;
}
