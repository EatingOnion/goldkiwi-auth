import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty, IsString, MinLength } from 'class-validator';

export class VerifyEmailChangeDto {
  @ApiProperty({ description: '변경할 이메일 (인증 코드 발송 대상)', example: 'new@example.com' })
  @IsNotEmpty({ message: '이메일은 필수입니다.' })
  @IsEmail({}, { message: '유효한 이메일 형식이 아닙니다.' })
  email!: string;

  @ApiProperty({ description: '6자리 인증 코드', example: '123456' })
  @IsNotEmpty({ message: '인증 코드는 필수입니다.' })
  @IsString()
  @MinLength(6, { message: '인증 코드는 6자리입니다.' })
  code!: string;
}
