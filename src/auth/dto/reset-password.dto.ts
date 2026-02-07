import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty, IsString, MinLength } from 'class-validator';

export class ResetPasswordDto {
  @ApiProperty({ description: '이메일 (인증 코드 발송 대상)', example: 'user@example.com' })
  @IsNotEmpty({ message: '이메일은 필수입니다.' })
  @IsEmail({}, { message: '유효한 이메일 형식이 아닙니다.' })
  email!: string;

  @ApiProperty({ description: '이메일 인증 코드 (6자리)', example: '123456' })
  @IsNotEmpty({ message: '인증 코드는 필수입니다.' })
  @IsString({ message: '인증 코드는 문자열이어야 합니다.' })
  verificationCode!: string;

  @ApiProperty({ description: '새 비밀번호 (최소 8자)', example: 'newpassword123' })
  @IsNotEmpty({ message: '새 비밀번호는 필수입니다.' })
  @IsString({ message: '비밀번호는 문자열이어야 합니다.' })
  @MinLength(8, { message: '비밀번호는 최소 8자 이상이어야 합니다.' })
  newPassword!: string;
}
