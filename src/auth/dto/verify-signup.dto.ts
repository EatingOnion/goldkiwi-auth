import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty, IsString, MinLength } from 'class-validator';

export class VerifySignupDto {
  @ApiProperty({ description: '사용자명 (고유)', example: 'johndoe' })
  @IsNotEmpty({ message: '사용자명은 필수입니다.' })
  @IsString({ message: '사용자명은 문자열이어야 합니다.' })
  username!: string;

  @ApiProperty({ description: '이메일 (고유)', example: 'john@example.com' })
  @IsNotEmpty({ message: '이메일은 필수입니다.' })
  @IsEmail({}, { message: '유효한 이메일 형식이 아닙니다.' })
  email!: string;

  @ApiProperty({ description: '비밀번호 (최소 8자)', example: 'password123' })
  @IsNotEmpty({ message: '비밀번호는 필수입니다.' })
  @IsString({ message: '비밀번호는 문자열이어야 합니다.' })
  @MinLength(8, { message: '비밀번호는 최소 8자 이상이어야 합니다.' })
  password!: string;

  @ApiProperty({ description: '이름', example: 'John Doe' })
  @IsNotEmpty({ message: '이름은 필수입니다.' })
  @IsString({ message: '이름은 문자열이어야 합니다.' })
  name!: string;

  @ApiProperty({ description: '이메일 인증 코드 (6자리)', example: '123456' })
  @IsNotEmpty({ message: '인증 코드는 필수입니다.' })
  @IsString({ message: '인증 코드는 문자열이어야 합니다.' })
  verificationCode!: string;
}
