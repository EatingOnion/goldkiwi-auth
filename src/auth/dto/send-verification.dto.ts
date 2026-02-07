import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsIn, IsNotEmpty } from 'class-validator';

export class SendVerificationDto {
  @ApiProperty({ description: '이메일 (인증 코드 발송 대상)', example: 'user@example.com' })
  @IsNotEmpty({ message: '이메일은 필수입니다.' })
  @IsEmail({}, { message: '유효한 이메일 형식이 아닙니다.' })
  email!: string;

  @ApiProperty({
    description: '용도: signup(회원가입) | password_reset(비밀번호 찾기)',
    enum: ['signup', 'password_reset'],
  })
  @IsNotEmpty({ message: '용도는 필수입니다.' })
  @IsIn(['signup', 'password_reset'], { message: 'signup 또는 password_reset만 가능합니다.' })
  purpose!: 'signup' | 'password_reset';
}
