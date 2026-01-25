import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString, IsOptional, ValidateIf } from 'class-validator';
import { ClientCredentialsDto } from './client-credentials.dto';

export class LoginDto extends ClientCredentialsDto {
  @ApiProperty({
    description: '이메일 (username이 없을 경우 필수)',
    example: 'john@example.com',
    required: false,
  })
  @ValidateIf((o) => !o.username)
  @IsNotEmpty({ message: '이메일 또는 사용자명 중 하나는 필수입니다.' })
  @IsString({ message: '이메일은 문자열이어야 합니다.' })
  email?: string;

  @ApiProperty({
    description: '사용자명 (email이 없을 경우 필수)',
    example: 'johndoe',
    required: false,
  })
  @ValidateIf((o) => !o.email)
  @IsNotEmpty({ message: '이메일 또는 사용자명 중 하나는 필수입니다.' })
  @IsString({ message: '사용자명은 문자열이어야 합니다.' })
  username?: string;

  @ApiProperty({ description: '비밀번호', example: 'password123' })
  @IsNotEmpty({ message: '비밀번호는 필수입니다.' })
  @IsString({ message: '비밀번호는 문자열이어야 합니다.' })
  password!: string;
}
