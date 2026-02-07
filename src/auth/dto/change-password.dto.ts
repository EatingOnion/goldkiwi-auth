import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsNotEmpty, IsOptional, IsString, MinLength } from 'class-validator';

export class ChangePasswordDto {
  @ApiPropertyOptional({
    description:
      '현재 비밀번호. OAuth 가입자의 비밀번호 설정 시 생략 가능',
  })
  @IsOptional()
  @IsString()
  currentPassword?: string;

  @ApiProperty({ description: '새 비밀번호 (최소 8자)', example: 'newpassword123' })
  @IsNotEmpty({ message: '새 비밀번호는 필수입니다.' })
  @IsString()
  @MinLength(8, { message: '비밀번호는 최소 8자 이상이어야 합니다.' })
  newPassword!: string;
}
