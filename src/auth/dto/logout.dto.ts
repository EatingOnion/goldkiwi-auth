import { ApiPropertyOptional } from '@nestjs/swagger';
import { IsOptional, IsString } from 'class-validator';

/** 로그아웃 시 clientId/clientSecret은 리프레시 토큰이 있을 때만 필요 */
export class LogoutDto {
  @ApiPropertyOptional({ description: '클라이언트 ID' })
  @IsOptional()
  @IsString()
  clientId?: string;

  @ApiPropertyOptional({ description: '클라이언트 시크릿' })
  @IsOptional()
  @IsString()
  clientSecret?: string;

  @ApiPropertyOptional({ description: '리프레시 토큰. 없으면 쿠키 사용' })
  @IsOptional()
  @IsString()
  refreshToken?: string;
}
