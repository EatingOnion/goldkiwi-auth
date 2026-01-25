import { ApiPropertyOptional } from '@nestjs/swagger';
import { ClientCredentialsDto } from './client-credentials.dto';

export class RefreshTokenDto extends ClientCredentialsDto {
  @ApiPropertyOptional({
    description:
      '리프레시 토큰. 없으면 쿠키 refreshToken 사용 (cookie-parser)',
  })
  refreshToken?: string;
}
