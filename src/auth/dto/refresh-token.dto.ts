import { ApiProperty } from '@nestjs/swagger';
import { ClientCredentialsDto } from './client-credentials.dto';

export class RefreshTokenDto extends ClientCredentialsDto {
  @ApiProperty({ description: '리프레시 토큰' })
  refreshToken!: string;
}
