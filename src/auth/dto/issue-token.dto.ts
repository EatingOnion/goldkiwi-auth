import { ApiProperty } from '@nestjs/swagger';
import { ClientCredentialsDto } from './client-credentials.dto';

export class IssueTokenDto extends ClientCredentialsDto {
  @ApiProperty({ description: '토큰 발급 대상 사용자 ID' })
  userId!: string;
}
