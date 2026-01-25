import { ApiProperty } from '@nestjs/swagger';

export class IssueTokenDto {
  @ApiProperty({ description: '토큰 발급 대상 사용자 ID' })
  userId!: string;
}
