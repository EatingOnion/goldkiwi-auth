import { ApiProperty } from '@nestjs/swagger';

/** 쿠키/클라이언트 검증용. 토큰 발급·갱신·폐기 시 Client 테이블 기준 검증에 사용. */
export class ClientCredentialsDto {
  @ApiProperty({ description: '클라이언트 ID (Client.clientId)' })
  clientId!: string;

  @ApiProperty({ description: '클라이언트 시크릿 (Client.clientSecret)' })
  clientSecret!: string;
}
