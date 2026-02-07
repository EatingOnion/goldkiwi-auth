import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString } from 'class-validator';

/** 쿠키/클라이언트 검증용. 토큰 발급·갱신·폐기 시 Client 테이블 기준 검증에 사용. */
export class ClientCredentialsDto {
  @ApiProperty({ description: '클라이언트 ID (Client.clientId)' })
  @IsNotEmpty({ message: 'clientId는 필수입니다.' })
  @IsString()
  clientId!: string;

  @ApiProperty({ description: '클라이언트 시크릿 (Client.clientSecret)' })
  @IsNotEmpty({ message: 'clientSecret은 필수입니다.' })
  @IsString()
  clientSecret!: string;
}
