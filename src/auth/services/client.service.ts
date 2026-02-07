import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';

export interface ValidatedClient {
  id: number;
  clientId: string;
  redirectUri: string;
}

@Injectable()
export class ClientService {
  constructor(private readonly prisma: PrismaService) {}

  /**
   * clientId + clientSecret 검증. 쿠키 기반 토큰 발급/갱신/폐기 시 클라이언트 검증용.
   */
  async validateClient(
    clientId: string,
    clientSecret: string,
  ): Promise<ValidatedClient> {
    const client = await this.prisma.client.findUnique({
      where: { clientId },
    });

    if (
      !client ||
      client.deletedAt != null ||
      client.clientSecret !== clientSecret
    ) {
      throw new UnauthorizedException('클라이언트가 유효하지 않습니다.');
    }

    return {
      id: client.id,
      clientId: client.clientId,
      redirectUri: client.redirectUri,
    };
  }
}
