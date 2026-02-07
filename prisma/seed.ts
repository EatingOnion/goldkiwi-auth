import 'dotenv/config';
import * as bcrypt from 'bcrypt';
import { PrismaClient } from '../generated/prisma/client';
import { PrismaPg } from '@prisma/adapter-pg';

const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) {
  throw new Error('DATABASE_URL 환경 변수가 설정되지 않았습니다.');
}

const adapter = new PrismaPg({ connectionString: DATABASE_URL });
const prisma = new PrismaClient({ adapter });

async function main() {
  console.log('🌱 시드 데이터 삽입 시작...');

  // 기본 사용자 생성 (비밀번호: Admin123!)
  const adminPassword = await bcrypt.hash('Admin123!', 10);
  const admin = await prisma.user.upsert({
    where: { username: 'admin' },
    update: {},
    create: {
      username: 'admin',
      email: 'admin@example.com',
      password: adminPassword,
      name: '관리자',
    },
  });
  console.log('  ✓ 사용자 생성:', admin.username);

  // 기본 계정 (a/a)
  const aPassword = await bcrypt.hash('a', 10);
  const aUser = await prisma.user.upsert({
    where: { username: 'a' },
    update: {},
    create: {
      username: 'a',
      email: 'a@example.com',
      password: aPassword,
      name: '기본',
    },
  });
  console.log('  ✓ 사용자 생성:', aUser.username);

  // 테스트 사용자 생성 (비밀번호: Test123!)
  const testPassword = await bcrypt.hash('Test123!', 10);
  const testUser = await prisma.user.upsert({
    where: { username: 'test' },
    update: {},
    create: {
      username: 'test',
      email: 'test@example.com',
      password: testPassword,
      name: '테스트 유저',
    },
  });
  console.log('  ✓ 사용자 생성:', testUser.username);

  // 기본 OAuth 클라이언트 (프론트엔드용)
  const client = await prisma.client.upsert({
    where: { clientId: 'goldkiwi-front' },
    update: {},
    create: {
      name: 'GoldKiwi Frontend',
      clientId: 'goldkiwi-front',
      clientSecret: 'goldkiwi-front-secret-dev',
      redirectUri: 'http://localhost:3000',
    },
  });
  console.log('  ✓ 클라이언트 생성:', client.name, `(clientId: ${client.clientId})`);

  console.log('🌱 시드 데이터 삽입 완료!');
  console.log('');
  console.log('기본 계정:');
  console.log('  - a / a');
  console.log('  - admin / Admin123!');
  console.log('  - test / Test123!');
  console.log('클라이언트: goldkiwi-front / goldkiwi-front-secret-dev');
}

main()
  .catch((e) => {
    console.error('시드 실행 오류:', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
