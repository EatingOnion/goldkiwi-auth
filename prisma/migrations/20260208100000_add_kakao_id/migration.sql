-- AlterTable
ALTER TABLE "auth"."User" ADD COLUMN "kakaoId" TEXT;

-- CreateIndex
CREATE UNIQUE INDEX "User_kakaoId_key" ON "auth"."User"("kakaoId");
