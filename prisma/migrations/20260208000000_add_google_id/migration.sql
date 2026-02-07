-- AlterTable
ALTER TABLE "auth"."User" ADD COLUMN "googleId" TEXT;

-- CreateIndex
CREATE UNIQUE INDEX "User_googleId_key" ON "auth"."User"("googleId");
