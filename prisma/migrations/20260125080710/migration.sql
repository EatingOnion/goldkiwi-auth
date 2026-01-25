/*
  Warnings:

  - Added the required column `clientSecret` to the `Client` table without a default value. This is not possible if the table is not empty.
  - Added the required column `clientId` to the `RefreshToken` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE "auth"."Client" ADD COLUMN     "clientSecret" TEXT NOT NULL;

-- AlterTable
ALTER TABLE "auth"."RefreshToken" ADD COLUMN     "clientId" TEXT NOT NULL;

-- CreateIndex
CREATE INDEX "RefreshToken_clientId_idx" ON "auth"."RefreshToken"("clientId");

-- AddForeignKey
ALTER TABLE "auth"."RefreshToken" ADD CONSTRAINT "RefreshToken_clientId_fkey" FOREIGN KEY ("clientId") REFERENCES "auth"."Client"("clientId") ON DELETE CASCADE ON UPDATE CASCADE;
