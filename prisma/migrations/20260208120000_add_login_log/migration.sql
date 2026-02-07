-- CreateTable
CREATE TABLE "auth"."LoginLog" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "ip" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "LoginLog_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "LoginLog_userId_idx" ON "auth"."LoginLog"("userId");

-- CreateIndex
CREATE INDEX "LoginLog_userId_createdAt_idx" ON "auth"."LoginLog"("userId", "createdAt");

-- AddForeignKey
ALTER TABLE "auth"."LoginLog" ADD CONSTRAINT "LoginLog_userId_fkey" FOREIGN KEY ("userId") REFERENCES "auth"."User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
