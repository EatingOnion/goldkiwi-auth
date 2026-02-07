-- CreateTable
CREATE TABLE "auth"."EmailVerification" (
    "id" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "code" TEXT NOT NULL,
    "purpose" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "EmailVerification_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "EmailVerification_email_purpose_idx" ON "auth"."EmailVerification"("email", "purpose");

-- CreateIndex
CREATE INDEX "EmailVerification_expiresAt_idx" ON "auth"."EmailVerification"("expiresAt");
