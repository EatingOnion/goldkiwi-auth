export type VerificationPurpose = 'signup' | 'password_reset' | 'email_change';

export function getVerificationCodeMailContent(
  code: string,
  purpose: VerificationPurpose,
  siteUrl?: string,
  email?: string,
  sentAt?: number,
): { subject: string; text: string; html: string } {
  const subject =
    purpose === 'signup'
      ? '[골드키위] 이메일 인증 코드'
      : purpose === 'password_reset'
        ? '[골드키위] 비밀번호 재설정 인증 코드'
        : '[골드키위] 이메일 변경 인증 코드';

  const intro =
    purpose === 'signup'
      ? '회원가입을 위한 이메일 인증 코드입니다.'
      : purpose === 'password_reset'
        ? '비밀번호 재설정을 위한 인증 코드입니다.'
        : '이메일 변경을 위한 인증 코드입니다.';

  const text = `${intro}\n\n인증 코드: ${code}\n\n※ 이 코드는 3분간 유효합니다.`;

  const baseUrl = (siteUrl || 'https://goldkiwi.com').replace(/\/$/, '');
  const verificationUrl = getVerificationUrl(baseUrl, purpose, email, sentAt);
  const html = buildHtmlEmail({ code, intro, verificationUrl });

  return { subject, text, html };
}

function getVerificationUrl(
  baseUrl: string,
  purpose: VerificationPurpose,
  email?: string,
  sentAt?: number,
): string {
  const encodedEmail = email ? encodeURIComponent(email) : '';
  const sentParam = sentAt ? `&sent=${sentAt}` : '';
  switch (purpose) {
    case 'signup':
      return encodedEmail ? `${baseUrl}/signup?email=${encodedEmail}${sentParam}` : `${baseUrl}/signup`;
    case 'password_reset':
      return encodedEmail ? `${baseUrl}/forgot-password?email=${encodedEmail}${sentParam}` : `${baseUrl}/forgot-password`;
    case 'email_change':
      return `${baseUrl}/mypage?edit=profile${encodedEmail ? `&email=${encodedEmail}` : ''}${sentParam}`;
    default:
      return baseUrl;
  }
}

function buildHtmlEmail({
  code,
  intro,
  verificationUrl,
}: {
  code: string;
  intro: string;
  verificationUrl: string;
}): string {
  return `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>골드키위 인증 코드</title>
</head>
<body style="margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; background-color: #09090b;">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background-color: #09090b; min-height: 100vh;">
    <tr>
      <td align="center" style="padding: 40px 20px;">
        <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width: 420px; background-color: #18181b; border: 1px solid #27272a; border-radius: 16px; overflow: hidden;">
          <tr>
            <td style="padding: 32px 24px; background-color: #a3e635; text-align: center;">
              <div style="display: inline-block; width: 48px; height: 48px; background-color: #18181b; border-radius: 12px; line-height: 48px; font-size: 24px; color: #000;">🥝</div>
              <p style="margin: 12px 0 0 0; font-size: 20px; font-weight: 700; color: #000;">골드키위</p>
            </td>
          </tr>
          <tr>
            <td style="padding: 32px 24px;">
              <p style="margin: 0 0 24px 0; font-size: 15px; color: #a1a1aa; line-height: 1.6;">${intro}</p>
              <div style="background-color: #27272a; border: 2px solid #a3e635; border-radius: 12px; padding: 20px; text-align: center;">
                <p style="margin: 0; font-size: 28px; font-weight: 700; letter-spacing: 8px; color: #a3e635;">${code}</p>
              </div>
              <p style="margin: 20px 0 0 0; font-size: 13px; color: #71717a;">※ 이 코드는 3분간 유효합니다.</p>
              <div style="margin-top: 28px; padding-top: 24px; border-top: 1px solid #27272a; text-align: center;">
                <a href="${verificationUrl}" style="display: inline-block; padding: 12px 24px; background-color: #a3e635; color: #000; font-weight: 600; text-decoration: none; border-radius: 8px;">인증 화면으로 이동</a>
              </div>
            </td>
          </tr>
          <tr>
            <td style="padding: 16px 24px; background-color: #09090b; border-top: 1px solid #27272a;">
              <p style="margin: 0; font-size: 12px; color: #52525b; text-align: center;">이 메일을 요청하지 않으셨다면 무시해 주세요.</p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>
  `.trim();
}
