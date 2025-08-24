type User = { fullName?: string; email: string };

const translations: Record<string, string> = {
  'email.verify_subject': 'Verify your email',
  'email.verify_body':
    '<p>Welcome, {{name}}!</p><p>Please verify your email by clicking <a href="{{verifyUrl}}">here</a>.</p>',
  'email.resent': 'Verification email resent. Please check your inbox.',
  'email.already_verified': 'Your email is already verified.',
};

export function getI18nText(
  key: string,
  user?: User,
  vars: Record<string, string> = {},
) {
  let text = translations[key] || key;
  text = text.replace(/{{name}}/g, user?.fullName || user?.email || '');
  for (const [k, v] of Object.entries(vars)) {
    text = text.replace(new RegExp(`{{${k}}}`, 'g'), v);
  }
  return text;
}
