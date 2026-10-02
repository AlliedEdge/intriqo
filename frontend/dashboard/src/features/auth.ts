export interface PasswordStrength {
  score: number
  label: string
  checks: {
    length: boolean
    lowercase: boolean
    uppercase: boolean
    numberOrSymbol: boolean
  }
}

export const PASSWORD_HELP = 'Use 8 or more characters. A long, unique passphrase works best.'
export const FORGOT_PASSWORD_CONFIRMATION = 'If an account exists for that email address, a password reset link has been sent. Check your inbox and spam folder.'
export const RESEND_VERIFICATION_CONFIRMATION = 'If an unverified account exists for that email address, a new verification link has been sent. Check your inbox and spam folder.'

export function validateEmail(email: string): string | null {
  if (!email.trim()) return 'Enter your email address.'
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) return 'Enter a valid email address.'
  return null
}

export function validatePassword(password: string, confirmation: string): string | null {
  if (Array.from(password).length < 8) return 'Use at least 8 characters for your password.'
  if (new TextEncoder().encode(password).length > 72) return 'Your password is too long. Use at most 72 bytes (fewer characters when using emoji or accented letters).'
  if (password !== confirmation) return 'Your passwords do not match.'
  return null
}

export function isValidAccountToken(token: string): boolean {
  return token.length >= 20 && token.length <= 512 && !/\s/.test(token)
}

/**
 * Turn the display name collected by signup into the username required by the
 * control-plane API. The result is deliberately conservative so it is safe to
 * show, log, and use as an identifier in the existing API contract.
 */
export function deriveUsername(fullName: string): string {
  const normalized = fullName
    .normalize('NFKD')
    .replace(/[\u0300-\u036f]/g, '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')

  const base = normalized || 'operator'
  const withMinimumLength = base.length >= 3 ? base : `${base}_user`
  return withMinimumLength.slice(0, 128)
}

export function passwordStrength(password: string): PasswordStrength {
  const checks = {
    length: Array.from(password).length >= 8,
    lowercase: /[a-z]/.test(password),
    uppercase: /[A-Z]/.test(password),
    numberOrSymbol: /[\d\W_]/.test(password),
  }
  const score = password.length === 0 ? 0 : !checks.length ? 1 : Object.values(checks).filter(Boolean).length
  const label = score === 0 ? 'Enter a password' : score <= 1 ? 'Too weak' : score === 2 ? 'Getting stronger' : score === 3 ? 'Good' : 'Strong'
  return { score, label, checks }
}
