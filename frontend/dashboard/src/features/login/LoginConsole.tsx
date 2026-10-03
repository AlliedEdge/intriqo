import { useState, type FormEvent } from 'react'
import { Link, useLocation, useNavigate } from 'react-router-dom'
import { ApiError } from '@/api/client'
import { useAuth } from '@/app/providers/AuthProvider'
import { AuthConsole } from '@/components/layout/AuthConsole'
import { AuthMessage, Button, Icon } from '@/components/ui'

export function LoginConsole() {
  const { signIn } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()

  const seeded = (location.state as { username?: string } | null)?.username
  const [username, setUsername] = useState(typeof seeded === 'string' ? seeded : '')
  const [password, setPassword] = useState('')
  const [revealed, setRevealed] = useState(false)
  const [focused, setFocused] = useState<'email' | 'password' | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [needsVerification, setNeedsVerification] = useState(false)
  const [submitting, setSubmitting] = useState(false)

  // Derived rather than stored, so the telemetry can never drift out of sync
  // with what the form is actually doing.
  const phase = error ? 'denied' : submitting || focused === 'password' ? 'verifying' : 'idle'

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (submitting) return
    setError(null)
    setNeedsVerification(false)
    const identifier = username.trim()
    if (!identifier || !password) {
      setError('Enter your username and password to continue.')
      return
    }
    setSubmitting(true)
    try {
      await signIn(identifier, password)
      navigate('/dashboard', { replace: true })
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Sign in failed. Try again.')
      setNeedsVerification(reason instanceof ApiError && reason.code === 'EMAIL_NOT_VERIFIED')
      setSubmitting(false)
    }
  }

  const edit = (setter: (value: string) => void) => (value: string) => {
    setter(value)
    if (error) setError(null)
    if (needsVerification) setNeedsVerification(false)
  }

  return (
    <AuthConsole scope="INTRIQO / SIGNIN" phase={phase} title="Sign in" description="Sign in to your Intriqo security console.">
      <form className="auth-form" onSubmit={submit} noValidate aria-busy={submitting}>
        <label className="field-label" htmlFor="login-username">
          Username
          <input
            id="login-username"
            name="username"
            type="text"
            autoComplete="username"
            autoCapitalize="none"
            autoCorrect="off"
            spellCheck={false}
            value={username}
            onChange={(event) => edit(setUsername)(event.target.value)}
            onFocus={() => setFocused('email')}
            onBlur={() => setFocused((field) => (field === 'email' ? null : field))}
            placeholder="analyst"
            disabled={submitting}
            aria-invalid={error ? true : undefined}
            required
          />
        </label>

        <label className="field-label" htmlFor="login-password">
          Password
          <div className="auth-password-field">
            <input
              id="login-password"
              name="password"
              type={revealed ? 'text' : 'password'}
              autoComplete="current-password"
              value={password}
              onChange={(event) => edit(setPassword)(event.target.value)}
              onFocus={() => setFocused('password')}
              onBlur={() => setFocused((field) => (field === 'password' ? null : field))}
              placeholder="Enter your password"
              disabled={submitting}
              aria-invalid={error ? true : undefined}
              required
            />
            <button
              type="button"
              className="password-toggle"
              aria-label={revealed ? 'Hide password' : 'Show password'}
              aria-pressed={revealed}
              onClick={() => setRevealed((value) => !value)}
              disabled={submitting}
            >
              {revealed ? 'Hide' : 'Show'}
            </button>
          </div>
        </label>

        <Link to="/forgot-password" className="inline-link auth-forgot-link">Forgot password?</Link>

        {error && <AuthMessage error>{error}</AuthMessage>}
        {needsVerification && (
          <Link className="inline-link" to="/verify-email">
            Resend your verification email <Icon name="arrow-right" size={14} />
          </Link>
        )}

        <Button type="submit" className="auth-submit" disabled={submitting}>
          {submitting ? 'Verifying credentials…' : 'Sign in'}
          <Icon name="arrow-right" size={16} />
        </Button>
      </form>

      <p className="auth-help auth-console__foot">
        <span>Don&apos;t have an account?</span>
        <Link className="inline-link" to="/signup">
          Create workspace <Icon name="arrow-right" size={14} />
        </Link>
      </p>
    </AuthConsole>
  )
}