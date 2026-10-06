import { useEffect, useRef, useState, type FormEvent, type ReactNode } from 'react'
import { Link, useParams, useSearchParams } from 'react-router-dom'
import { ApiError, apiConfiguration } from '@/api/client'
import { auditApi, authApi, eventsApi, findingsApi, incidentsApi, tasksApi } from '@/api'
import { useAuth } from '@/app/providers/AuthProvider'
import { useApi } from '@/hooks/useApi'
import { findingSeverity, formatDate, formatDateOnly, prettyJson, relativeTime, shortId, toIsoDateTime, truncate } from '@/lib/format'
import {
  eventDetectionSource, eventDetector, eventRelationshipIds, findingDetectionSource,
  findingDetector, findingEventType, incidentRelationshipIds, investigationState,
  taskFindingIds,
} from '@/lib/soc'
import type { AgentTask, AuditLog, Finding, Incident, MessageResponse, RegisteredUser, SecurityEvent, Severity } from '@/types/api'
import {
  FORGOT_PASSWORD_CONFIRMATION, isValidAccountToken, PASSWORD_HELP,
  passwordStrength, RESEND_VERIFICATION_CONFIRMATION, validateEmail, validatePassword,
} from './auth'
import {
  AuthMessage, Badge, Button, Card, EmptyState, ErrorState, Icon, KeyValue, LoadingRows,
  PageHeader, Pagination, SectionHeading, SeverityBadge, StatusBadge, TableFrame, Logo,
} from '@/components/ui'
import { LandingHero } from './landing/LandingHero'
import { PacketToFindings } from './landing/PacketToFindings'
import { AuthConsole } from '@/components/layout/AuthConsole'
import { GridPulse } from '@/components/GridPulse'
import { SignalGlobe } from '@/components/SignalGlobe'

const GITHUB_URL = 'https://github.com/AlliedEdge/intriqo'
// const DOCS_URL = `${GITHUB_URL}/tree/main/docs`
// const CONTRIBUTING_URL = `${GITHUB_URL}/blob/main/CONTRIBUTING.md`

function Reveal({ children, className = '' }: { children: ReactNode; className?: string }) {
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const element = ref.current
    if (!element || typeof IntersectionObserver === 'undefined') {
      element?.classList.add('is-visible')
      return
    }
    const observer = new IntersectionObserver(([entry]) => {
      if (entry.isIntersecting) {
        element.classList.add('is-visible')
        observer.unobserve(element)
      }
    }, { rootMargin: '0px 0px -8% 0px', threshold: 0.08 })
    observer.observe(element)
    return () => observer.disconnect()
  }, [])

  return <div ref={ref} className={`reveal ${className}`}>{children}</div>
}

function asString(value: unknown): string {
  if (typeof value === 'string') return value
  if (typeof value === 'number' || typeof value === 'boolean') return String(value)
  return ''
}

function safeError(error: Error | null): string {
  return error?.message || 'The control plane returned an unexpected response.'
}

function ExternalLink({ href, children, className = '' }: { href: string; children: ReactNode; className?: string }) {
  return <a className={className} href={href} target="_blank" rel="noreferrer">{children}<Icon name="arrow-up-right" size={14} /></a>
}

function ProvenanceBadges({ eventType, source, detector }: { eventType?: string | null; source?: string | null; detector?: string | null }) {
  return <span className="provenance-inline">
    {eventType && <Badge tone="info">{eventType}</Badge>}
    {source && <Badge tone="neutral">source: {source}</Badge>}
    {detector && <Badge tone="neutral">detector: {detector}</Badge>}
  </span>
}

function EventProvenance({ event }: { event: SecurityEvent }) {
  return <ProvenanceBadges eventType={event.event_type} source={eventDetectionSource(event)} detector={eventDetector(event)} />
}

function FindingProvenance({ finding, event }: { finding: Finding; event?: SecurityEvent | null }) {
  return <ProvenanceBadges eventType={findingEventType(finding) || event?.event_type} source={findingDetectionSource(finding) || (event ? eventDetectionSource(event) : null)} detector={findingDetector(finding) || (event ? eventDetector(event) : null)} />
}

function AuditLink({ resourceId }: { resourceId: string }) {
  return <Link className="panel-link" to={`/audit?resource_id=${encodeURIComponent(resourceId)}`}>Audit trail <Icon name="arrow-right" size={14} /></Link>
}

function InvestigationState({ tasks }: { tasks: AgentTask[] }) {
  const state = investigationState(tasks)
  const description = state === 'COMPLETED'
    ? 'All linked investigation tasks have completed.'
    : state === 'BLOCKED'
      ? 'A linked investigation task failed or was cancelled.'
      : state === 'IN_PROGRESS'
        ? 'Linked investigation tasks are still running.'
        : 'No investigation task is linked yet.'
  return <div className="workflow-state"><div><strong>Investigation</strong><span>{description}</span></div><StatusBadge status={state} /></div>
}

function ArchitectureFlow() {
  const steps = ['Network traffic', 'C++ IDS engine', 'SecurityEvent', 'Python control plane', 'AgentTask', 'Investigation', 'Policy decision', 'Audit log']

  return (
    <div className="architecture-flow">
      {steps.map((step, index) => (
        <div className="flow-step-wrap" key={step}>
          <div className={`flow-step${index === 0 || index === steps.length - 1 ? ' flow-step-emphasis' : ''}`}>
            <span className="flow-index">{String(index + 1).padStart(2, '0')}</span>
            <span>{step}</span>
          </div>
          {index < steps.length - 1 && <span className="flow-arrow"><Icon name="arrow-right" size={16} /></span>}
        </div>
      ))}
    </div>
  )
}

export function LandingPage() {
  return (
    <div className="public-site">
      <LandingHero />

      <main>
        <PacketToFindings />

        <section id="product" className="public-section section-light-red">
          <GridPulse className="slr-grid-pulse" />
          <div className="slr-bg-canvas" aria-hidden="true">
            <div className="slr-blob slr-blob-1" /><div className="slr-blob slr-blob-2" /><div className="slr-blob slr-blob-3" />
            <div className="slr-ring slr-ring-1" /><div className="slr-ring slr-ring-2" />
            <div className="slr-sparks"><span /><span /><span /><span /><span /><span /></div>
          </div>
          <div className="container slr-content">
          <Reveal><div className="section-intro" data-grid-avoid><p className="eyebrow">PACKET TO FINDING</p><h2>A clear path from packet to finding.</h2><p>Each layer has a defined responsibility and a typed handoff, so detection, investigation, policy, and audit records remain connected.</p></div></Reveal>
          <Reveal className="reveal-delay-1"><div className="capability-grid" data-grid-avoid>
            <Capability icon="network" index="01" title="C++ detection" copy="IPv4 parsing, TCP/UDP/ICMP handling, flow tracking, and deterministic port-scan detection." />
            <Capability icon="layers" index="02" title="SecurityEvent" copy="A typed JSON handoff carries detected network signals from the IDS into the rest of the SOC." />
            <Capability icon="server" index="03" title="Control plane" copy="FastAPI services connect authenticated events, incidents, tasks, findings, and audit logs." />
            <Capability icon="bot" index="04" title="Investigation" copy="The multi-agent design routes evidence through investigation tasks toward structured findings." />
            <Capability icon="shield" index="05" title="Auditability" copy="Policy decisions and operator-facing records keep the path from event to finding inspectable." />
          </div></Reveal>
          </div>{/* .slr-content */}
        </section>

        <section id="architecture" className="public-section architecture-section">
          <div className="container">
            <Reveal><div className="section-intro"><p className="eyebrow">CONTROL PLANE / INVESTIGATION</p><h2>One workflow. Explicit boundaries.</h2><p>Intriqo keeps detection, persistence, investigation, policy, and auditability visible as separate, inspectable stages.</p></div></Reveal>
            <Reveal className="reveal-delay-1"><div className="architecture-card"><ArchitectureFlow /><div className="architecture-caption"><span><span className="legend-dot legend-cyan" />Implemented path</span><span><span className="legend-dot legend-slate" />Contract boundary</span><ExternalLink href={`${GITHUB_URL}/blob/main/docs/architecture/system-architecture.md`} className="inline-link">Read the architecture <Icon name="arrow-up-right" size={14} /></ExternalLink></div></div></Reveal>
          </div>
        </section>

        <section id="get-intriqo" className="public-section download-section section-light-red">
          <GridPulse className="slr-grid-pulse" />
          <div className="slr-bg-canvas" aria-hidden="true">
            <div className="slr-blob slr-blob-1" /><div className="slr-blob slr-blob-2" /><div className="slr-blob slr-blob-3" />
            <div className="slr-ring slr-ring-1" /><div className="slr-ring slr-ring-2" />
            <div className="slr-sparks"><span /><span /><span /><span /><span /><span /></div>
          </div>
          <div className="container slr-content">
             <Reveal><div className="section-intro" data-grid-avoid><p className="eyebrow">GET STARTED</p><h2>Run the control plane where you work.</h2><p>Use the repository's source and Docker workflows to run the web application, backend, and supporting services locally.</p></div></Reveal>
            <Reveal className="reveal-delay-1"><div className="download-grid" data-grid-avoid>
              <DownloadCard icon="code" label="SOURCE" title="Clone the repository" copy="Use the documented Python, C++, Node.js, and Docker prerequisites." command="git clone https://github.com/AlliedEdge/intriqo.git" href={`${GITHUB_URL}#quick-start`} />
              <DownloadCard icon="layers" label="LOCAL RUNTIME" title="One-command stack" copy="Start PostgreSQL and the host-process Core v1 services with the documented launcher." command="./scripts/start-intriqo.sh" href={`${GITHUB_URL}#quick-start`} />
              <DownloadCard icon="terminal" label="LINUX" title="Linux development" copy="Build the engine, run the control plane, and start the Vite dashboard from source." command="cd frontend/dashboard && npm run dev" href={`${GITHUB_URL}#quick-start`} />
            </div></Reveal>
          </div>{/* .slr-content */}
        </section>

        <section className="public-section final-cta-section">
          <div className="container final-cta-layout">
            <Reveal className="final-cta-content">
              <div>
                <p className="eyebrow">FOLLOW THE SIGNAL</p>
                <h2>Build your next investigation on evidence.</h2>
                <p className="final-cta-desc">
                  Explore the source, run the stack locally, and see where the workflow takes you.
                </p>
              </div>
              <div className="final-cta-actions">
                <ExternalLink href={GITHUB_URL} className="button button-primary">
                  Open GitHub <Icon name="arrow-up-right" size={16} />
                </ExternalLink>
                <Link to="/signup" className="button button-secondary">
                  Create account <Icon name="arrow-right" size={16} />
                </Link>
              </div>
            </Reveal>
            <div className="final-cta-globe-wrap" aria-hidden="true">
              <SignalGlobe />
            </div>
          </div>
        </section>
      </main>

      <footer className="public-footer container"><Logo /><span>Open-source security operations, with the receipts left in the repository.</span><span>© {new Date().getFullYear()} AlliedEdge</span></footer>
    </div>
  )
}

function Capability({ icon, index, title, copy }: { icon: 'network' | 'server' | 'bot' | 'shield' | 'activity' | 'layers'; index: string; title: string; copy: string }) {
  return <article className="capability"><div className="capability-top"><span className="capability-icon"><Icon name={icon} size={20} /></span><span className="capability-index">{index}</span></div><h3>{title}</h3><p>{copy}</p></article>
}

function DownloadCard({ icon, label, title, copy, command, href }: { icon: 'code' | 'layers' | 'terminal'; label: string; title: string; copy: string; command: string; href: string }) {
  return <article className="download-card"><div className="download-card-top"><span className="capability-icon"><Icon name={icon} size={19} /></span><span className="card-label">{label}</span></div><h3>{title}</h3><p>{copy}</p><code>{command}</code><ExternalLink href={href} className="inline-link">Read setup <Icon name="arrow-up-right" size={14} /></ExternalLink></article>
}

function authError(reason: unknown, fallback: string): string {
  return reason instanceof Error ? reason.message : fallback
}

function NewPasswordFields({ password, confirmation, onPasswordChange, onConfirmationChange, disabled }: { password: string; confirmation: string; onPasswordChange: (value: string) => void; onConfirmationChange: (value: string) => void; disabled: boolean }) {
  const [visible, setVisible] = useState(false)
  const strength = passwordStrength(password)
  return <>
    <label className="field-label" htmlFor="new-password">Password</label>
    <div className="auth-password-field"><input id="new-password" name="password" type={visible ? 'text' : 'password'} autoComplete="new-password" value={password} onChange={(event) => onPasswordChange(event.target.value)} placeholder="Create a strong password" disabled={disabled} required aria-describedby="password-help password-strength" /><button type="button" className="password-toggle" aria-label={visible ? 'Hide passwords' : 'Show passwords'} aria-pressed={visible} onClick={() => setVisible((value) => !value)} disabled={disabled}>{visible ? 'Hide' : 'Show'}</button></div>
    <div className="password-feedback"><div id="password-strength" className={`password-strength password-strength-${strength.score}`}><span className="password-strength-track" aria-hidden="true">{[1, 2, 3, 4].map((step) => <span key={step} className={step <= strength.score ? 'is-filled' : ''} />)}</span><span>{strength.label}</span></div><p id="password-help">{PASSWORD_HELP}</p></div>
    <label className="field-label" htmlFor="confirm-password">Confirm password<input id="confirm-password" name="confirm-password" type={visible ? 'text' : 'password'} autoComplete="new-password" value={confirmation} onChange={(event) => onConfirmationChange(event.target.value)} placeholder="Enter your password again" disabled={disabled} required /></label>
  </>
}

function ResendVerification({ initialEmail = '' }: { initialEmail?: string }) {
  const [email, setEmail] = useState(initialEmail)
  const [error, setError] = useState<string | null>(null)
  const [sent, setSent] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (submitting) return
    setSent(false)
    const invalid = validateEmail(email)
    setError(invalid)
    if (invalid) return
    setSubmitting(true)
    try {
      await authApi.resendVerification(email.trim())
      setSent(true)
    } catch (reason) {
      setError(authError(reason, 'Unable to send a verification link. Try again.'))
    } finally {
      setSubmitting(false)
    }
  }
  return <form className="auth-form auth-resend" onSubmit={submit} noValidate aria-busy={submitting}>
    <div className="auth-section-heading"><h3>Need a new verification link?</h3><p>Use the email address you registered with. Only your newest link will work.</p></div>
    <label className="field-label" htmlFor="verification-email">Email address<input id="verification-email" name="email" type="email" autoComplete="email" value={email} onChange={(event) => { setEmail(event.target.value); setSent(false) }} placeholder="you@example.com" disabled={submitting} required /></label>
    {error && <AuthMessage error>{error}</AuthMessage>}
    {sent && <AuthMessage>{RESEND_VERIFICATION_CONFIRMATION}</AuthMessage>}
    <Button type="submit" variant="secondary" disabled={submitting || sent}>{submitting ? 'Sending verification link…' : sent ? 'Verification link requested' : 'Resend verification email'}</Button>
  </form>
}

export function SignupPage() {
  const [fullName, setFullName] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [confirmation, setConfirmation] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)
  const [registered, setRegistered] = useState<RegisteredUser | null>(null)

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (submitting) return
    const invalid = !fullName.trim() ? 'Enter your full name.'
      : validateEmail(email) || validatePassword(password, confirmation)
    setError(invalid)
    if (invalid) return
    setSubmitting(true)
    try {
      const account = await authApi.register({ full_name: fullName.trim(), email: email.trim(), password })
      setRegistered(account)
      setPassword('')
      setConfirmation('')
    } catch (reason) {
      setError(authError(reason, 'Unable to create your account. Try again.'))
    } finally {
      setSubmitting(false)
    }
  }

  if (registered) return <AuthConsole scope="INTRIQO / SIGNUP" title="Check your email" description="Your verification link has been sent to your registered email address.">
    <div className="auth-state"><AuthMessage>Your verification link has been sent to <strong>{registered.email}</strong>. Open it to finish setting up your account.</AuthMessage><p className="auth-detail">Your sign-in username is <strong className="mono">{registered.username}</strong>. Keep it handy when you return to the dashboard.</p></div>
    <ResendVerification initialEmail={registered.email} />
      <p className="auth-help">Already verified? <Link className="inline-link" to="/login" state={{ username: registered.username }}>Sign in</Link></p>
  </AuthConsole>

  return <AuthConsole scope="INTRIQO / SIGNUP" phase={error ? 'denied' : submitting ? 'verifying' : 'idle'} title="Create your account" description="Join your Intriqo control plane and start investigating.">
    <form className="auth-form" onSubmit={submit} noValidate aria-busy={submitting}>
      <label className="field-label" htmlFor="full-name">Full name<input id="full-name" name="name" autoComplete="name" value={fullName} onChange={(event) => setFullName(event.target.value)} placeholder="Alex Morgan" disabled={submitting} required /></label>
      <label className="field-label" htmlFor="signup-email">Email address<input id="signup-email" name="email" type="email" autoComplete="email" value={email} onChange={(event) => setEmail(event.target.value)} placeholder="you@example.com" disabled={submitting} required /></label>
      <NewPasswordFields password={password} confirmation={confirmation} onPasswordChange={setPassword} onConfirmationChange={setConfirmation} disabled={submitting} />
      {error && <AuthMessage error>{error}</AuthMessage>}
      <Button type="submit" disabled={submitting} className="auth-submit">{submitting ? 'Creating your account…' : 'Create account'}<Icon name="arrow-right" size={16} /></Button>
    </form>
    <p className="auth-help auth-console__foot"><span>Already have an account?</span><Link className="inline-link" to="/login">Sign in</Link></p>
  </AuthConsole>
}

export function VerifyEmailPage() {
  const [params] = useSearchParams()
  const token = params.get('token') || ''
  return <VerifyEmailResult token={token} key={token} />
}

function VerifyEmailResult({ token }: { token: string }) {
  const validToken = isValidAccountToken(token)
  const [state, setState] = useState<'checking' | 'success' | 'error' | 'empty'>(validToken ? 'checking' : token ? 'error' : 'empty')
  const [error, setError] = useState<string | null>(token && !validToken ? 'This verification link is incomplete or invalid. Request a new link below.' : null)
  const verification = useRef<Promise<MessageResponse> | null>(null)

  useEffect(() => {
    if (!validToken) return
    let active = true
    // Reuse this single-use operation during React StrictMode's effect replay.
    verification.current ??= authApi.verifyEmail(token)
    void verification.current.then(() => {
      if (active) setState('success')
    }, (reason: unknown) => {
      if (!active) return
      setError(reason instanceof ApiError && reason.code === 'INVALID_OR_EXPIRED_TOKEN'
        ? 'This verification link has expired or was already used. If you have already verified your email, sign in. Otherwise, request a new link below.'
        : authError(reason, 'Unable to verify your email. Request a new link below.'))
      setState('error')
    })
    return () => { active = false }
  }, [token, validToken])

  return <AuthConsole scope="INTRIQO / VERIFY" phase={state === 'checking' ? 'verifying' : state === 'error' ? 'denied' : 'idle'} title={state === 'success' ? 'Email verified' : state === 'checking' ? 'Verifying your email' : 'Verify your email'} description={state === 'success' ? 'You’re all set. Your email address has been confirmed.' : 'Confirm your email address to complete your account setup.'}>
    <div className="auth-state">
      {state === 'checking' && <div className="auth-progress" role="status"><span className="loading-spinner" /> Checking your verification link…</div>}
      {state === 'success' && <><AuthMessage>Your email has been verified successfully. Sign in to open your workspace.</AuthMessage><Link className="button button-primary auth-submit" to="/login">Continue to sign in <Icon name="arrow-right" size={16} /></Link></>}
      {state === 'error' && <AuthMessage error>{error}</AuthMessage>}
      {state === 'empty' && <p className="auth-detail">Open the verification link in your email, or enter your email below to request a new one.</p>}
    </div>
    {(state === 'error' || state === 'empty') && <ResendVerification />}
    {state !== 'success' && <p className="auth-help">Already verified? <Link className="inline-link" to="/login">Sign in</Link> <span className="auth-link-separator">·</span> <Link className="inline-link" to="/signup">Create an account</Link></p>}
  </AuthConsole>
}

export function ForgotPasswordPage() {
  const [email, setEmail] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)
  const [sent, setSent] = useState(false)
  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (submitting) return
    const invalid = validateEmail(email)
    setError(invalid)
    if (invalid) return
    setSubmitting(true)
    try {
      await authApi.forgotPassword(email.trim())
      setSent(true)
    } catch (reason) {
      setError(authError(reason, 'Unable to request a password reset. Try again.'))
    } finally {
      setSubmitting(false)
    }
  }
  return <AuthConsole scope="INTRIQO / RECOVERY" phase={error ? 'denied' : submitting ? 'verifying' : 'idle'} title={sent ? 'Check your inbox' : 'Forgot your password?'} description={sent ? 'Follow the link in your email to choose a new password.' : 'Enter the email address associated with your Intriqo account.'}>
    {sent ? <div className="auth-state"><AuthMessage>{FORGOT_PASSWORD_CONFIRMATION}</AuthMessage><p className="auth-detail">Reset links expire and can only be used once. Use the newest email if you requested more than one.</p><Button type="button" variant="secondary" onClick={() => setSent(false)}>Try another email address</Button></div> : <form className="auth-form" onSubmit={submit} noValidate aria-busy={submitting}>
      <label className="field-label" htmlFor="recovery-email">Email address<input id="recovery-email" name="email" type="email" autoComplete="email" value={email} onChange={(event) => setEmail(event.target.value)} placeholder="you@example.com" disabled={submitting} required /></label>
      {error && <AuthMessage error>{error}</AuthMessage>}
      <Button type="submit" disabled={submitting} className="auth-submit">{submitting ? 'Sending reset link…' : 'Send reset link'}<Icon name="arrow-right" size={16} /></Button>
    </form>}
    <p className="auth-help"><Link className="inline-link" to="/login"><Icon name="chevron-left" size={14} /> Back to sign in</Link> <span className="auth-link-separator">·</span> <Link className="inline-link" to="/signup">Create an account</Link></p>
  </AuthConsole>
}

export function ResetPasswordPage() {
  const [params] = useSearchParams()
  const token = params.get('token') || ''
  return <ResetPasswordForm token={token} key={token} />
}

function ResetPasswordForm({ token }: { token: string }) {
  const { signOut } = useAuth()
  const [password, setPassword] = useState('')
  const [confirmation, setConfirmation] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)
  const [complete, setComplete] = useState(false)
  const [expired, setExpired] = useState(false)
  const validToken = isValidAccountToken(token)
  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (submitting || !validToken || expired) return
    const invalid = validatePassword(password, confirmation)
    setError(invalid)
    if (invalid) return
    setSubmitting(true)
    try {
      await authApi.resetPassword(token, password)
      signOut()
      setPassword('')
      setConfirmation('')
      setComplete(true)
    } catch (reason) {
      if (reason instanceof ApiError && reason.code === 'INVALID_OR_EXPIRED_TOKEN') {
        setExpired(true)
        setError('This reset link has expired or was already used. Request a new link to reset your password.')
      } else {
        setError(authError(reason, 'Unable to reset your password. Try again.'))
      }
    } finally {
      setSubmitting(false)
    }
  }
  return <AuthConsole scope="INTRIQO / RECOVERY" phase={error ? 'denied' : submitting ? 'verifying' : 'idle'} title={complete ? 'Password updated' : 'Choose a new password'} description={complete ? 'Your new password is ready to use.' : 'Use a unique password that you haven’t used elsewhere.'}>
     {complete ? <div className="auth-state"><AuthMessage>Password updated successfully. Sign in with your new password to continue.</AuthMessage><Link className="button button-primary auth-submit" to="/login">Continue to sign in <Icon name="arrow-right" size={16} /></Link></div>
      : !validToken || expired ? <div className="auth-state"><AuthMessage error>{error || 'This reset link is missing or incomplete. Open the full link from your email, or request a new one.'}</AuthMessage><Link className="button button-primary auth-submit" to="/forgot-password">Request a new reset link <Icon name="arrow-right" size={16} /></Link></div>
        : <form className="auth-form" onSubmit={submit} noValidate aria-busy={submitting}>
          <NewPasswordFields password={password} confirmation={confirmation} onPasswordChange={setPassword} onConfirmationChange={setConfirmation} disabled={submitting} />
          {error && <AuthMessage error>{error}</AuthMessage>}
          <Button type="submit" disabled={submitting} className="auth-submit">{submitting ? 'Updating password…' : 'Reset password'}<Icon name="arrow-right" size={16} /></Button>
        </form>}
    {!complete && <p className="auth-help"><Link className="inline-link" to="/login"><Icon name="chevron-left" size={14} /> Back to sign in</Link> <span className="auth-link-separator">·</span> <Link className="inline-link" to="/forgot-password">Request another link</Link></p>}
  </AuthConsole>
}

interface DashboardSnapshot {
  counts: Record<Severity, number>
  events: { items: SecurityEvent[]; total: number }
  incidents: { items: Incident[]; total: number }
  tasks: { items: AgentTask[]; total: number }
  findings: { items: Finding[]; total: number }
  audit: { items: AuditLog[]; total: number }
}

const dashboardSeverities: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

export function DashboardPage() {
  const [reload, setReload] = useState(0)
  const query = useApi<DashboardSnapshot>(async (signal) => {
    const [countResponses, events, activeIncidentResponses, tasks, findings, audit] = await Promise.all([
      Promise.all(dashboardSeverities.map((severity) => eventsApi.list({ severity, page: 1, page_size: 1 }, signal))),
      eventsApi.list({ page: 1, page_size: 8 }, signal),
      Promise.all((['OPEN', 'INVESTIGATING', 'CONTAINED'] as const).map((status) => incidentsApi.list({ status, page: 1, page_size: 6 }, signal))),
      tasksApi.list({ page: 1, page_size: 6 }, signal),
      findingsApi.list({ page: 1, page_size: 6 }, signal),
      auditApi.list({ page: 1, page_size: 10 }, signal),
    ])
    const counts = {} as Record<Severity, number>
    dashboardSeverities.forEach((severity, index) => { counts[severity] = countResponses[index].total })
    const incidents = {
      items: activeIncidentResponses.flatMap((response) => response.items)
        .sort((left, right) => Date.parse(right.updated_at) - Date.parse(left.updated_at))
        .slice(0, 6),
      total: activeIncidentResponses.reduce((total, response) => total + response.total, 0),
      page: 1,
      page_size: 6,
      has_next: false,
    }
    return { counts, events, incidents, tasks, findings, audit }
  }, `dashboard-${reload}`)

  if (query.loading && !query.data) return <div className="page-stack"><PageHeader eyebrow="SECURITY OPERATIONS" title="Overview" description="Loading the current control-plane state…" /><LoadingRows columns={4} rows={7} /></div>
  if (query.error && !query.data) return <div className="page-stack"><PageHeader eyebrow="SECURITY OPERATIONS" title="Overview" description="The dashboard reads directly from the Intriqo APIs." /><ErrorState message={safeError(query.error)} onRetry={() => setReload((value) => value + 1)} /></div>
  if (!query.data) return null
  const { counts, events, incidents, tasks, findings, audit } = query.data

  return <div className="page-stack"><PageHeader eyebrow="SECURITY OPERATIONS" title="Overview" description="A connected view of detection, investigation, and audit activity." actions={<Button variant="secondary" size="sm" icon="refresh" onClick={() => setReload((value) => value + 1)}>Refresh</Button>} />
     <div className="dashboard-meta"><span><span className="status-pulse" /> REST API connected</span><span>{incidents.total.toLocaleString()} incidents · {tasks.total.toLocaleString()} tasks · {findings.total.toLocaleString()} findings · {audit.total.toLocaleString()} audit records</span>{query.updatedAt && <span>Updated {relativeTime(query.updatedAt.toISOString())}</span>}</div>
    <div className="metric-grid">{dashboardSeverities.map((severity) => <Card className={`metric-card metric-${severity.toLowerCase()}`} key={severity}><div className="metric-label"><SeverityBadge severity={severity} /><Icon name="arrow-up-right" size={15} /></div><strong>{counts[severity].toLocaleString()}</strong><span>events in control plane</span></Card>)}</div>
     <div className="dashboard-grid dashboard-grid-primary"><Card className="panel panel-wide"><SectionHeading title="Recent security events" description="Latest events emitted by the IDS engine." action={<Link className="panel-link" to="/events">View all <Icon name="arrow-right" size={14} /></Link>} />{events.items.length === 0 ? <EmptyState icon="network" title="No security events yet" description="Run the Intriqo IDS demo to generate your first event." /> : <TableFrame><table className="data-table"><thead><tr><th>Severity</th><th>Provenance</th><th>Source → destination</th><th>Detected</th><th>Links</th></tr></thead><tbody>{events.items.map((event) => { const relationships = eventRelationshipIds(event); return <tr key={event.event_id}><td><SeverityBadge severity={event.severity} /></td><td><Link className="table-link" to={`/events/${event.event_id}`}><EventProvenance event={event} /></Link></td><td className="mono">{event.source_address} <span className="muted">→</span> {event.destination_address}</td><td>{formatDate(event.timestamp)}</td><td><span className="table-counts">{relationships.incidentIds.length} incident · {relationships.taskIds.length} task · {relationships.findingIds.length} finding</span></td></tr> })}</tbody></table></TableFrame>}</Card><Card className="panel"><SectionHeading title="Active incidents" description="Open work requiring operator attention." action={<Link className="panel-link" to="/incidents">View all <Icon name="arrow-right" size={14} /></Link>} />{incidents.items.length === 0 ? <EmptyState icon="alert" title="No active incidents" description="Incidents will appear here when the control plane creates them." /> : <div className="compact-list">{incidents.items.map((incident) => <Link className="compact-list-row" to={`/incidents/${incident.incident_id}`} key={incident.incident_id}><span><strong>{truncate(incident.title, 42)}</strong><small>{shortId(incident.incident_id, 12)} · {relativeTime(incident.updated_at)} · {incident.linked_event_ids.length} events · {(incident.linked_task_ids || []).length} tasks</small></span><span><SeverityBadge severity={incident.severity} /><StatusBadge status={incident.status} /></span></Link>)}</div>}</Card></div>
     <div className="dashboard-grid"><Card className="panel"><SectionHeading title="Agent activity" description="Tasks in the investigation workflow." action={<Link className="panel-link" to="/agents">Agents <Icon name="arrow-right" size={14} /></Link>} />{tasks.items.length === 0 ? <EmptyState icon="bot" title="No agent tasks" description="Agent tasks will appear after an incident is queued." /> : <div className="compact-list">{tasks.items.map((task) => <Link className="compact-list-row" to={`/tasks/${task.task_id}`} key={task.task_id}><span><strong>{truncate(task.description, 38)}</strong><small>{task.task_type} · {formatDate(task.created_at)} · {taskFindingIds(task).length} findings</small></span><StatusBadge status={task.status} /></Link>)}</div>}</Card><Card className="panel"><SectionHeading title="Recent findings" description="Structured output from investigation agents." action={<Link className="panel-link" to="/findings">Findings <Icon name="arrow-right" size={14} /></Link>} />{findings.items.length === 0 ? <EmptyState icon="bot" title="No findings yet" description="Agent findings will appear here after a task completes." /> : <div className="compact-list">{findings.items.map((finding) => <Link className="compact-list-row" to={`/findings/${finding.finding_id}`} key={finding.finding_id}><span><strong>{truncate(finding.summary || finding.findings[0] || 'Untitled finding', 38)}</strong><small>{finding.agent_name} · {formatDate(finding.created_at)}</small><FindingProvenance finding={finding} /></span><span><SeverityBadge severity={findingSeverity(finding)} /><StatusBadge status={finding.status} /></span></Link>)}</div>}</Card><Card className="panel"><SectionHeading title="Activity timeline" description="Append-only audit records across the workflow." action={<Link className="panel-link" to="/audit">Audit <Icon name="arrow-right" size={14} /></Link>} />{audit.items.length === 0 ? <EmptyState icon="clock" title="No audit activity" description="Workflow actions will be recorded here as the system runs." /> : <div className="timeline">{audit.items.slice(0, 7).map((entry) => <TimelineEntry entry={entry} key={entry.id} />)}</div>}</Card></div>
  </div>
}

function TimelineEntry({ entry }: { entry: AuditLog }) {
  const icon = entry.resource_type === 'security_event' ? 'network' : entry.resource_type === 'incident' ? 'alert' : entry.resource_type === 'agent_task' ? 'bot' : entry.resource_type === 'finding' ? 'check' : 'list'
  const path = resourcePath(entry.resource_type, entry.resource_id)
  return <div className="timeline-entry"><span className="timeline-icon"><Icon name={icon} size={14} /></span><div><strong>{entry.action.replace(/_/g, ' ')}</strong><span>{entry.resource_type.replace(/_/g, ' ')} <span className="muted">·</span> {path ? <Link className="table-link mono" to={path}>{shortId(entry.resource_id, 12)}</Link> : shortId(entry.resource_id, 12)}</span></div><time title={formatDate(entry.created_at, true)}>{relativeTime(entry.created_at)}</time></div>
}

function resourcePath(resourceType: string, resourceId: string): string | null {
  if (resourceType === 'security_event') return `/events/${resourceId}`
  if (resourceType === 'incident') return `/incidents/${resourceId}`
  if (resourceType === 'agent_task') return `/tasks/${resourceId}`
  if (resourceType === 'finding') return `/findings/${resourceId}`
  return null
}

interface EventFilters {
  severity: string
  event_type: string
  source_address: string
  destination_address: string
  from_time: string
  to_time: string
}

const emptyEventFilters: EventFilters = { severity: '', event_type: '', source_address: '', destination_address: '', from_time: '', to_time: '' }

export function EventsPage() {
  const [draft, setDraft] = useState<EventFilters>(emptyEventFilters)
  const [filters, setFilters] = useState<EventFilters>(emptyEventFilters)
  const [page, setPage] = useState(1)
  const key = JSON.stringify({ ...filters, page })
  const query = useApi((signal) => eventsApi.list({
    severity: filters.severity || undefined,
    event_type: filters.event_type || undefined,
    source_address: filters.source_address || undefined,
    destination_address: filters.destination_address || undefined,
    from_time: toIsoDateTime(filters.from_time),
    to_time: toIsoDateTime(filters.to_time),
    page,
    page_size: 20,
  }, signal), key)

  const applyFilters = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    setPage(1)
    setFilters(draft)
  }

  const resetFilters = () => {
    setDraft(emptyEventFilters)
    setFilters(emptyEventFilters)
    setPage(1)
  }

  return <div className="page-stack"><PageHeader eyebrow="DETECTION" title="Events" description="Explore SecurityEvents emitted by the C++ IDS and persisted by the control plane." actions={<Button variant="secondary" size="sm" icon="refresh" onClick={query.refresh}>Refresh</Button>} />
    <Card className="filter-card"><form className="filter-form" onSubmit={applyFilters}><div className="filter-field"><label htmlFor="event-severity">Severity</label><select id="event-severity" value={draft.severity} onChange={(event) => setDraft((current) => ({ ...current, severity: event.target.value }))}><option value="">All severities</option>{['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((severity) => <option value={severity} key={severity}>{severity}</option>)}</select></div><div className="filter-field"><label htmlFor="event-type">Event type</label><input id="event-type" value={draft.event_type} onChange={(event) => setDraft((current) => ({ ...current, event_type: event.target.value }))} placeholder="PORT_SCAN" /></div><div className="filter-field"><label htmlFor="event-source">Source IP</label><input id="event-source" value={draft.source_address} onChange={(event) => setDraft((current) => ({ ...current, source_address: event.target.value }))} placeholder="10.0.0.10" /></div><div className="filter-field"><label htmlFor="event-destination">Destination IP</label><input id="event-destination" value={draft.destination_address} onChange={(event) => setDraft((current) => ({ ...current, destination_address: event.target.value }))} placeholder="10.0.0.20" /></div><div className="filter-field"><label htmlFor="event-from">From</label><input id="event-from" type="datetime-local" value={draft.from_time} onChange={(event) => setDraft((current) => ({ ...current, from_time: event.target.value }))} /></div><div className="filter-field"><label htmlFor="event-to">To</label><input id="event-to" type="datetime-local" value={draft.to_time} onChange={(event) => setDraft((current) => ({ ...current, to_time: event.target.value }))} /></div><div className="filter-actions"><Button type="submit" icon="filter">Apply filters</Button><Button type="button" variant="ghost" onClick={resetFilters}>Reset</Button></div></form></Card>
     {query.loading && !query.data ? <Card className="panel"><LoadingRows columns={6} /></Card> : query.error && !query.data ? <ErrorState message={safeError(query.error)} onRetry={query.refresh} /> : query.data && query.data.items.length === 0 ? <Card className="panel"><EmptyState icon="network" title="No security events found" description="Adjust the filters or run the Intriqo IDS demo to generate a SecurityEvent." /></Card> : query.data ? <Card className="panel"><SectionHeading title="Security event explorer" description={`${query.data.total.toLocaleString()} persisted events`} /><TableFrame><table className="data-table"><thead><tr><th>Severity</th><th>Provenance</th><th>Source</th><th>Destination</th><th>Detected</th><th>Relationships</th></tr></thead><tbody>{query.data.items.map((event) => { const relationships = eventRelationshipIds(event); return <tr key={event.event_id}><td><SeverityBadge severity={event.severity} /></td><td><Link className="table-link" to={`/events/${event.event_id}`} title={event.event_type}><EventProvenance event={event} /><small className="table-subtext">{shortId(event.event_id, 14)}</small></Link></td><td className="mono">{event.source_address}</td><td className="mono">{event.destination_address}</td><td title={formatDate(event.timestamp, true)}>{formatDate(event.timestamp)}</td><td><span className="table-counts">{relationships.incidentIds.length} incident · {relationships.taskIds.length} task · {relationships.findingIds.length} finding</span></td></tr> })}</tbody></table></TableFrame><Pagination page={query.data.page} hasNext={query.data.has_next} total={query.data.total} pageSize={query.data.page_size} onPageChange={setPage} /></Card> : null}
  </div>
}

export function EventDetailPage() {
  const { eventId = '' } = useParams()
  const query = useApi(async (signal) => {
    const event = await eventsApi.get(eventId, signal)
    const relationships = eventRelationshipIds(event)
    let incidentIds = relationships.incidentIds
    let taskIds = relationships.taskIds
    let findingIds = relationships.findingIds
    if (event.linked_incident_ids === undefined) {
      try {
        const incidents = await incidentsApi.list({ page: 1, page_size: 100 }, signal)
        incidentIds = incidents.items.filter((incident) => incident.linked_event_ids.includes(event.event_id)).map((incident) => incident.incident_id)
      } catch {
        // Relationship reads are supplementary; the event remains useful without them.
      }
    }
    let relatedTasks: AgentTask[] = []
    if (event.linked_task_ids === undefined) {
      try {
        relatedTasks = (await tasksApi.list({ event_id: event.event_id, page: 1, page_size: 100 }, signal)).items
        taskIds = relatedTasks.map((task) => task.task_id)
      } catch {
        // Keep the relationship section readable when an older API cannot read tasks.
      }
    }
    let relatedFindings: Finding[] = []
    if (event.linked_finding_ids === undefined && relatedTasks.length > 0) {
      const responses = await Promise.all(relatedTasks.map((task) => findingsApi.list({ task_id: task.task_id, page: 1, page_size: 100 }, signal).catch(() => null)))
      relatedFindings = responses.flatMap((response) => response?.items || [])
      findingIds = relatedFindings.map((finding) => finding.finding_id)
    }
    const [relatedIncidents, directTasks, directFindings] = await Promise.all([
      Promise.all(incidentIds.map((id) => incidentsApi.get(id, signal).catch(() => null))).then((items) => items.filter((item): item is Incident => item !== null)),
      Promise.all(taskIds.map((id) => tasksApi.get(id, signal).catch(() => null))).then((items) => items.filter((item): item is AgentTask => item !== null)),
      Promise.all(findingIds.map((id) => findingsApi.get(id, signal).catch(() => null))).then((items) => items.filter((item): item is Finding => item !== null)),
    ])
    return { event, relatedIncidents, relatedTasks: relatedTasks.length > 0 ? relatedTasks : directTasks, relatedFindings: relatedFindings.length > 0 ? relatedFindings : directFindings }
  }, eventId)

  if (query.loading && !query.data) return <div className="page-stack"><BackLink to="/events" label="Events" /><PageHeader eyebrow="SECURITY EVENT" title="Loading event…" /><LoadingRows columns={2} rows={5} /></div>
  if (query.error && !query.data) return <div className="page-stack"><BackLink to="/events" label="Events" /><ErrorState message={safeError(query.error)} onRetry={query.refresh} /></div>
  if (!query.data) return null
  const { event, relatedIncidents, relatedTasks, relatedFindings } = query.data
  return <div className="page-stack"><BackLink to="/events" label="Events" /><PageHeader eyebrow="SECURITY EVENT" title={event.event_type} description={event.description || 'No description was provided by the detector.'} actions={<StatusBadge status="INGESTED" />} />
     <div className="detail-grid"><Card className="panel"><SectionHeading title="Event metadata" action={<AuditLink resourceId={event.event_id} />} /><dl className="key-value-grid"><KeyValue label="Event ID" value={event.event_id} mono /><KeyValue label="Event type" value={<Badge tone="info">{event.event_type}</Badge>} /><KeyValue label="Severity" value={<SeverityBadge severity={event.severity} />} /><KeyValue label="Detection source" value={eventDetectionSource(event) || <span className="muted">Not supplied</span>} /><KeyValue label="Detector" value={eventDetector(event) || <span className="muted">Not supplied</span>} /><KeyValue label="Detected" value={formatDate(event.timestamp, true)} /><KeyValue label="Ingested" value={formatDate(event.ingested_at, true)} /><KeyValue label="Source" value={event.source_address} mono /><KeyValue label="Destination" value={event.destination_address} mono /></dl></Card><Card className="panel"><SectionHeading title="Detection details" description="Detector-specific evidence from the SecurityEvent contract." />{Object.keys(event.details || {}).length === 0 ? <EmptyState icon="info" title="No additional details" description="This event did not include detector-specific metadata." /> : <dl className="detail-properties">{Object.entries(event.details || {}).map(([key, value]) => <KeyValue key={key} label={key.replace(/_/g, ' ')} value={asString(value) || prettyJson(value)} mono={typeof value !== 'string'} />)}</dl>}</Card></div>
     <Card className="panel"><SectionHeading title="Related incidents" description={`${relatedIncidents.length} linked incident${relatedIncidents.length === 1 ? '' : 's'} returned by the control plane.`} />{relatedIncidents.length === 0 ? <EmptyState icon="alert" title="No linked incident" description="This event is not linked to an incident yet." /> : <div className="compact-list">{relatedIncidents.map((incident) => <Link className="compact-list-row" to={`/incidents/${incident.incident_id}`} key={incident.incident_id}><span><strong>{incident.title}</strong><small>{shortId(incident.incident_id, 14)} · {incident.linked_event_ids.length} events · {(incident.linked_task_ids || []).length} tasks · updated {relativeTime(incident.updated_at)}</small></span><span><SeverityBadge severity={incident.severity} /><StatusBadge status={incident.status} /></span></Link>)}</div>}</Card>
     <div className="dashboard-grid"><Card className="panel"><SectionHeading title="Investigation tasks" description={`${relatedTasks.length} task${relatedTasks.length === 1 ? '' : 's'} linked to this event.`} />{relatedTasks.length === 0 ? <EmptyState icon="bot" title="No linked task" description="No investigation task is linked to this event yet." /> : <div className="compact-list">{relatedTasks.map((task) => <Link className="compact-list-row" to={`/tasks/${task.task_id}`} key={task.task_id}><span><strong>{truncate(task.description, 48)}</strong><small>{task.task_type} · {formatDate(task.created_at)} · {taskFindingIds(task).length} findings</small></span><StatusBadge status={task.status} /></Link>)}</div>}</Card><Card className="panel"><SectionHeading title="Findings" description={`${relatedFindings.length} finding${relatedFindings.length === 1 ? '' : 's'} linked to this event.`} />{relatedFindings.length === 0 ? <EmptyState icon="check" title="No linked finding" description="Findings will appear here after an investigation task submits a result." /> : <div className="compact-list">{relatedFindings.map((finding) => <Link className="compact-list-row" to={`/findings/${finding.finding_id}`} key={finding.finding_id}><span><strong>{truncate(finding.summary || finding.findings[0] || 'Untitled finding', 44)}</strong><small>{finding.agent_name} · {formatDate(finding.created_at)}</small><FindingProvenance finding={finding} /></span><StatusBadge status={finding.status} /></Link>)}</div>}</Card></div>
     <Card className="panel raw-json"><details><summary><span><Icon name="code" size={16} /> Raw JSON</span><span className="muted">Expand to inspect the API payload</span></summary><pre>{prettyJson(event)}</pre></details></Card>
  </div>
}

function BackLink({ to, label }: { to: string; label: string }) {
  return <Link className="back-link" to={to}><Icon name="chevron-left" size={15} /> {label}</Link>
}

interface IncidentFilters {
  status: string
  severity: string
}

const emptyIncidentFilters: IncidentFilters = { status: '', severity: '' }

export function IncidentsPage() {
  const [draft, setDraft] = useState<IncidentFilters>(emptyIncidentFilters)
  const [filters, setFilters] = useState<IncidentFilters>(emptyIncidentFilters)
  const [page, setPage] = useState(1)
  const key = JSON.stringify({ ...filters, page })
  const query = useApi((signal) => incidentsApi.list({
    status: filters.status || undefined,
    severity: filters.severity || undefined,
    page,
    page_size: 20,
  }, signal), key)

  const applyFilters = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    setPage(1)
    setFilters(draft)
  }
  const resetFilters = () => {
    setDraft(emptyIncidentFilters)
    setFilters(emptyIncidentFilters)
    setPage(1)
  }

  return <div className="page-stack"><PageHeader eyebrow="INVESTIGATION" title="Incidents" description="The central record for grouping events, tasks, findings, and operator decisions." actions={<Button variant="secondary" size="sm" icon="refresh" onClick={query.refresh}>Refresh</Button>} />
    <Card className="filter-card"><form className="filter-form filter-form-short" onSubmit={applyFilters}><div className="filter-field"><label htmlFor="incident-status">Status</label><select id="incident-status" value={draft.status} onChange={(event) => setDraft((current) => ({ ...current, status: event.target.value }))}><option value="">All statuses</option>{['OPEN', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'CLOSED', 'FALSE_POSITIVE'].map((status) => <option value={status} key={status}>{status.replace(/_/g, ' ')}</option>)}</select></div><div className="filter-field"><label htmlFor="incident-severity">Severity</label><select id="incident-severity" value={draft.severity} onChange={(event) => setDraft((current) => ({ ...current, severity: event.target.value }))}><option value="">All severities</option>{['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((severity) => <option value={severity} key={severity}>{severity}</option>)}</select></div><div className="filter-actions"><Button type="submit" icon="filter">Apply filters</Button><Button type="button" variant="ghost" onClick={resetFilters}>Reset</Button></div></form></Card>
    {query.loading && !query.data ? <Card className="panel"><LoadingRows columns={7} /></Card> : query.error && !query.data ? <ErrorState message={safeError(query.error)} onRetry={query.refresh} /> : query.data && query.data.items.length === 0 ? <Card className="panel"><EmptyState icon="alert" title="No incidents found" description="Incidents will appear here when the control plane groups a security event for investigation." /></Card> : query.data ? <Card className="panel"><SectionHeading title="Incident queue" description={`${query.data.total.toLocaleString()} persisted incidents`} /><TableFrame><table className="data-table"><thead><tr><th>Incident</th><th>Sources</th><th>Severity</th><th>Status</th><th>Events</th><th>Findings</th><th>Created / updated</th></tr></thead><tbody>{query.data.items.map((incident) => <tr key={incident.incident_id}><td><Link className="table-link" to={`/incidents/${incident.incident_id}`} title={incident.title}>{truncate(incident.title, 44)}</Link><small className="table-subtext">{shortId(incident.incident_id, 14)}</small></td><td><span className="table-counts">{(incident.detection_sources || []).join(' · ') || '—'}</span></td><td><SeverityBadge severity={incident.severity} /></td><td><StatusBadge status={incident.status} /></td><td>{incident.event_count ?? incident.linked_event_ids.length}</td><td>{incident.finding_count ?? incident.linked_finding_ids?.length ?? 0}</td><td><span>{formatDate(incident.created_at)}</span><small className="table-subtext">{formatDate(incident.updated_at)}</small></td></tr>)}</tbody></table></TableFrame><Pagination page={query.data.page} hasNext={query.data.has_next} total={query.data.total} pageSize={query.data.page_size} onPageChange={setPage} /></Card> : null}
  </div>
}

interface IncidentDetailSnapshot {
  incident: Incident
  events: SecurityEvent[]
  tasks: AgentTask[]
  findings: Finding[]
  audit: AuditLog[]
}

export function IncidentDetailPage() {
  const { incidentId = '' } = useParams()
  const query = useApi<IncidentDetailSnapshot>(async (signal) => {
    const incident = await incidentsApi.get(incidentId, signal)
    const eventIds = incident.linked_event_ids || []
    const relationships = incidentRelationshipIds(incident)
    let taskIds = relationships.taskIds
    let findingIds = relationships.findingIds
    let tasks: AgentTask[] = []
    if (incident.linked_task_ids === undefined) {
      try {
        tasks = (await tasksApi.list({ incident_id: incidentId, page: 1, page_size: 100 }, signal)).items
        taskIds = tasks.map((task) => task.task_id)
      } catch {
        // Keep the incident summary readable if related task reads are unavailable.
      }
    }
    const [events, directTasks] = await Promise.all([
      Promise.all(eventIds.map((id) => eventsApi.get(id, signal).catch(() => null))).then((items) => items.filter((event): event is SecurityEvent => event !== null)),
      Promise.all(taskIds.map((id) => tasksApi.get(id, signal).catch(() => null))).then((items) => items.filter((task): task is AgentTask => task !== null)),
    ])
    tasks = tasks.length > 0 ? tasks : directTasks
    if (incident.linked_finding_ids === undefined && findingIds.length === 0) {
      const findingResponses = await Promise.all(tasks.map((task) => findingsApi.list({ task_id: task.task_id, page: 1, page_size: 100 }, signal).catch(() => null)))
      findingIds = findingResponses.flatMap((response) => response?.items || []).map((finding) => finding.finding_id)
    }
    const findings = (await Promise.all(findingIds.map((id) => findingsApi.get(id, signal).catch(() => null)))).filter((finding): finding is Finding => finding !== null)
    let audit: AuditLog[] = []
    try {
      audit = (await auditApi.list({ resource_id: incidentId, page: 1, page_size: 50 }, signal)).items
    } catch {
      // The incident remains readable if an older control plane does not expose audit reads.
    }
    return { incident, events, tasks, findings, audit }
  }, incidentId)

  if (query.loading && !query.data) return <div className="page-stack"><BackLink to="/incidents" label="Incidents" /><PageHeader eyebrow="INCIDENT" title="Loading incident…" /><LoadingRows columns={3} rows={6} /></div>
  if (query.error && !query.data) return <div className="page-stack"><BackLink to="/incidents" label="Incidents" /><ErrorState message={safeError(query.error)} onRetry={query.refresh} /></div>
  if (!query.data) return null
  const { incident, events, tasks, findings, audit } = query.data
  return <div className="page-stack"><BackLink to="/incidents" label="Incidents" /><PageHeader eyebrow={`INCIDENT / ${shortId(incident.incident_id, 14)}`} title={incident.title} description={incident.description || 'No description was provided for this incident.'} actions={<span className="header-badges"><SeverityBadge severity={incident.severity} /><StatusBadge status={incident.status} /></span>} />
     <div className="detail-grid"><Card className="panel"><SectionHeading title="Incident summary" action={<AuditLink resourceId={incident.incident_id} />} /><dl className="key-value-grid"><KeyValue label="Incident ID" value={incident.incident_id} mono /><KeyValue label="Detection sources" value={(incident.detection_sources || []).join(' · ') || 'Not supplied'} /><KeyValue label="Containment / resolution" value={<StatusBadge status={incident.status} />} /><KeyValue label="Severity" value={<SeverityBadge severity={incident.severity} />} /><KeyValue label="Created" value={formatDate(incident.created_at, true)} /><KeyValue label="Updated" value={formatDate(incident.updated_at, true)} /><KeyValue label="Resolved" value={formatDate(incident.resolved_at, true)} />{incident.correlation_key && <KeyValue label="Correlation key" value={incident.correlation_key} mono />}{incident.correlation_window_seconds !== null && incident.correlation_window_seconds !== undefined && <KeyValue label="Correlation window" value={`${incident.correlation_window_seconds}s`} />}</dl></Card><Card className="panel"><SectionHeading title="Workflow state" description="Investigation completion is tracked separately from containment and resolution." /><InvestigationState tasks={tasks} /><div className="workflow-counts"><WorkflowCount label="Events" value={events.length} icon="network" /><WorkflowCount label="Agent tasks" value={tasks.length} icon="bot" /><WorkflowCount label="Findings" value={findings.length} icon="check" /><WorkflowCount label="Audit records" value={audit.length} icon="list" /></div></Card></div>
     <Card className="panel"><SectionHeading title="Related events" description={`${events.length} SecurityEvent${events.length === 1 ? '' : 's'} linked to this incident.`} />{events.length === 0 ? <EmptyState icon="network" title="No related events" description="The incident has no readable linked SecurityEvents." /> : <TableFrame><table className="data-table"><thead><tr><th>Severity</th><th>Provenance</th><th>Source → destination</th><th>Detected</th><th>Links</th></tr></thead><tbody>{events.map((event) => { const relationships = eventRelationshipIds(event); return <tr key={event.event_id}><td><SeverityBadge severity={event.severity} /></td><td><Link className="table-link" to={`/events/${event.event_id}`}><EventProvenance event={event} /></Link></td><td className="mono">{event.source_address} <span className="muted">→</span> {event.destination_address}</td><td>{formatDate(event.timestamp)}</td><td><span className="table-counts">{relationships.taskIds.length} task · {relationships.findingIds.length} finding</span></td></tr> })}</tbody></table></TableFrame>}</Card>
     <div className="dashboard-grid"><Card className="panel"><SectionHeading title="Agent tasks" description={`${tasks.length} investigation task${tasks.length === 1 ? '' : 's'} linked to this incident.`} />{tasks.length === 0 ? <EmptyState icon="bot" title="No agent tasks" description="No task is linked to this incident yet." /> : <div className="compact-list">{tasks.map((task) => <Link className="compact-list-row" to={`/tasks/${task.task_id}`} key={task.task_id}><span><strong>{truncate(task.description, 46)}</strong><small>{task.task_type} · {shortId(task.task_id, 14)} · created {formatDate(task.created_at)} · {taskFindingIds(task).length} findings</small></span><StatusBadge status={task.status} /></Link>)}</div>}</Card><Card className="panel"><SectionHeading title="Findings" description={`${findings.length} result${findings.length === 1 ? '' : 's'} submitted by the investigation workflow.`} />{findings.length === 0 ? <EmptyState icon="check" title="No findings" description="A completed investigation task will attach findings here." /> : <div className="compact-list">{findings.map((finding) => <Link className="compact-list-row" to={`/findings/${finding.finding_id}`} key={finding.finding_id}><span><strong>{truncate(finding.summary || finding.findings[0] || 'Untitled finding', 46)}</strong><small>{finding.agent_name} · {Math.round(finding.confidence * 100)}% confidence · {formatDate(finding.created_at)}</small><FindingProvenance finding={finding} /></span><span><SeverityBadge severity={findingSeverity(finding)} /><StatusBadge status={finding.status} /></span></Link>)}</div>}</Card></div>
     <Card className="panel"><SectionHeading title="Incident timeline" description="Audit entries whose resource is this incident." action={<AuditLink resourceId={incident.incident_id} />} />{audit.length === 0 ? <EmptyState icon="clock" title="No incident audit entries" description="The control plane has not returned audit records for this incident." /> : <div className="timeline">{audit.map((entry) => <TimelineEntry entry={entry} key={entry.id} />)}</div>}</Card>
  </div>
}

function WorkflowCount({ label, value, icon }: { label: string; value: number; icon: 'network' | 'bot' | 'check' | 'list' }) {
  return <div className="workflow-count"><span className="workflow-count-icon"><Icon name={icon} size={16} /></span><strong>{value}</strong><span>{label}</span></div>
}

export function AgentsPage() {
  const query = useApi((signal) => tasksApi.list({ task_type: 'INVESTIGATION', page: 1, page_size: 30 }, signal), 'investigation-agent')
  return <div className="page-stack"><PageHeader eyebrow="AUTOMATION" title="Agents" description="Inspect the agent capabilities that are backed by the current control-plane workflow." actions={<Button variant="secondary" size="sm" icon="refresh" onClick={query.refresh}>Refresh</Button>} />
    <div className="agent-hero"><div className="agent-hero-icon"><Icon name="bot" size={24} /></div><div><div className="agent-title-row"><h2>Investigation Agent</h2><Badge tone="success"><span className="status-pulse" /> IMPLEMENTED</Badge></div><p>Deterministic investigation workflow for turning an AgentTask into a structured Finding.</p><div className="agent-tags"><span>Evidence synthesis</span><span>Port-scan analysis</span><span>Finding submission</span></div></div></div>
    <div className="agent-capability-grid"><AgentCapability title="Investigation" status="IMPLEMENTED" icon="bot" copy="Reads the task context, analyzes the event, and submits a structured result." /><AgentCapability title="Correlation" status="COMING LATER" icon="layers" copy="The architecture leaves room for multi-event incident reconstruction." /><AgentCapability title="Threat intelligence" status="COMING LATER" icon="search" copy="External reputation and enrichment are not operational in this phase." /><AgentCapability title="Response" status="COMING LATER" icon="shield" copy="Policy-controlled actions remain a future surface; no autonomous response is claimed." /></div>
     <Card className="panel"><SectionHeading title="Recent investigation tasks" description="Tasks returned by GET /api/v1/agent-tasks?task_type=INVESTIGATION." />{query.loading && !query.data ? <LoadingRows columns={5} /> : query.error && !query.data ? <ErrorState message={safeError(query.error)} onRetry={query.refresh} /> : query.data && query.data.items.length === 0 ? <EmptyState icon="bot" title="No investigation tasks" description="Tasks will appear here after the control plane queues an investigation." /> : query.data ? <TableFrame><table className="data-table"><thead><tr><th>Task</th><th>Priority</th><th>Status</th><th>Relationships</th><th>Incident</th><th>Created</th><th>Completed</th></tr></thead><tbody>{query.data.items.map((task) => <tr key={task.task_id}><td><Link className="table-link" to={`/tasks/${task.task_id}`}><strong>{truncate(task.description, 48)}</strong><small className="table-subtext mono">{shortId(task.task_id, 14)}</small></Link></td><td><Badge tone={task.priority.toLowerCase()}>{task.priority}</Badge></td><td><StatusBadge status={task.status} /></td><td><span className="table-counts">{task.event_id ? 'event' : '—'} · {taskFindingIds(task).length} finding</span></td><td>{task.incident_id ? <Link className="table-link mono" to={`/incidents/${task.incident_id}`}>{shortId(task.incident_id, 12)}</Link> : <span className="muted">—</span>}</td><td>{formatDate(task.created_at)}</td><td>{formatDate(task.completed_at)}</td></tr>)}</tbody></table></TableFrame> : null}</Card>
  </div>
}

function AgentCapability({ title, status, icon, copy }: { title: string; status: 'IMPLEMENTED' | 'COMING LATER'; icon: 'bot' | 'layers' | 'search' | 'shield'; copy: string }) {
  return <article className={`agent-capability ${status === 'COMING LATER' ? 'agent-capability-future' : ''}`}><div className="agent-capability-top"><span className="capability-icon"><Icon name={icon} size={18} /></span><Badge tone={status === 'IMPLEMENTED' ? 'success' : 'neutral'}>{status}</Badge></div><h3>{title}</h3><p>{copy}</p></article>
}

interface FindingFilters {
  status: string
  agent_name: string
}

const emptyFindingFilters: FindingFilters = { status: '', agent_name: '' }

export function FindingsPage() {
  const [draft, setDraft] = useState<FindingFilters>(emptyFindingFilters)
  const [filters, setFilters] = useState<FindingFilters>(emptyFindingFilters)
  const [page, setPage] = useState(1)
  const key = JSON.stringify({ ...filters, page })
  const query = useApi((signal) => findingsApi.list({ status: filters.status || undefined, agent_name: filters.agent_name || undefined, page, page_size: 20 }, signal), key)
  const applyFilters = (event: FormEvent<HTMLFormElement>) => { event.preventDefault(); setPage(1); setFilters(draft) }
  const resetFilters = () => { setDraft(emptyFindingFilters); setFilters(emptyFindingFilters); setPage(1) }
  return <div className="page-stack"><PageHeader eyebrow="INVESTIGATION OUTPUT" title="Findings" description="Structured results submitted by agents, with evidence and confidence kept close to the task." actions={<Button variant="secondary" size="sm" icon="refresh" onClick={query.refresh}>Refresh</Button>} />
    <Card className="filter-card"><form className="filter-form filter-form-short" onSubmit={applyFilters}><div className="filter-field"><label htmlFor="finding-status">Status</label><select id="finding-status" value={draft.status} onChange={(event) => setDraft((current) => ({ ...current, status: event.target.value }))}><option value="">All statuses</option>{['SUCCESS', 'INCONCLUSIVE', 'FAILED'].map((status) => <option value={status} key={status}>{status}</option>)}</select></div><div className="filter-field"><label htmlFor="finding-agent">Agent</label><input id="finding-agent" value={draft.agent_name} onChange={(event) => setDraft((current) => ({ ...current, agent_name: event.target.value }))} placeholder="investigation_agent" /></div><div className="filter-actions"><Button type="submit" icon="filter">Apply filters</Button><Button type="button" variant="ghost" onClick={resetFilters}>Reset</Button></div></form></Card>
     {query.loading && !query.data ? <Card className="panel"><LoadingRows columns={7} /></Card> : query.error && !query.data ? <ErrorState message={safeError(query.error)} onRetry={query.refresh} /> : query.data && query.data.items.length === 0 ? <Card className="panel"><EmptyState icon="bot" title="No findings found" description="Completed investigations will appear here when an agent submits a result." /></Card> : query.data ? <Card className="panel"><SectionHeading title="Agent findings" description={`${query.data.total.toLocaleString()} persisted findings`} /><TableFrame><table className="data-table"><thead><tr><th>Finding</th><th>Provenance</th><th>Severity</th><th>Task</th><th>Created</th><th>Status</th></tr></thead><tbody>{query.data.items.map((finding) => { const severity = findingSeverity(finding); return <tr key={finding.finding_id}><td><Link className="table-link" to={`/findings/${finding.finding_id}`}>{truncate(finding.summary || finding.findings[0] || 'Untitled finding', 45)}</Link><small className="table-subtext mono">{shortId(finding.finding_id, 14)}</small></td><td><FindingProvenance finding={finding} /></td><td>{severity ? <SeverityBadge severity={severity} /> : <span className="muted" title="Severity is not part of the current Finding contract">—</span>}</td><td><Link className="table-link mono" to={`/tasks/${finding.task_id}`}>{shortId(finding.task_id, 12)}</Link></td><td>{formatDate(finding.created_at)}</td><td><StatusBadge status={finding.status} /></td></tr> })}</tbody></table></TableFrame><Pagination page={query.data.page} hasNext={query.data.has_next} total={query.data.total} pageSize={query.data.page_size} onPageChange={setPage} /></Card> : null}
  </div>
}

interface FindingDetailSnapshot {
  finding: Finding
  task: AgentTask
  incident: Incident | null
  event: SecurityEvent | null
  audit: AuditLog[]
}

export function FindingDetailPage() {
  const { findingId = '' } = useParams()
  const query = useApi<FindingDetailSnapshot>(async (signal) => {
    const finding = await findingsApi.get(findingId, signal)
    const task = await tasksApi.get(finding.task_id, signal)
    const incidentId = finding.incident_id ?? task.incident_id
    const eventId = finding.event_id ?? task.event_id
    const [incident, event] = await Promise.all([
      incidentId ? incidentsApi.get(incidentId, signal).catch(() => null) : Promise.resolve(null),
      eventId ? eventsApi.get(eventId, signal).catch(() => null) : Promise.resolve(null),
    ])
    let audit: AuditLog[] = []
    try {
      audit = (await auditApi.list({ resource_id: findingId, page: 1, page_size: 50 }, signal)).items
    } catch {
      // The finding remains readable if an older control plane does not expose audit reads.
    }
    return { finding, task, incident, event, audit }
  }, findingId)

  if (query.loading && !query.data) return <div className="page-stack"><BackLink to="/findings" label="Findings" /><PageHeader eyebrow="FINDING" title="Loading finding…" /><LoadingRows columns={2} rows={5} /></div>
  if (query.error && !query.data) return <div className="page-stack"><BackLink to="/findings" label="Findings" /><ErrorState message={safeError(query.error)} onRetry={query.refresh} /></div>
  if (!query.data) return null
  const { finding, task, incident, event, audit } = query.data
  const metadata = finding.finding_metadata || {}
  const recommendation = metadata.recommendation ?? metadata.recommendations
  const provenanceEventType = findingEventType(finding) || event?.event_type
  const provenanceSource = findingDetectionSource(finding) || (event ? eventDetectionSource(event) : null)
  const provenanceDetector = findingDetector(finding) || (event ? eventDetector(event) : null)
  return <div className="page-stack"><BackLink to="/findings" label="Findings" /><PageHeader eyebrow={`FINDING / ${shortId(finding.finding_id, 14)}`} title={finding.summary || finding.findings[0] || 'Investigation finding'} description={`Submitted by ${finding.agent_name} on ${formatDateOnly(finding.created_at)}.`} actions={<span className="header-badges"><SeverityBadge severity={findingSeverity(finding)} /><StatusBadge status={finding.status} /></span>} />
     <div className="detail-grid"><Card className="panel"><SectionHeading title="Finding summary" action={<AuditLink resourceId={finding.finding_id} />} /><dl className="key-value-grid"><KeyValue label="Finding ID" value={finding.finding_id} mono /><KeyValue label="Agent" value={finding.agent_name} mono /><KeyValue label="Task" value={<Link className="table-link mono" to={`/tasks/${finding.task_id}`}>{shortId(finding.task_id, 16)}</Link>} /><KeyValue label="Confidence" value={`${Math.round(finding.confidence * 100)}%`} /><KeyValue label="Created" value={formatDate(finding.created_at, true)} /><KeyValue label="Severity" value={findingSeverity(finding) ? <SeverityBadge severity={findingSeverity(finding)} /> : <span className="muted">Not supplied</span>} /><KeyValue label="Detection source" value={provenanceSource || <span className="muted">Not supplied</span>} /><KeyValue label="Event type" value={provenanceEventType || <span className="muted">Not supplied</span>} /><KeyValue label="Detector" value={provenanceDetector || <span className="muted">Not supplied</span>} /></dl></Card><Card className="panel"><SectionHeading title="Provenance" description="The finding receipt preserves the detector and workflow context returned by the API." /><FindingProvenance finding={finding} event={event} />{finding.provenance && Object.keys(finding.provenance).length > 0 ? <pre className="json-block">{prettyJson(finding.provenance)}</pre> : <EmptyState icon="info" title="No provenance receipt" description="This finding response does not include provenance metadata." />}</Card></div>
     <Card className="panel"><SectionHeading title="Recommendation" description="Read from finding metadata when supplied by the agent." />{recommendation ? <p className="detail-copy">{typeof recommendation === 'string' ? recommendation : prettyJson(recommendation)}</p> : <EmptyState icon="info" title="No recommendation provided" description="This finding does not include a recommendation in finding_metadata." />}</Card>
     <Card className="panel"><SectionHeading title="Findings" description="Agent-generated observations." />{finding.findings.length === 0 ? <EmptyState icon="info" title="No observations" description="The agent submitted no finding strings." /> : <ul className="finding-list">{finding.findings.map((item, index) => <li key={`${item}-${index}`}><span className="finding-bullet"><Icon name="check" size={13} /></span><span>{item}</span></li>)}</ul>}</Card>
     <div className="dashboard-grid"><Card className="panel"><SectionHeading title="Evidence" description="Structured evidence objects submitted with the result." />{finding.evidence.length === 0 ? <EmptyState icon="database" title="No evidence attached" description="The finding contains no evidence objects." /> : <div className="evidence-list">{finding.evidence.map((item, index) => <details className="evidence-item" key={index}><summary>Evidence {String(index + 1).padStart(2, '0')}</summary><pre>{prettyJson(item)}</pre></details>)}</div>}</Card><Card className="panel"><SectionHeading title="Related resources" /><div className="related-resource-list"><Link className="related-resource" to={`/tasks/${task.task_id}`}><span className="resource-icon"><Icon name="bot" size={16} /></span><span><strong>{task.description}</strong><small>AgentTask · {shortId(task.task_id, 14)} · {task.status}</small></span><Icon name="arrow-up-right" size={15} /></Link>{incident ? <Link className="related-resource" to={`/incidents/${incident.incident_id}`}><span className="resource-icon"><Icon name="alert" size={16} /></span><span><strong>{incident.title}</strong><small>Incident · {shortId(incident.incident_id, 14)} · {incident.status}</small></span><Icon name="arrow-up-right" size={15} /></Link> : <div className="related-resource related-resource-muted"><span className="resource-icon"><Icon name="alert" size={16} /></span><span><strong>No related incident</strong><small>The task has no readable incident link.</small></span></div>}{event ? <Link className="related-resource" to={`/events/${event.event_id}`}><span className="resource-icon"><Icon name="network" size={16} /></span><span><strong>{event.event_type}</strong><small>SecurityEvent · {shortId(event.event_id, 14)} · {formatDate(event.timestamp)}</small></span><Icon name="arrow-up-right" size={15} /></Link> : <div className="related-resource related-resource-muted"><span className="resource-icon"><Icon name="network" size={16} /></span><span><strong>No related event</strong><small>The task has no readable event link.</small></span></div>}<Link className="related-resource" to={`/audit?resource_id=${encodeURIComponent(finding.finding_id)}`}><span className="resource-icon"><Icon name="list" size={16} /></span><span><strong>Audit trail</strong><small>{audit.length} record{audit.length === 1 ? '' : 's'} for this finding</small></span><Icon name="arrow-up-right" size={15} /></Link></div></Card></div>
     <Card className="panel"><SectionHeading title="Finding audit timeline" description="Append-only records for this finding." action={<AuditLink resourceId={finding.finding_id} />} />{audit.length === 0 ? <EmptyState icon="clock" title="No finding audit entries" description="The control plane has not returned audit records for this finding." /> : <div className="timeline">{audit.map((entry) => <TimelineEntry entry={entry} key={entry.id} />)}</div>}</Card>
     {finding.error && <Card className="panel"><SectionHeading title="Agent error" /><pre className="json-block">{prettyJson(finding.error)}</pre></Card>}
  </div>
}

interface TaskDetailSnapshot {
  task: AgentTask
  event: SecurityEvent | null
  incident: Incident | null
  findings: Finding[]
  audit: AuditLog[]
}

export function TaskDetailPage() {
  const { taskId = '' } = useParams()
  const query = useApi<TaskDetailSnapshot>(async (signal) => {
    const task = await tasksApi.get(taskId, signal)
    let findingIds = taskFindingIds(task)
    let findings: Finding[] = []
    if (task.finding_ids === undefined) {
      try {
        findings = (await findingsApi.list({ task_id: task.task_id, page: 1, page_size: 100 }, signal)).items
        findingIds = findings.map((finding) => finding.finding_id)
      } catch {
        // Keep task metadata readable if an older API cannot read findings.
      }
    }
    const [event, incident, directFindings] = await Promise.all([
      task.event_id ? eventsApi.get(task.event_id, signal).catch(() => null) : Promise.resolve(null),
      task.incident_id ? incidentsApi.get(task.incident_id, signal).catch(() => null) : Promise.resolve(null),
      Promise.all(findingIds.map((id) => findingsApi.get(id, signal).catch(() => null))).then((items) => items.filter((item): item is Finding => item !== null)),
    ])
    findings = findings.length > 0 ? findings : directFindings
    let audit: AuditLog[] = []
    try {
      audit = (await auditApi.list({ resource_id: task.task_id, page: 1, page_size: 50 }, signal)).items
    } catch {
      // The task remains readable if an older control plane does not expose audit reads.
    }
    return { task, event, incident, findings, audit }
  }, taskId)

  if (query.loading && !query.data) return <div className="page-stack"><BackLink to="/agents" label="Agents" /><PageHeader eyebrow="AGENT TASK" title="Loading task…" /><LoadingRows columns={2} rows={5} /></div>
  if (query.error && !query.data) return <div className="page-stack"><BackLink to="/agents" label="Agents" /><ErrorState message={safeError(query.error)} onRetry={query.refresh} /></div>
  if (!query.data) return null
  const { task, event, incident, findings, audit } = query.data
  return <div className="page-stack"><BackLink to="/agents" label="Agents" /><PageHeader eyebrow={`AGENT TASK / ${shortId(task.task_id, 14)}`} title={task.description} description={`Investigation task created ${formatDate(task.created_at)}.`} actions={<span className="header-badges"><Badge tone={task.priority.toLowerCase()}>{task.priority}</Badge><StatusBadge status={task.status} /></span>} />
    <div className="detail-grid"><Card className="panel"><SectionHeading title="Task metadata" action={<AuditLink resourceId={task.task_id} />} /><dl className="key-value-grid"><KeyValue label="Task ID" value={task.task_id} mono /><KeyValue label="Task type" value={task.task_type} /><KeyValue label="Status" value={<StatusBadge status={task.status} />} /><KeyValue label="Priority" value={<Badge tone={task.priority.toLowerCase()}>{task.priority}</Badge>} /><KeyValue label="Created" value={formatDate(task.created_at, true)} /><KeyValue label="Updated" value={formatDate(task.updated_at, true)} /><KeyValue label="Completed" value={formatDate(task.completed_at, true)} /><KeyValue label="Finding count" value={findings.length} /></dl></Card><Card className="panel"><SectionHeading title="Investigation outcome" description="Task completion is separate from the linked incident’s containment or resolution state." /><InvestigationState tasks={[task]} /><div className="workflow-counts"><WorkflowCount label="Findings" value={findings.length} icon="check" /><WorkflowCount label="Audit records" value={audit.length} icon="list" /></div></Card></div>
    <div className="dashboard-grid"><Card className="panel"><SectionHeading title="Source event" />{event ? <Link className="related-resource" to={`/events/${event.event_id}`}><span className="resource-icon"><Icon name="network" size={16} /></span><span><strong>{event.event_type}</strong><small><EventProvenance event={event} /> · {formatDate(event.timestamp)}</small></span><Icon name="arrow-up-right" size={15} /></Link> : <EmptyState icon="network" title="No source event" description="This task does not have a readable event relationship." />}</Card><Card className="panel"><SectionHeading title="Incident" />{incident ? <Link className="related-resource" to={`/incidents/${incident.incident_id}`}><span className="resource-icon"><Icon name="alert" size={16} /></span><span><strong>{incident.title}</strong><small><SeverityBadge severity={incident.severity} /> · {incident.status}</small></span><Icon name="arrow-up-right" size={15} /></Link> : <EmptyState icon="alert" title="No linked incident" description="This task does not have a readable incident relationship." />}</Card></div>
    <Card className="panel"><SectionHeading title="Findings and evidence" description={`${findings.length} finding${findings.length === 1 ? '' : 's'} returned for this task.`} />{findings.length === 0 ? <EmptyState icon="check" title="No findings" description="Evidence will appear here after the investigation task submits a finding." /> : <div className="compact-list">{findings.map((finding) => <Link className="compact-list-row" to={`/findings/${finding.finding_id}`} key={finding.finding_id}><span><strong>{truncate(finding.summary || finding.findings[0] || 'Untitled finding', 55)}</strong><small>{finding.agent_name} · {finding.evidence.length} evidence item{finding.evidence.length === 1 ? '' : 's'} · {formatDate(finding.created_at)}</small><FindingProvenance finding={finding} /></span><span><SeverityBadge severity={findingSeverity(finding)} /><StatusBadge status={finding.status} /></span></Link>)}</div>}</Card>
    <Card className="panel"><SectionHeading title="Task audit timeline" description="Append-only records for this task." action={<AuditLink resourceId={task.task_id} />} />{audit.length === 0 ? <EmptyState icon="clock" title="No task audit entries" description="The control plane has not returned audit records for this task." /> : <div className="timeline">{audit.map((entry) => <TimelineEntry entry={entry} key={entry.id} />)}</div>}</Card>
  </div>
}

interface AuditFilters {
  action: string
  outcome: string
  resource_id: string
}

const emptyAuditFilters: AuditFilters = { action: '', outcome: '', resource_id: '' }

export function AuditPage() {
  const [searchParams] = useSearchParams()
  const initialResourceId = searchParams.get('resource_id') || ''
  const [draft, setDraft] = useState<AuditFilters>(() => ({ ...emptyAuditFilters, resource_id: initialResourceId }))
  const [filters, setFilters] = useState<AuditFilters>(() => ({ ...emptyAuditFilters, resource_id: initialResourceId }))
  const [page, setPage] = useState(1)
  const key = JSON.stringify({ ...filters, page })
  const query = useApi((signal) => auditApi.list({ action: filters.action || undefined, outcome: filters.outcome || undefined, resource_id: filters.resource_id || undefined, page, page_size: 25 }, signal), key)
  const applyFilters = (event: FormEvent<HTMLFormElement>) => { event.preventDefault(); setPage(1); setFilters(draft) }
  const resetFilters = () => { setDraft(emptyAuditFilters); setFilters(emptyAuditFilters); setPage(1) }
  return <div className="page-stack"><PageHeader eyebrow="GOVERNANCE" title="Audit" description="Append-only security operation history returned by the authenticated control plane." actions={<Button variant="secondary" size="sm" icon="refresh" onClick={query.refresh}>Refresh</Button>} />
     <Card className="filter-card"><form className="filter-form filter-form-short" onSubmit={applyFilters}><div className="filter-field"><label htmlFor="audit-action">Action</label><input id="audit-action" value={draft.action} onChange={(event) => setDraft((current) => ({ ...current, action: event.target.value }))} placeholder="FINDING_SUBMITTED" /></div><div className="filter-field"><label htmlFor="audit-outcome">Outcome</label><select id="audit-outcome" value={draft.outcome} onChange={(event) => setDraft((current) => ({ ...current, outcome: event.target.value }))}><option value="">All outcomes</option><option value="SUCCESS">SUCCESS</option><option value="FAILURE">FAILURE</option></select></div><div className="filter-field"><label htmlFor="audit-resource">Resource ID</label><input id="audit-resource" value={draft.resource_id} onChange={(event) => setDraft((current) => ({ ...current, resource_id: event.target.value }))} placeholder="event / incident / task / finding ID" /></div><div className="filter-actions"><Button type="submit" icon="filter">Apply filters</Button><Button type="button" variant="ghost" onClick={resetFilters}>Reset</Button></div></form></Card>
     {query.loading && !query.data ? <Card className="panel"><LoadingRows columns={6} /></Card> : query.error && !query.data ? <ErrorState message={safeError(query.error)} onRetry={query.refresh} /> : query.data && query.data.items.length === 0 ? <Card className="panel"><EmptyState icon="list" title="No audit entries" description="The control plane has not recorded activity matching these filters." /></Card> : query.data ? <Card className="panel"><SectionHeading title="Operation history" description={`${query.data.total.toLocaleString()} immutable records`} /><TableFrame><table className="data-table"><thead><tr><th>Actor</th><th>Action</th><th>Resource</th><th>Outcome</th><th>Timestamp</th><th>Detail</th></tr></thead><tbody>{query.data.items.map((entry) => { const path = resourcePath(entry.resource_type, entry.resource_id); return <tr key={entry.id}><td className="mono">{entry.actor}</td><td><strong>{entry.action}</strong><small className="table-subtext mono">{shortId(entry.id, 14)}</small></td><td><span>{entry.resource_type}</span>{path ? <Link className="table-link table-subtext mono" to={path}>{shortId(entry.resource_id, 14)}</Link> : <small className="table-subtext mono">{shortId(entry.resource_id, 14)}</small>}</td><td><StatusBadge status={entry.outcome} /></td><td title={formatDate(entry.created_at, true)}>{formatDate(entry.created_at)}</td><td>{entry.detail || <span className="muted">—</span>}{Object.keys(entry.extra).length > 0 && <details className="inline-details"><summary>Extra</summary><pre>{prettyJson(entry.extra)}</pre></details>}</td></tr> })}</tbody></table></TableFrame><Pagination page={query.data.page} hasNext={query.data.has_next} total={query.data.total} pageSize={query.data.page_size} onPageChange={setPage} /></Card> : null}
  </div>
}

export function SettingsPage() {
  const { user } = useAuth()
  return <div className="page-stack"><PageHeader eyebrow="WORKSPACE" title="Settings" description="Session and connection details for this dashboard instance." /><div className="detail-grid"><Card className="panel"><SectionHeading title="Current operator" /><dl className="key-value-grid"><KeyValue label="Username" value={user?.username || '—'} /><KeyValue label="Role" value={<Badge tone="info">{user?.role || '—'}</Badge>} /><KeyValue label="Session" value={<StatusBadge status="AUTHENTICATED" />} /><KeyValue label="Token storage" value="Session-only browser storage" /></dl></Card><Card className="panel"><SectionHeading title="Control plane" description="The dashboard reads typed, authenticated REST responses and refreshes explicitly." /><dl className="key-value-grid"><KeyValue label="API base" value={apiConfiguration.baseUrl} mono /><KeyValue label="Transport" value="Authenticated REST" /><KeyValue label="Refresh model" value="Initial fetch + explicit refresh" /><KeyValue label="API docs" value={<a className="table-link" href="/docs" target="_blank" rel="noreferrer">Open FastAPI docs <Icon name="external" size={13} /></a>} /></dl></Card></div><Card className="panel settings-note"><div className="settings-note-icon"><Icon name="info" size={20} /></div><div><strong>Security note</strong><p>JWTs are never rendered in the interface or written to project files. Sign out clears the current browser session.</p></div></Card></div>
}
