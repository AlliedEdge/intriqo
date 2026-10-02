import { useState, type FormEvent, type ReactNode } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { apiConfiguration } from '@/api/client'
import { auditApi, eventsApi, findingsApi, incidentsApi, tasksApi } from '@/api'
import { useAuth } from '@/app/providers/AuthProvider'
import { useApi } from '@/hooks/useApi'
import { findingSeverity, formatDate, formatDateOnly, prettyJson, relativeTime, shortId, toIsoDateTime, truncate } from '@/lib/format'
import type { AgentTask, AuditLog, Finding, Incident, SecurityEvent, Severity } from '@/types/api'
import {
  Badge, Button, Card, EmptyState, ErrorState, Icon, KeyValue, LoadingRows, PageHeader,
  Pagination, SectionHeading, SeverityBadge, StatusBadge, TableFrame, Logo,
} from '@/components/ui'

const GITHUB_URL = 'https://github.com/AlliedEdge/intriqo'
const DOCS_URL = `${GITHUB_URL}/tree/main/docs`
const CONTRIBUTING_URL = `${GITHUB_URL}/blob/main/CONTRIBUTING.md`

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

function ArchitectureFlow({ compact = false }: { compact?: boolean }) {
  const steps = compact
    ? ['Network traffic', 'C++ IDS', 'SecurityEvent', 'Control plane', 'Findings']
    : ['Network traffic', 'C++ IDS engine', 'SecurityEvent', 'FastAPI control plane', 'PostgreSQL', 'Agent tasks', 'Investigation agent', 'Findings / policy', 'Controlled response']

  return (
    <div className={`architecture-flow${compact ? ' architecture-flow-compact' : ''}`}>
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
        <header className="public-nav container">
        <Link to="/" aria-label="Intriqo home"><Logo /></Link>
        <nav className="public-links" aria-label="Public navigation">
          <a href="#product">Product</a>
          <a href="#architecture">Architecture</a>
          <a href={DOCS_URL} target="_blank" rel="noreferrer">Docs</a>
          <a href={GITHUB_URL} target="_blank" rel="noreferrer">GitHub</a>
        </nav>
        <div className="public-actions">
          <ExternalLink href={`${GITHUB_URL}#quick-start`} className="nav-text-link">Download</ExternalLink>
          <Link className="button button-secondary button-sm" to="/login">Sign in</Link>
        </div>
      </header>

      <main>
        <section className="hero-section container">
          <div className="hero-copy">
            <p className="eyebrow"><span className="status-pulse" />OPEN-SOURCE SECURITY OPERATIONS</p>
            <h1>Understand every signal before it becomes an incident.</h1>
            <p className="hero-lede">Intriqo connects a high-performance C++ network IDS to an authenticated control plane, PostgreSQL persistence, and deterministic investigation workflows.</p>
            <div className="hero-actions">
              <ExternalLink href={GITHUB_URL} className="button button-primary">View on GitHub <Icon name="arrow-up-right" size={16} /></ExternalLink>
              <ExternalLink href={`${GITHUB_URL}#quick-start`} className="button button-secondary">Download <Icon name="download" size={16} /></ExternalLink>
              <Link to="/login" className="button button-ghost">Open dashboard <Icon name="arrow-right" size={16} /></Link>
            </div>
            <div className="hero-notes"><span><Icon name="check" size={14} /> IPv4 packet parsing</span><span><Icon name="check" size={14} /> Deterministic port-scan detection</span><span><Icon name="check" size={14} /> Auditable workflow</span></div>
          </div>
          <div className="hero-visual" aria-label="Intriqo data flow">
            <div className="visual-header"><span className="visual-kicker">CONTROL PLANE / DATA FLOW</span><span className="visual-live"><span className="status-pulse" />REST API</span></div>
            <div className="signal-grid" />
            <div className="hero-pipeline"><ArchitectureFlow compact /></div>
            <div className="hero-visual-footer"><span>DETECTION</span><span>INVESTIGATION</span><span>DECISION</span></div>
          </div>
        </section>

        <section id="product" className="public-section container">
          <div className="section-intro"><p className="eyebrow">WHAT SHIPS TODAY</p><h2>A clear path from packet to finding.</h2><p>Each layer has a defined responsibility, a typed contract, and a place in the operator workflow. No invented telemetry. No opaque automation.</p></div>
          <div className="capability-grid">
            <Capability icon="network" index="01" title="C++ IDS engine" copy="IPv4 packet parsing, TCP/UDP/ICMP handling, flow tracking, and deterministic port-scan detection." />
            <Capability icon="server" index="02" title="Control plane" copy="FastAPI services for authenticated event, incident, task, finding, and audit management." />
            <Capability icon="bot" index="03" title="Investigation agent" copy="A deterministic investigation workflow that turns an agent task into structured findings." />
            <Capability icon="shield" index="04" title="Policy boundary" copy="Agent work is represented as auditable tasks and findings before any controlled action is considered." />
            <Capability icon="activity" index="05" title="Observability" copy="Follow the relationship between security events, incidents, agent tasks, findings, and audit records." />
          </div>
        </section>

        <section id="architecture" className="public-section architecture-section">
          <div className="container">
            <div className="section-intro"><p className="eyebrow">SYSTEM ARCHITECTURE</p><h2>One workflow. Explicit boundaries.</h2><p>Intriqo keeps detection, persistence, investigation, and response policy visible as separate, inspectable stages.</p></div>
            <div className="architecture-card"><ArchitectureFlow /><div className="architecture-caption"><span><span className="legend-dot legend-cyan" />Implemented path</span><span><span className="legend-dot legend-slate" />Contract boundary</span><ExternalLink href={`${GITHUB_URL}/blob/main/docs/architecture/system-architecture.md`} className="inline-link">Read the architecture <Icon name="arrow-up-right" size={14} /></ExternalLink></div></div>
          </div>
        </section>

        <section id="open-source" className="public-section container split-section">
          <div className="section-intro"><p className="eyebrow">OPEN SOURCE BY DEFAULT</p><h2>Built to be read, run, and improved.</h2><p>The repository is the product surface. Source, contracts, deployment notes, and architecture decisions stay close to the code.</p><ExternalLink href={GITHUB_URL} className="inline-link">Browse the repository <Icon name="arrow-up-right" size={14} /></ExternalLink></div>
          <div className="resource-list">
            <ResourceRow icon="github" title="GitHub repository" copy="Source code, issues, and release history." href={GITHUB_URL} />
            <ResourceRow icon="book" title="Documentation" copy="Architecture, engine, agents, and security model." href={DOCS_URL} />
            <ResourceRow icon="code" title="Contributing" copy="Development conventions and pull request guidance." href={CONTRIBUTING_URL} />
            <ResourceRow icon="alert" title="Security reporting" copy="Responsible disclosure process for security issues." href={`${GITHUB_URL}/blob/main/SECURITY.md`} />
          </div>
        </section>

        <section id="get-intriqo" className="public-section download-section">
          <div className="container">
            <div className="section-intro"><p className="eyebrow">GET INTRIQO</p><h2>Run the control plane where you work.</h2><p>There is no native desktop package in this phase. Use the repository's source and Docker workflows to run the web application and backend locally.</p></div>
            <div className="download-grid">
              <DownloadCard icon="code" label="SOURCE" title="Clone the repository" copy="Use the documented Python, C++, Node.js, and Docker prerequisites." command="git clone https://github.com/AlliedEdge/intriqo.git" href={`${GITHUB_URL}#quick-start`} />
              <DownloadCard icon="layers" label="CONTAINERIZED" title="Docker Compose" copy="Start PostgreSQL and the project services using the repository compose file." command="docker compose up -d" href={`${GITHUB_URL}#quick-start`} />
              <DownloadCard icon="terminal" label="LINUX" title="Linux development" copy="Build the engine, run the control plane, and start the Vite dashboard from source." command="cd frontend/dashboard && npm run dev" href={`${GITHUB_URL}#quick-start`} />
            </div>
          </div>
        </section>

        <section className="public-section developer-section container">
          <div className="developer-copy"><p className="eyebrow">FOR DEVELOPERS</p><h2>Start with the workflow, not a mock.</h2><p>Generate a real SecurityEvent, watch it persist through the control plane, and inspect the resulting incident, task, finding, and audit entries in the dashboard.</p><div className="developer-links"><ExternalLink href={GITHUB_URL} className="inline-link">GitHub <Icon name="arrow-up-right" size={14} /></ExternalLink><ExternalLink href={DOCS_URL} className="inline-link">Documentation <Icon name="arrow-up-right" size={14} /></ExternalLink><ExternalLink href={`${GITHUB_URL}/tree/main/contracts`} className="inline-link">Contracts <Icon name="arrow-up-right" size={14} /></ExternalLink><Link to="/login" className="inline-link">Open dashboard <Icon name="arrow-right" size={14} /></Link></div></div>
          <div className="code-window"><div className="code-window-bar"><span /><span /><span /><small>quick-start.sh</small></div><pre><code><span className="code-comment"># start infrastructure</span>{'\n'}docker compose up -d{'\n'}{'\n'}<span className="code-comment"># start the SOC dashboard</span>{'\n'}cd frontend/dashboard && npm install{'\n'}npm run dev</code></pre></div>
        </section>
      </main>

      <footer className="public-footer container"><Logo /><span>Open-source security operations, with the receipts left in the repository.</span><span>© {new Date().getFullYear()} AlliedEdge</span></footer>
    </div>
  )
}

function Capability({ icon, index, title, copy }: { icon: 'network' | 'server' | 'bot' | 'shield' | 'activity'; index: string; title: string; copy: string }) {
  return <article className="capability"><div className="capability-top"><span className="capability-icon"><Icon name={icon} size={20} /></span><span className="capability-index">{index}</span></div><h3>{title}</h3><p>{copy}</p></article>
}

function ResourceRow({ icon, title, copy, href }: { icon: 'github' | 'book' | 'code' | 'alert'; title: string; copy: string; href: string }) {
  return <ExternalLink href={href} className="resource-row"><span className="resource-icon"><Icon name={icon} size={18} /></span><span><strong>{title}</strong><small>{copy}</small></span><Icon name="arrow-up-right" size={16} /></ExternalLink>
}

function DownloadCard({ icon, label, title, copy, command, href }: { icon: 'code' | 'layers' | 'terminal'; label: string; title: string; copy: string; command: string; href: string }) {
  return <article className="download-card"><div className="download-card-top"><span className="capability-icon"><Icon name={icon} size={19} /></span><span className="card-label">{label}</span></div><h3>{title}</h3><p>{copy}</p><code>{command}</code><ExternalLink href={href} className="inline-link">Read setup <Icon name="arrow-up-right" size={14} /></ExternalLink></article>
}

export function LoginPage() {
  const { signIn } = useAuth()
  const navigate = useNavigate()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    setError(null)
    if (!username.trim() || !password) {
      setError('Enter your username and password to continue.')
      return
    }
    setSubmitting(true)
    try {
      await signIn(username.trim(), password)
      navigate('/dashboard', { replace: true })
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Sign in failed. Try again.')
    } finally {
      setSubmitting(false)
    }
  }

  return <div className="auth-page"><div className="auth-layout"><div className="auth-aside"><Link to="/" aria-label="Back to Intriqo"><Logo /></Link><div><p className="eyebrow">SECURITY OPERATIONS / CONTROL PLANE</p><h1>Sign in to your SOC.</h1><p>Access the investigation workflow backed by the Intriqo control plane. Events, incidents, findings, and audit history stay connected.</p></div><div className="auth-aside-flow"><ArchitectureFlow compact /></div><span className="auth-build">OPEN SOURCE / ALLIEDEDGE</span></div><main className="auth-card-wrap"><Card className="auth-card"><div className="auth-card-header"><Link to="/" className="auth-mobile-logo"><Logo compact /></Link><p className="eyebrow">OPERATOR ACCESS</p><h2>Welcome back</h2><p>Use your Intriqo control-plane credentials.</p></div><form onSubmit={submit} className="auth-form" noValidate><label className="field-label" htmlFor="username">Username<input id="username" name="username" autoComplete="username" value={username} onChange={(event) => setUsername(event.target.value)} placeholder="analyst" disabled={submitting} /></label><label className="field-label" htmlFor="password">Password<input id="password" name="password" type="password" autoComplete="current-password" value={password} onChange={(event) => setPassword(event.target.value)} placeholder="Enter your password" disabled={submitting} /></label>{error && <div className="form-error" role="alert"><Icon name="alert" size={16} />{error}</div>}<Button type="submit" disabled={submitting} className="auth-submit">{submitting ? 'Signing in…' : 'Sign in'}<Icon name="arrow-right" size={16} /></Button></form><p className="auth-help">Authentication is handled by the FastAPI control plane. No social login is enabled.</p></Card><Link to="/" className="back-public"><Icon name="chevron-left" size={14} /> Back to public site</Link></main></div></div>
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
    const [countResponses, events, incidents, tasks, findings, audit] = await Promise.all([
      Promise.all(dashboardSeverities.map((severity) => eventsApi.list({ severity, page: 1, page_size: 1 }, signal))),
      eventsApi.list({ page: 1, page_size: 8 }, signal),
      incidentsApi.list({ page: 1, page_size: 6 }, signal),
      tasksApi.list({ page: 1, page_size: 6 }, signal),
      findingsApi.list({ page: 1, page_size: 6 }, signal),
      auditApi.list({ page: 1, page_size: 10 }, signal),
    ])
    const counts = {} as Record<Severity, number>
    dashboardSeverities.forEach((severity, index) => { counts[severity] = countResponses[index].total })
    return { counts, events, incidents, tasks, findings, audit }
  }, `dashboard-${reload}`)

  if (query.loading && !query.data) return <div className="page-stack"><PageHeader eyebrow="SECURITY OPERATIONS" title="Overview" description="Loading the current control-plane state…" /><LoadingRows columns={4} rows={7} /></div>
  if (query.error && !query.data) return <div className="page-stack"><PageHeader eyebrow="SECURITY OPERATIONS" title="Overview" description="The dashboard reads directly from the Intriqo APIs." /><ErrorState message={safeError(query.error)} onRetry={() => setReload((value) => value + 1)} /></div>
  if (!query.data) return null
  const { counts, events, incidents, tasks, findings, audit } = query.data

  return <div className="page-stack"><PageHeader eyebrow="SECURITY OPERATIONS" title="Overview" description="A connected view of detection, investigation, and audit activity." actions={<Button variant="secondary" size="sm" icon="refresh" onClick={() => setReload((value) => value + 1)}>Refresh</Button>} />
    <div className="dashboard-meta"><span><span className="status-pulse" /> REST API connected</span>{query.updatedAt && <span>Updated {relativeTime(query.updatedAt.toISOString())}</span>}</div>
    <div className="metric-grid">{dashboardSeverities.map((severity) => <Card className={`metric-card metric-${severity.toLowerCase()}`} key={severity}><div className="metric-label"><SeverityBadge severity={severity} /><Icon name="arrow-up-right" size={15} /></div><strong>{counts[severity].toLocaleString()}</strong><span>events in control plane</span></Card>)}</div>
    <div className="dashboard-grid dashboard-grid-primary"><Card className="panel panel-wide"><SectionHeading title="Recent security events" description="Latest events emitted by the IDS engine." action={<Link className="panel-link" to="/events">View all <Icon name="arrow-right" size={14} /></Link>} />{events.items.length === 0 ? <EmptyState icon="network" title="No security events yet" description="Run the Intriqo IDS demo to generate your first event." /> : <TableFrame><table className="data-table"><thead><tr><th>Severity</th><th>Event type</th><th>Source → destination</th><th>Detected</th><th>Status</th></tr></thead><tbody>{events.items.map((event) => <tr key={event.event_id}><td><SeverityBadge severity={event.severity} /></td><td><Link className="table-link" to={`/events/${event.event_id}`}>{event.event_type}</Link></td><td className="mono">{event.source_address} <span className="muted">→</span> {event.destination_address}</td><td>{formatDate(event.timestamp)}</td><td><StatusBadge status="INGESTED" /></td></tr>)}</tbody></table></TableFrame>}</Card><Card className="panel"><SectionHeading title="Active incidents" description="Open work requiring operator attention." action={<Link className="panel-link" to="/incidents">View all <Icon name="arrow-right" size={14} /></Link>} />{incidents.items.length === 0 ? <EmptyState icon="alert" title="No active incidents" description="Incidents will appear here when the control plane creates them." /> : <div className="compact-list">{incidents.items.map((incident) => <Link className="compact-list-row" to={`/incidents/${incident.incident_id}`} key={incident.incident_id}><span><strong>{truncate(incident.title, 42)}</strong><small>{shortId(incident.incident_id, 12)} · {relativeTime(incident.updated_at)}</small></span><span><SeverityBadge severity={incident.severity} /><StatusBadge status={incident.status} /></span></Link>)}</div>}</Card></div>
    <div className="dashboard-grid"><Card className="panel"><SectionHeading title="Agent activity" description="Tasks in the investigation workflow." action={<Link className="panel-link" to="/agents">Agents <Icon name="arrow-right" size={14} /></Link>} />{tasks.items.length === 0 ? <EmptyState icon="bot" title="No agent tasks" description="Agent tasks will appear after an incident is queued." /> : <div className="compact-list">{tasks.items.map((task) => <Link className="compact-list-row" to="/agents" key={task.task_id}><span><strong>{truncate(task.description, 38)}</strong><small>{task.task_type} · {formatDate(task.created_at)}</small></span><StatusBadge status={task.status} /></Link>)}</div>}</Card><Card className="panel"><SectionHeading title="Recent findings" description="Structured output from investigation agents." action={<Link className="panel-link" to="/findings">Findings <Icon name="arrow-right" size={14} /></Link>} />{findings.items.length === 0 ? <EmptyState icon="bot" title="No findings yet" description="Agent findings will appear here after a task completes." /> : <div className="compact-list">{findings.items.map((finding) => <Link className="compact-list-row" to={`/findings/${finding.finding_id}`} key={finding.finding_id}><span><strong>{truncate(finding.summary || finding.findings[0] || 'Untitled finding', 38)}</strong><small>{finding.agent_name} · {formatDate(finding.created_at)}</small></span><StatusBadge status={finding.status} /></Link>)}</div>}</Card><Card className="panel"><SectionHeading title="Activity timeline" description="Append-only audit records across the workflow." action={<Link className="panel-link" to="/audit">Audit <Icon name="arrow-right" size={14} /></Link>} />{audit.items.length === 0 ? <EmptyState icon="clock" title="No audit activity" description="Workflow actions will be recorded here as the system runs." /> : <div className="timeline">{audit.items.slice(0, 7).map((entry) => <TimelineEntry entry={entry} key={entry.id} />)}</div>}</Card></div>
  </div>
}

function TimelineEntry({ entry }: { entry: AuditLog }) {
  const icon = entry.resource_type === 'security_event' ? 'network' : entry.resource_type === 'incident' ? 'alert' : entry.resource_type === 'agent_task' ? 'bot' : entry.resource_type === 'finding' ? 'check' : 'list'
  return <div className="timeline-entry"><span className="timeline-icon"><Icon name={icon} size={14} /></span><div><strong>{entry.action.replace(/_/g, ' ')}</strong><span>{entry.resource_type.replace(/_/g, ' ')} <span className="muted">·</span> {shortId(entry.resource_id, 12)}</span></div><time title={formatDate(entry.created_at, true)}>{relativeTime(entry.created_at)}</time></div>
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
    {query.loading && !query.data ? <Card className="panel"><LoadingRows columns={5} /></Card> : query.error && !query.data ? <ErrorState message={safeError(query.error)} onRetry={query.refresh} /> : query.data && query.data.items.length === 0 ? <Card className="panel"><EmptyState icon="network" title="No security events found" description="Adjust the filters or run the Intriqo IDS demo to generate a SecurityEvent." /></Card> : query.data ? <Card className="panel"><SectionHeading title="Security event explorer" description={`${query.data.total.toLocaleString()} persisted events`} /><TableFrame><table className="data-table"><thead><tr><th>Severity</th><th>Event type</th><th>Source</th><th>Destination</th><th>Detected</th><th>Status</th></tr></thead><tbody>{query.data.items.map((event) => <tr key={event.event_id}><td><SeverityBadge severity={event.severity} /></td><td><Link className="table-link" to={`/events/${event.event_id}`} title={event.event_type}>{event.event_type}</Link><small className="table-subtext">{shortId(event.event_id, 14)}</small></td><td className="mono">{event.source_address}</td><td className="mono">{event.destination_address}</td><td title={formatDate(event.timestamp, true)}>{formatDate(event.timestamp)}</td><td><StatusBadge status="INGESTED" /></td></tr>)}</tbody></table></TableFrame><Pagination page={query.data.page} hasNext={query.data.has_next} total={query.data.total} pageSize={query.data.page_size} onPageChange={setPage} /></Card> : null}
  </div>
}

export function EventDetailPage() {
  const { eventId = '' } = useParams()
  const query = useApi(async (signal) => {
    const event = await eventsApi.get(eventId, signal)
    let relatedIncidents: Incident[] = []
    try {
      const incidents = await incidentsApi.list({ page: 1, page_size: 100 }, signal)
      relatedIncidents = incidents.items.filter((incident) => incident.linked_event_ids.includes(event.event_id))
    } catch {
      // Related incidents are supplementary; the event detail remains useful if this read is unavailable.
    }
    return { event, relatedIncidents }
  }, eventId)

  if (query.loading && !query.data) return <div className="page-stack"><BackLink to="/events" label="Events" /><PageHeader eyebrow="SECURITY EVENT" title="Loading event…" /><LoadingRows columns={2} rows={5} /></div>
  if (query.error && !query.data) return <div className="page-stack"><BackLink to="/events" label="Events" /><ErrorState message={safeError(query.error)} onRetry={query.refresh} /></div>
  if (!query.data) return null
  const { event, relatedIncidents } = query.data
  return <div className="page-stack"><BackLink to="/events" label="Events" /><PageHeader eyebrow="SECURITY EVENT" title={event.event_type} description={event.description || 'No description was provided by the detector.'} actions={<StatusBadge status="INGESTED" />} />
    <div className="detail-grid"><Card className="panel"><SectionHeading title="Event metadata" /><dl className="key-value-grid"><KeyValue label="Event ID" value={event.event_id} mono /><KeyValue label="Severity" value={<SeverityBadge severity={event.severity} />} /><KeyValue label="Detected" value={formatDate(event.timestamp, true)} /><KeyValue label="Ingested" value={formatDate(event.ingested_at, true)} /><KeyValue label="Source" value={event.source_address} mono /><KeyValue label="Destination" value={event.destination_address} mono /></dl></Card><Card className="panel"><SectionHeading title="Detection details" description="Detector-specific evidence from the SecurityEvent contract." />{Object.keys(event.details).length === 0 ? <EmptyState icon="info" title="No additional details" description="This event did not include detector-specific metadata." /> : <dl className="detail-properties">{Object.entries(event.details).map(([key, value]) => <KeyValue key={key} label={key.replace(/_/g, ' ')} value={asString(value) || prettyJson(value)} mono={typeof value !== 'string'} />)}</dl>}</Card></div>
    <Card className="panel"><SectionHeading title="Related incidents" description="Incidents that link this event through the control plane." />{relatedIncidents.length === 0 ? <EmptyState icon="alert" title="No linked incident" description="This event is not linked to an incident yet." /> : <div className="compact-list">{relatedIncidents.map((incident) => <Link className="compact-list-row" to={`/incidents/${incident.incident_id}`} key={incident.incident_id}><span><strong>{incident.title}</strong><small>{shortId(incident.incident_id, 14)} · updated {relativeTime(incident.updated_at)}</small></span><span><SeverityBadge severity={incident.severity} /><StatusBadge status={incident.status} /></span></Link>)}</div>}</Card>
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
    {query.loading && !query.data ? <Card className="panel"><LoadingRows columns={5} /></Card> : query.error && !query.data ? <ErrorState message={safeError(query.error)} onRetry={query.refresh} /> : query.data && query.data.items.length === 0 ? <Card className="panel"><EmptyState icon="alert" title="No incidents found" description="Incidents will appear here when the control plane groups a security event for investigation." /></Card> : query.data ? <Card className="panel"><SectionHeading title="Incident queue" description={`${query.data.total.toLocaleString()} persisted incidents`} /><TableFrame><table className="data-table"><thead><tr><th>Incident</th><th>Severity</th><th>Status</th><th>Linked events</th><th>Created</th><th>Updated</th></tr></thead><tbody>{query.data.items.map((incident) => <tr key={incident.incident_id}><td><Link className="table-link" to={`/incidents/${incident.incident_id}`} title={incident.title}>{truncate(incident.title, 44)}</Link><small className="table-subtext">{shortId(incident.incident_id, 14)}</small></td><td><SeverityBadge severity={incident.severity} /></td><td><StatusBadge status={incident.status} /></td><td>{incident.linked_event_ids.length}</td><td>{formatDate(incident.created_at)}</td><td>{formatDate(incident.updated_at)}</td></tr>)}</tbody></table></TableFrame><Pagination page={query.data.page} hasNext={query.data.has_next} total={query.data.total} pageSize={query.data.page_size} onPageChange={setPage} /></Card> : null}
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
    const events = (await Promise.all(incident.linked_event_ids.map((id) => eventsApi.get(id, signal).catch(() => null)))).filter((event): event is SecurityEvent => event !== null)
    const tasksResponse = await tasksApi.list({ incident_id: incidentId, page: 1, page_size: 100 }, signal)
    const findingResponses = await Promise.all(tasksResponse.items.map((task) => findingsApi.list({ task_id: task.task_id, page: 1, page_size: 100 }, signal).catch(() => null)))
    const findings = findingResponses.flatMap((response) => response?.items || [])
    let audit: AuditLog[] = []
    try {
      audit = (await auditApi.list({ resource_id: incidentId, page: 1, page_size: 50 }, signal)).items
    } catch {
      // The incident remains readable if an older control plane does not expose audit reads.
    }
    return { incident, events, tasks: tasksResponse.items, findings, audit }
  }, incidentId)

  if (query.loading && !query.data) return <div className="page-stack"><BackLink to="/incidents" label="Incidents" /><PageHeader eyebrow="INCIDENT" title="Loading incident…" /><LoadingRows columns={3} rows={6} /></div>
  if (query.error && !query.data) return <div className="page-stack"><BackLink to="/incidents" label="Incidents" /><ErrorState message={safeError(query.error)} onRetry={query.refresh} /></div>
  if (!query.data) return null
  const { incident, events, tasks, findings, audit } = query.data
  return <div className="page-stack"><BackLink to="/incidents" label="Incidents" /><PageHeader eyebrow={`INCIDENT / ${shortId(incident.incident_id, 14)}`} title={incident.title} description={incident.description || 'No description was provided for this incident.'} actions={<span className="header-badges"><SeverityBadge severity={incident.severity} /><StatusBadge status={incident.status} /></span>} />
    <div className="detail-grid"><Card className="panel"><SectionHeading title="Incident summary" /><dl className="key-value-grid"><KeyValue label="Incident ID" value={incident.incident_id} mono /><KeyValue label="Status" value={<StatusBadge status={incident.status} />} /><KeyValue label="Severity" value={<SeverityBadge severity={incident.severity} />} /><KeyValue label="Created" value={formatDate(incident.created_at, true)} /><KeyValue label="Updated" value={formatDate(incident.updated_at, true)} /><KeyValue label="Resolved" value={formatDate(incident.resolved_at, true)} /></dl></Card><Card className="panel"><SectionHeading title="Workflow state" description="Every related object is read from its own authenticated API." /><div className="workflow-counts"><WorkflowCount label="Events" value={events.length} icon="network" /><WorkflowCount label="Agent tasks" value={tasks.length} icon="bot" /><WorkflowCount label="Findings" value={findings.length} icon="check" /><WorkflowCount label="Audit records" value={audit.length} icon="list" /></div></Card></div>
    <Card className="panel"><SectionHeading title="Related events" description="SecurityEvents linked to this incident." />{events.length === 0 ? <EmptyState icon="network" title="No related events" description="The incident has no readable linked SecurityEvents." /> : <TableFrame><table className="data-table"><thead><tr><th>Severity</th><th>Event type</th><th>Source → destination</th><th>Detected</th></tr></thead><tbody>{events.map((event) => <tr key={event.event_id}><td><SeverityBadge severity={event.severity} /></td><td><Link className="table-link" to={`/events/${event.event_id}`}>{event.event_type}</Link></td><td className="mono">{event.source_address} <span className="muted">→</span> {event.destination_address}</td><td>{formatDate(event.timestamp)}</td></tr>)}</tbody></table></TableFrame>}</Card>
    <div className="dashboard-grid"><Card className="panel"><SectionHeading title="Agent tasks" description="Investigation work derived from this incident." />{tasks.length === 0 ? <EmptyState icon="bot" title="No agent tasks" description="No task is linked to this incident yet." /> : <div className="compact-list">{tasks.map((task) => <div className="compact-list-row" key={task.task_id}><span><strong>{truncate(task.description, 46)}</strong><small>{task.task_type} · {shortId(task.task_id, 14)} · created {formatDate(task.created_at)}</small></span><StatusBadge status={task.status} /></div>)}</div>}</Card><Card className="panel"><SectionHeading title="Findings" description="Results submitted by the investigation workflow." />{findings.length === 0 ? <EmptyState icon="bot" title="No findings" description="A completed investigation task will attach findings here." /> : <div className="compact-list">{findings.map((finding) => <Link className="compact-list-row" to={`/findings/${finding.finding_id}`} key={finding.finding_id}><span><strong>{truncate(finding.summary || finding.findings[0] || 'Untitled finding', 46)}</strong><small>{finding.agent_name} · {Math.round(finding.confidence * 100)}% confidence</small></span><StatusBadge status={finding.status} /></Link>)}</div>}</Card></div>
    <Card className="panel"><SectionHeading title="Incident timeline" description="Audit entries whose resource is this incident." />{audit.length === 0 ? <EmptyState icon="clock" title="No incident audit entries" description="The control plane has not returned audit records for this incident." /> : <div className="timeline">{audit.map((entry) => <TimelineEntry entry={entry} key={entry.id} />)}</div>}</Card>
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
    <Card className="panel"><SectionHeading title="Recent investigation tasks" description="Tasks returned by GET /api/v1/agent-tasks?task_type=INVESTIGATION." />{query.loading && !query.data ? <LoadingRows columns={4} /> : query.error && !query.data ? <ErrorState message={safeError(query.error)} onRetry={query.refresh} /> : query.data && query.data.items.length === 0 ? <EmptyState icon="bot" title="No investigation tasks" description="Tasks will appear here after the control plane queues an investigation." /> : query.data ? <TableFrame><table className="data-table"><thead><tr><th>Task</th><th>Priority</th><th>Status</th><th>Incident</th><th>Created</th><th>Completed</th></tr></thead><tbody>{query.data.items.map((task) => <tr key={task.task_id}><td><strong>{truncate(task.description, 48)}</strong><small className="table-subtext mono">{shortId(task.task_id, 14)}</small></td><td><Badge tone={task.priority.toLowerCase()}>{task.priority}</Badge></td><td><StatusBadge status={task.status} /></td><td>{task.incident_id ? <Link className="table-link mono" to={`/incidents/${task.incident_id}`}>{shortId(task.incident_id, 12)}</Link> : <span className="muted">—</span>}</td><td>{formatDate(task.created_at)}</td><td>{formatDate(task.completed_at)}</td></tr>)}</tbody></table></TableFrame> : null}</Card>
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
    {query.loading && !query.data ? <Card className="panel"><LoadingRows columns={6} /></Card> : query.error && !query.data ? <ErrorState message={safeError(query.error)} onRetry={query.refresh} /> : query.data && query.data.items.length === 0 ? <Card className="panel"><EmptyState icon="bot" title="No findings found" description="Completed investigations will appear here when an agent submits a result." /></Card> : query.data ? <Card className="panel"><SectionHeading title="Agent findings" description={`${query.data.total.toLocaleString()} persisted findings`} /><TableFrame><table className="data-table"><thead><tr><th>Finding</th><th>Severity</th><th>Agent</th><th>Task</th><th>Created</th><th>Status</th></tr></thead><tbody>{query.data.items.map((finding) => { const severity = findingSeverity(finding); return <tr key={finding.finding_id}><td><Link className="table-link" to={`/findings/${finding.finding_id}`}>{truncate(finding.summary || finding.findings[0] || 'Untitled finding', 45)}</Link><small className="table-subtext mono">{shortId(finding.finding_id, 14)}</small></td><td>{severity ? <SeverityBadge severity={severity} /> : <span className="muted" title="Severity is not part of the current Finding contract">—</span>}</td><td className="mono">{finding.agent_name}</td><td><Link className="table-link mono" to="/agents">{shortId(finding.task_id, 12)}</Link></td><td>{formatDate(finding.created_at)}</td><td><StatusBadge status={finding.status} /></td></tr> })}</tbody></table></TableFrame><Pagination page={query.data.page} hasNext={query.data.has_next} total={query.data.total} pageSize={query.data.page_size} onPageChange={setPage} /></Card> : null}
  </div>
}

interface FindingDetailSnapshot {
  finding: Finding
  task: AgentTask
  incident: Incident | null
  event: SecurityEvent | null
}

export function FindingDetailPage() {
  const { findingId = '' } = useParams()
  const query = useApi<FindingDetailSnapshot>(async (signal) => {
    const finding = await findingsApi.get(findingId, signal)
    const task = await tasksApi.get(finding.task_id, signal)
    const [incident, event] = await Promise.all([
      task.incident_id ? incidentsApi.get(task.incident_id, signal).catch(() => null) : Promise.resolve(null),
      task.event_id ? eventsApi.get(task.event_id, signal).catch(() => null) : Promise.resolve(null),
    ])
    return { finding, task, incident, event }
  }, findingId)

  if (query.loading && !query.data) return <div className="page-stack"><BackLink to="/findings" label="Findings" /><PageHeader eyebrow="FINDING" title="Loading finding…" /><LoadingRows columns={2} rows={5} /></div>
  if (query.error && !query.data) return <div className="page-stack"><BackLink to="/findings" label="Findings" /><ErrorState message={safeError(query.error)} onRetry={query.refresh} /></div>
  if (!query.data) return null
  const { finding, incident, event } = query.data
  const recommendation = finding.finding_metadata.recommendation ?? finding.finding_metadata.recommendations
  return <div className="page-stack"><BackLink to="/findings" label="Findings" /><PageHeader eyebrow={`FINDING / ${shortId(finding.finding_id, 14)}`} title={finding.summary || finding.findings[0] || 'Investigation finding'} description={`Submitted by ${finding.agent_name} on ${formatDateOnly(finding.created_at)}.`} actions={<StatusBadge status={finding.status} />} />
    <div className="detail-grid"><Card className="panel"><SectionHeading title="Finding summary" /><dl className="key-value-grid"><KeyValue label="Finding ID" value={finding.finding_id} mono /><KeyValue label="Agent" value={finding.agent_name} mono /><KeyValue label="Task" value={<Link className="table-link mono" to="/agents">{shortId(finding.task_id, 16)}</Link>} /><KeyValue label="Confidence" value={`${Math.round(finding.confidence * 100)}%`} /><KeyValue label="Created" value={formatDate(finding.created_at, true)} /><KeyValue label="Severity" value={findingSeverity(finding) ? <SeverityBadge severity={findingSeverity(finding)} /> : <span className="muted">Not included in contract</span>} /></dl></Card><Card className="panel"><SectionHeading title="Recommendation" description="Read from finding metadata when supplied by the agent." />{recommendation ? <p className="detail-copy">{typeof recommendation === 'string' ? recommendation : prettyJson(recommendation)}</p> : <EmptyState icon="info" title="No recommendation provided" description="This finding does not include a recommendation in finding_metadata." />}</Card></div>
    <Card className="panel"><SectionHeading title="Findings" description="Agent-generated observations." />{finding.findings.length === 0 ? <EmptyState icon="info" title="No observations" description="The agent submitted no finding strings." /> : <ul className="finding-list">{finding.findings.map((item, index) => <li key={`${item}-${index}`}><span className="finding-bullet"><Icon name="check" size={13} /></span><span>{item}</span></li>)}</ul>}</Card>
    <div className="dashboard-grid"><Card className="panel"><SectionHeading title="Evidence" description="Structured evidence objects submitted with the result." />{finding.evidence.length === 0 ? <EmptyState icon="database" title="No evidence attached" description="The finding contains no evidence objects." /> : <div className="evidence-list">{finding.evidence.map((item, index) => <details className="evidence-item" key={index}><summary>Evidence {String(index + 1).padStart(2, '0')}</summary><pre>{prettyJson(item)}</pre></details>)}</div>}</Card><Card className="panel"><SectionHeading title="Related resources" /><div className="related-resource-list">{incident ? <Link className="related-resource" to={`/incidents/${incident.incident_id}`}><span className="resource-icon"><Icon name="alert" size={16} /></span><span><strong>{incident.title}</strong><small>Incident · {shortId(incident.incident_id, 14)}</small></span><Icon name="arrow-up-right" size={15} /></Link> : <div className="related-resource related-resource-muted"><span className="resource-icon"><Icon name="alert" size={16} /></span><span><strong>No related incident</strong><small>The task has no readable incident link.</small></span></div>}{event ? <Link className="related-resource" to={`/events/${event.event_id}`}><span className="resource-icon"><Icon name="network" size={16} /></span><span><strong>{event.event_type}</strong><small>SecurityEvent · {shortId(event.event_id, 14)}</small></span><Icon name="arrow-up-right" size={15} /></Link> : <div className="related-resource related-resource-muted"><span className="resource-icon"><Icon name="network" size={16} /></span><span><strong>No related event</strong><small>The task has no readable event link.</small></span></div>}</div></Card></div>
    {finding.error && <Card className="panel"><SectionHeading title="Agent error" /><pre className="json-block">{prettyJson(finding.error)}</pre></Card>}
  </div>
}

interface AuditFilters {
  action: string
  outcome: string
}

const emptyAuditFilters: AuditFilters = { action: '', outcome: '' }

export function AuditPage() {
  const [draft, setDraft] = useState<AuditFilters>(emptyAuditFilters)
  const [filters, setFilters] = useState<AuditFilters>(emptyAuditFilters)
  const [page, setPage] = useState(1)
  const key = JSON.stringify({ ...filters, page })
  const query = useApi((signal) => auditApi.list({ action: filters.action || undefined, outcome: filters.outcome || undefined, page, page_size: 25 }, signal), key)
  const applyFilters = (event: FormEvent<HTMLFormElement>) => { event.preventDefault(); setPage(1); setFilters(draft) }
  const resetFilters = () => { setDraft(emptyAuditFilters); setFilters(emptyAuditFilters); setPage(1) }
  return <div className="page-stack"><PageHeader eyebrow="GOVERNANCE" title="Audit" description="Append-only security operation history returned by the authenticated control plane." actions={<Button variant="secondary" size="sm" icon="refresh" onClick={query.refresh}>Refresh</Button>} />
    <Card className="filter-card"><form className="filter-form filter-form-short" onSubmit={applyFilters}><div className="filter-field"><label htmlFor="audit-action">Action</label><input id="audit-action" value={draft.action} onChange={(event) => setDraft((current) => ({ ...current, action: event.target.value }))} placeholder="FINDING_SUBMITTED" /></div><div className="filter-field"><label htmlFor="audit-outcome">Outcome</label><select id="audit-outcome" value={draft.outcome} onChange={(event) => setDraft((current) => ({ ...current, outcome: event.target.value }))}><option value="">All outcomes</option><option value="SUCCESS">SUCCESS</option><option value="FAILURE">FAILURE</option></select></div><div className="filter-actions"><Button type="submit" icon="filter">Apply filters</Button><Button type="button" variant="ghost" onClick={resetFilters}>Reset</Button></div></form></Card>
    {query.loading && !query.data ? <Card className="panel"><LoadingRows columns={6} /></Card> : query.error && !query.data ? <ErrorState message={safeError(query.error)} onRetry={query.refresh} /> : query.data && query.data.items.length === 0 ? <Card className="panel"><EmptyState icon="list" title="No audit entries" description="The control plane has not recorded activity matching these filters." /></Card> : query.data ? <Card className="panel"><SectionHeading title="Operation history" description={`${query.data.total.toLocaleString()} immutable records`} /><TableFrame><table className="data-table"><thead><tr><th>Actor</th><th>Action</th><th>Resource</th><th>Outcome</th><th>Timestamp</th><th>Detail</th></tr></thead><tbody>{query.data.items.map((entry) => <tr key={entry.id}><td className="mono">{entry.actor}</td><td><strong>{entry.action}</strong><small className="table-subtext mono">{shortId(entry.id, 14)}</small></td><td><span>{entry.resource_type}</span><small className="table-subtext mono">{shortId(entry.resource_id, 14)}</small></td><td><StatusBadge status={entry.outcome} /></td><td title={formatDate(entry.created_at, true)}>{formatDate(entry.created_at)}</td><td>{entry.detail || <span className="muted">—</span>}{Object.keys(entry.extra).length > 0 && <details className="inline-details"><summary>Extra</summary><pre>{prettyJson(entry.extra)}</pre></details>}</td></tr>)}</tbody></table></TableFrame><Pagination page={query.data.page} hasNext={query.data.has_next} total={query.data.total} pageSize={query.data.page_size} onPageChange={setPage} /></Card> : null}
  </div>
}

export function SettingsPage() {
  const { user } = useAuth()
  return <div className="page-stack"><PageHeader eyebrow="WORKSPACE" title="Settings" description="Session and connection details for this dashboard instance." /><div className="detail-grid"><Card className="panel"><SectionHeading title="Current operator" /><dl className="key-value-grid"><KeyValue label="Username" value={user?.username || '—'} /><KeyValue label="Role" value={<Badge tone="info">{user?.role || '—'}</Badge>} /><KeyValue label="Session" value={<StatusBadge status="AUTHENTICATED" />} /><KeyValue label="Token storage" value="Session-only browser storage" /></dl></Card><Card className="panel"><SectionHeading title="Control plane" description="The dashboard uses typed REST services and can add SSE/WebSocket transport later without changing page contracts." /><dl className="key-value-grid"><KeyValue label="API base" value={apiConfiguration.baseUrl} mono /><KeyValue label="Transport" value="Authenticated REST" /><KeyValue label="Refresh model" value="Initial fetch + explicit refresh" /><KeyValue label="API docs" value={<a className="table-link" href="/docs" target="_blank" rel="noreferrer">Open FastAPI docs <Icon name="external" size={13} /></a>} /></dl></Card></div><Card className="panel settings-note"><div className="settings-note-icon"><Icon name="info" size={20} /></div><div><strong>Security note</strong><p>JWTs are never rendered in the interface or written to project files. Sign out clears the current browser session.</p></div></Card></div>
}
