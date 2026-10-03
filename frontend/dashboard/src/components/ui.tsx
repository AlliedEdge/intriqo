import { forwardRef, type ButtonHTMLAttributes, type HTMLAttributes, type ReactNode } from 'react'
import logoUrl from '../../../../assets/branding/intriqo-logo.svg'
import type { Severity } from '@/types/api'

export type IconName =
  | 'activity' | 'alert' | 'arrow-right' | 'arrow-up-right' | 'book' | 'bot'
  | 'check' | 'chevron-down' | 'chevron-left' | 'chevron-right' | 'clock'
  | 'code' | 'database' | 'download' | 'external' | 'filter' | 'github'
  | 'grid' | 'info' | 'layers' | 'list' | 'lock' | 'logout' | 'menu'
  | 'network' | 'refresh' | 'search' | 'server' | 'settings' | 'shield'
  | 'sliders' | 'terminal' | 'user' | 'x'

const iconPaths: Record<IconName, string[]> = {
  activity: ['M3 12h4l2-7 4 14 2-7h6'],
  alert: ['M12 3 2.8 20h18.4L12 3Z', 'M12 9v4', 'M12 17h.01'],
  'arrow-right': ['M5 12h14', 'm13 6 6 6-6 6'],
  'arrow-up-right': ['M5 19 19 5', 'M9 5h10v10'],
  book: ['M4 5.5A2.5 2.5 0 0 1 6.5 3H20v16H6.5A2.5 2.5 0 0 0 4 21.5v-16Z', 'M4 18.5A2.5 2.5 0 0 1 6.5 16H20'],
  bot: ['M8 9h8', 'M9 13h.01', 'M15 13h.01', 'M6 7h12a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V9a2 2 0 0 1 2-2Z', 'M12 3v4', 'M9 3h6'],
  check: ['m5 12 4 4L19 6'],
  'chevron-down': ['m6 9 6 6 6-6'],
  'chevron-left': ['m15 18-6-6 6-6'],
  'chevron-right': ['m9 18 6-6-6-6'],
  clock: ['M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18Z', 'M12 7v5l3 2'],
  code: ['m8 9-4 3 4 3', 'm16 9 4 3-4 3', 'm14 5-4 14'],
  database: ['M4 6c0 1.7 3.6 3 8 3s8-1.3 8-3-3.6-3-8-3-8 1.3-8 3Z', 'M4 6v6c0 1.7 3.6 3 8 3s8-1.3 8-3V6', 'M4 12v6c0 1.7 3.6 3 8 3s8-1.3 8-3v-6'],
  download: ['M12 3v12', 'm7 10 5 5 5-5', 'M5 21h14'],
  external: ['M14 4h6v6', 'M10 14 20 4', 'M20 14v5a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h5'],
  filter: ['M4 5h16', 'M7 12h10', 'M10 19h4'],
  github: ['M15 22v-4a4.8 4.8 0 0 0-1-3.5c3.3-.4 6.8-1.6 6.8-7A5.4 5.4 0 0 0 19.3 4 5 5 0 0 0 19.2.1S17.9-.3 15 1.6a13.4 13.4 0 0 0-6 0C6.1-.3 4.8.1 4.8.1A5 5 0 0 0 4.7 4 5.4 5.4 0 0 0 3.2 7.5c0 5.4 3.5 6.6 6.8 7A4.8 4.8 0 0 0 9 18v4', 'M9 18c-4.5 2-5-2-7-2'],
  grid: ['M4 4h6v6H4z', 'M14 4h6v6h-6z', 'M4 14h6v6H4z', 'M14 14h6v6h-6z'],
  info: ['M12 16v-4', 'M12 8h.01', 'M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18Z'],
  layers: ['m12 3 9 5-9 5-9-5 9-5Z', 'm3 12 9 5 9-5', 'm3 16 9 5 9-5'],
  list: ['M8 6h12', 'M8 12h12', 'M8 18h12', 'M4 6h.01', 'M4 12h.01', 'M4 18h.01'],
  lock: ['M6 10V7a6 6 0 0 1 12 0v3', 'M5 10h14v10H5z', 'M12 14v2'],
  logout: ['M10 17l5-5-5-5', 'M15 12H3', 'M21 19V5a2 2 0 0 0-2-2h-5'],
  menu: ['M4 6h16', 'M4 12h16', 'M4 18h16'],
  network: ['M12 3v5', 'M5 21v-5h14v5', 'M12 8 5 16', 'M12 8l7 8', 'M4 3h16'],
  refresh: ['M20 11a8 8 0 0 0-14.6-4L3 10', 'M3 4v6h6', 'M4 13a8 8 0 0 0 14.6 4L21 14', 'M21 20v-6h-6'],
  search: ['m21 21-4.3-4.3', 'M11 18a7 7 0 1 0 0-14 7 7 0 0 0 0 14Z'],
  server: ['M4 4h16v6H4z', 'M4 14h16v6H4z', 'M7 7h.01', 'M7 17h.01', 'M11 7h6', 'M11 17h6'],
  settings: ['M12 15.5a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7Z', 'M19.4 15a1.7 1.7 0 0 0 .3 1.9l.1.1-1.7 1.7-.1-.1a1.7 1.7 0 0 0-1.9-.3 1.7 1.7 0 0 0-1 1.6v.1h-2.4v-.1a1.7 1.7 0 0 0-1-1.6 1.7 1.7 0 0 0-1.9.3l-.1.1L8 17l.1-.1a1.7 1.7 0 0 0 .3-1.9 1.7 1.7 0 0 0-1.6-1H6.7v-2.4h.1a1.7 1.7 0 0 0 1.6-1 1.7 1.7 0 0 0-.3-1.9L8 8.6l1.7-1.7.1.1a1.7 1.7 0 0 0 1.9.3 1.7 1.7 0 0 0 1-1.6v-.1h2.4v.1a1.7 1.7 0 0 0 1 1.6 1.7 1.7 0 0 0 1.9-.3l.1-.1 1.7 1.7-.1.1a1.7 1.7 0 0 0-.3 1.9 1.7 1.7 0 0 0 1.6 1h.1V14h-.1a1.7 1.7 0 0 0-1.6 1Z'],
  shield: ['M12 3 20 6v5c0 5-3.4 8.6-8 10-4.6-1.4-8-5-8-10V6l8-3Z', 'm9 12 2 2 4-4'],
  sliders: ['M4 6h6', 'M14 6h6', 'M4 12h10', 'M18 12h2', 'M4 18h2', 'M10 18h10', 'M10 4v4', 'M14 10v4', 'M6 16v4'],
  terminal: ['M4 5h16v14H4z', 'm7 9 3 3-3 3', 'M13 15h4'],
  user: ['M20 21a8 8 0 0 0-16 0', 'M12 13a4 4 0 1 0 0-8 4 4 0 0 0 0 8Z'],
  x: ['M6 6l12 12', 'M18 6 6 18'],
}

export function Icon({ name, size = 18, strokeWidth = 1.8 }: { name: IconName; size?: number; strokeWidth?: number }) {
  return (
    <svg aria-hidden="true" className="icon" width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={strokeWidth} strokeLinecap="round" strokeLinejoin="round">
      {iconPaths[name].map((path, index) => <path key={`${name}-${index}`} d={path} />)}
    </svg>
  )
}

export function Logo({ compact = false }: { compact?: boolean }) {
  return (
    <span className={`brand-lockup${compact ? ' brand-lockup-compact' : ''}`}>
      <img src={logoUrl} alt="" className="brand-mark" />
      <span className="brand-name">INTRIQO</span>
    </span>
  )
}

export function Button({ variant = 'primary', size = 'md', icon, children, className = '', ...props }: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: 'primary' | 'secondary' | 'ghost' | 'danger'; size?: 'sm' | 'md'; icon?: IconName }) {
  return (
    <button className={`button button-${variant} button-${size} ${className}`} {...props}>
      {icon && <Icon name={icon} size={size === 'sm' ? 15 : 17} />}
      {children}
    </button>
  )
}

export function Badge({ tone = 'neutral', children, className = '' }: { tone?: string; children: ReactNode; className?: string }) {
  return <span className={`badge badge-${tone.toLowerCase().replace(/\s+/g, '-')} ${className}`}>{children}</span>
}

export function SeverityBadge({ severity }: { severity: string | null | undefined }) {
  const value = severity?.toUpperCase() || 'UNKNOWN'
  const tone = value === 'CRITICAL' ? 'critical' : value === 'HIGH' ? 'high' : value === 'MEDIUM' ? 'medium' : value === 'LOW' ? 'low' : 'neutral'
  return <Badge tone={tone}><span className="severity-dot" />{value}</Badge>
}

export function StatusBadge({ status }: { status: string | null | undefined }) {
  const value = status?.replace(/_/g, ' ') || 'UNKNOWN'
  const tone = status === 'COMPLETED' || status === 'SUCCESS' || status === 'RESOLVED' || status === 'CLOSED' || status === 'INGESTED'
    ? 'success'
    : status === 'FAILED' || status === 'FAILURE' || status === 'CANCELLED' || status === 'FALSE_POSITIVE'
      ? 'danger'
      : status === 'IN_PROGRESS' || status === 'INVESTIGATING' || status === 'CONTAINED'
        ? 'info'
        : 'neutral'
  return <Badge tone={tone}>{value}</Badge>
}

export const Card = forwardRef<HTMLElement, HTMLAttributes<HTMLElement>>(
  ({ children, className = '', ...props }, ref) => (
    <section ref={ref} className={`card ${className}`} {...props}>{children}</section>
  )
)
Card.displayName = 'Card'

export function AuthMessage({ children, error = false }: { children: ReactNode; error?: boolean }) {
  return <div className={error ? 'form-error' : 'form-success'} role={error ? 'alert' : 'status'}><Icon name={error ? 'alert' : 'check'} size={16} /><span>{children}</span></div>
}

export function PageHeader({ eyebrow, title, description, actions }: { eyebrow?: string; title: string; description?: string; actions?: ReactNode }) {
  return (
    <div className="page-header">
      <div>
        {eyebrow && <p className="eyebrow">{eyebrow}</p>}
        <h1>{title}</h1>
        {description && <p className="page-description">{description}</p>}
      </div>
      {actions && <div className="page-actions">{actions}</div>}
    </div>
  )
}

export function SectionHeading({ title, description, action }: { title: string; description?: string; action?: ReactNode }) {
  return (
    <div className="section-heading">
      <div>
        <h2>{title}</h2>
        {description && <p>{description}</p>}
      </div>
      {action}
    </div>
  )
}

export function EmptyState({ icon = 'inbox', title, description, action }: { icon?: IconName | 'inbox'; title: string; description: string; action?: ReactNode }) {
  return (
    <div className="empty-state">
      <div className="empty-icon"><Icon name={icon === 'inbox' ? 'database' : icon} size={22} /></div>
      <h3>{title}</h3>
      <p>{description}</p>
      {action}
    </div>
  )
}

export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="error-state">
      <div className="empty-icon error-icon"><Icon name="alert" size={20} /></div>
      <div><strong>Unable to load this view</strong><p>{message}</p></div>
      {onRetry && <Button variant="secondary" size="sm" icon="refresh" onClick={onRetry}>Retry</Button>}
    </div>
  )
}

export function LoadingRows({ columns, rows = 5 }: { columns: number; rows?: number }) {
  return (
    <div className="table-skeleton" aria-label="Loading">
      {Array.from({ length: rows }, (_, row) => (
        <div className="skeleton-row" key={row}>{Array.from({ length: columns }, (_, column) => <span className="skeleton-line" key={column} />)}</div>
      ))}
    </div>
  )
}

export function TableFrame({ children }: { children: ReactNode }) {
  return <div className="table-frame"><div className="table-scroll">{children}</div></div>
}

export function Pagination({ page, hasNext, total, pageSize, onPageChange }: { page: number; hasNext: boolean; total: number; pageSize: number; onPageChange: (page: number) => void }) {
  const first = total === 0 ? 0 : (page - 1) * pageSize + 1
  const last = Math.min(page * pageSize, total)
  return (
    <div className="pagination">
      <span>Showing {first}–{last} of {total}</span>
      <div className="pagination-actions">
        <Button variant="ghost" size="sm" icon="chevron-left" disabled={page <= 1} aria-label="Previous page" onClick={() => onPageChange(page - 1)} />
        <span className="page-number">{page}</span>
        <Button variant="ghost" size="sm" icon="chevron-right" disabled={!hasNext} aria-label="Next page" onClick={() => onPageChange(page + 1)} />
      </div>
    </div>
  )
}

export function KeyValue({ label, value, mono = false }: { label: string; value: ReactNode; mono?: boolean }) {
  return <div className="key-value"><dt>{label}</dt><dd className={mono ? 'mono' : ''}>{value}</dd></div>
}

export function SeverityLegend() {
  const values: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
  return <div className="severity-legend">{values.map((value) => <span key={value}><SeverityBadge severity={value} /></span>)}</div>
}
