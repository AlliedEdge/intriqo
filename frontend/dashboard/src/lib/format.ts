import type { Finding } from '@/types/api'

export function formatDate(value: string | null | undefined, withSeconds = false): string {
  if (!value) return '—'

  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return '—'

  return new Intl.DateTimeFormat('en-US', {
    month: 'short',
    day: '2-digit',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    ...(withSeconds ? { second: '2-digit' } : {}),
    hour12: false,
  }).format(date)
}

export function formatDateOnly(value: string | null | undefined): string {
  if (!value) return '—'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return '—'

  return new Intl.DateTimeFormat('en-US', {
    month: 'short',
    day: '2-digit',
    year: 'numeric',
  }).format(date)
}

export function relativeTime(value: string | null | undefined): string {
  if (!value) return '—'
  const timestamp = new Date(value).getTime()
  if (Number.isNaN(timestamp)) return '—'

  const deltaSeconds = Math.round((timestamp - Date.now()) / 1000)
  const absoluteSeconds = Math.abs(deltaSeconds)
  const formatter = new Intl.RelativeTimeFormat('en', { numeric: 'auto' })

  if (absoluteSeconds < 60) return formatter.format(deltaSeconds, 'second')
  const minutes = Math.round(deltaSeconds / 60)
  if (Math.abs(minutes) < 60) return formatter.format(minutes, 'minute')
  const hours = Math.round(deltaSeconds / 3600)
  if (Math.abs(hours) < 24) return formatter.format(hours, 'hour')
  return formatter.format(Math.round(deltaSeconds / 86400), 'day')
}

export function shortId(value: string | null | undefined, length = 8): string {
  if (!value) return '—'
  return value.length > length ? `${value.slice(0, length)}…` : value
}

export function truncate(value: string | null | undefined, length = 72): string {
  if (!value) return '—'
  return value.length > length ? `${value.slice(0, length - 1)}…` : value
}

export function prettyJson(value: unknown): string {
  return JSON.stringify(value, null, 2)
}

export function findingSeverity(finding: Finding): string | null {
  const candidate = finding.severity ?? finding.finding_metadata.severity
  return typeof candidate === 'string' ? candidate : null
}

export function initials(value: string): string {
  return value
    .split(/\s+|[._-]/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0]?.toUpperCase() ?? '')
    .join('') || 'IN'
}

export function toIsoDateTime(value: string): string | undefined {
  if (!value) return undefined
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? undefined : date.toISOString()
}
