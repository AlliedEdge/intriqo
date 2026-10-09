/**
 * ArchitectureExplorer — Interactive React Flow system architecture canvas.
 *
 * Replaces the static "One workflow. Explicit boundaries." section.
 * Every node status is derived from real source-code evidence — see architectureData.ts.
 */

import React, { useCallback, useMemo, useRef, useState } from 'react'
import {
  ReactFlow,
  Background,
  BackgroundVariant,
  Controls,
  MiniMap,
  Handle,
  Position,
  getBezierPath,
  useReactFlow,
  ReactFlowProvider,
  type Edge,
  type Node,
  type NodeProps,
  type EdgeProps,
  type FitViewOptions,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import './ArchitectureExplorer.css'

import {
  ARCH_NODES,
  ARCH_EDGES,
  ARCH_GROUPS,
  STATUS_LABELS,
  STATUS_COLORS,
  LAYER_LABELS,
  LAYER_COLORS,
  computeArchStats,
  type ArchNodeData,
  type ImplementationStatus,
} from './architectureData'

// ─── Icon mini-renderer ───────────────────────────────────────────────────────

const ICON_PATHS: Record<string, string[]> = {
  network:    ['M12 3v5', 'M5 21v-5h14v5', 'M12 8 5 16', 'M12 8l7 8', 'M4 3h16'],
  sliders:    ['M4 6h6', 'M14 6h6', 'M4 12h10', 'M18 12h2', 'M4 18h2', 'M10 18h10', 'M10 4v4', 'M14 10v4', 'M6 16v4'],
  layers:     ['m12 3 9 5-9 5-9-5 9-5Z', 'm3 12 9 5 9-5', 'm3 16 9 5 9-5'],
  server:     ['M4 4h16v6H4z', 'M4 14h16v6H4z', 'M7 7h.01', 'M7 17h.01', 'M11 7h6', 'M11 17h6'],
  bot:        ['M8 9h8', 'M9 13h.01', 'M15 13h.01', 'M6 7h12a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V9a2 2 0 0 1 2-2Z', 'M12 3v4', 'M9 3h6'],
  shield:     ['M12 3 20 6v5c0 5-3.4 8.6-8 10-4.6-1.4-8-5-8-10V6l8-3Z', 'm9 12 2 2 4-4'],
  database:   ['M4 6c0 1.7 3.6 3 8 3s8-1.3 8-3-3.6-3-8-3-8 1.3-8 3Z', 'M4 6v6c0 1.7 3.6 3 8 3s8-1.3 8-3V6', 'M4 12v6c0 1.7 3.6 3 8 3s8-1.3 8-3v-6'],
  activity:   ['M3 12h4l2-7 4 14 2-7h6'],
  code:       ['m8 9-4 3 4 3', 'm16 9 4 3-4 3', 'm14 5-4 14'],
  terminal:   ['M4 5h16v14H4z', 'm7 9 3 3-3 3', 'M13 15h4'],
  grid:       ['M4 4h6v6H4z', 'M14 4h6v6h-6z', 'M4 14h6v6H4z', 'M14 14h6v6h-6z'],
  check:      ['m5 12 4 4L19 6'],
  x:          ['M6 6l12 12', 'M18 6 6 18'],
  search:     ['m21 21-4.3-4.3', 'M11 18a7 7 0 1 0 0-14 7 7 0 0 0 0 14Z'],
  filter:     ['M4 5h16', 'M7 12h10', 'M10 19h4'],
  'zoom-in':  ['M11 8v6', 'M8 11h6', 'M21 21l-4.3-4.3', 'M11 18a7 7 0 1 0 0-14 7 7 0 0 0 0 14Z'],
}

function SvgIcon({ name, size = 14, color = 'currentColor' }: { name: string; size?: number; color?: string }) {
  const paths = ICON_PATHS[name] ?? ICON_PATHS.grid
  return (
    <svg aria-hidden="true" width={size} height={size} viewBox="0 0 24 24"
      fill="none" stroke={color} strokeWidth={1.8} strokeLinecap="round" strokeLinejoin="round">
      {paths.map((d, i) => <path key={i} d={d} />)}
    </svg>
  )
}

// ─── Node data shape (must satisfy Record<string, unknown>) ──────────────────

type ArchNodeRecord = ArchNodeData & {
  selected?: boolean
  dimmed?: boolean
  [key: string]: unknown
}

// ─── Custom arch node ─────────────────────────────────────────────────────────

function ArchNode({ data }: NodeProps) {
  const d = data as ArchNodeRecord
  return (
    <div
      className={`arch-node status-${d.status}${d.selected ? ' is-selected' : ''}${d.dimmed ? ' is-dimmed' : ''}`}
      role="button"
      aria-label={`${d.label} — ${STATUS_LABELS[d.status as ImplementationStatus] ?? d.status}`}
      tabIndex={0}
    >
      <Handle type="target" position={Position.Left}   style={{ opacity: 0 }} />
      <Handle type="target" position={Position.Top}    style={{ opacity: 0 }} />
      <Handle type="source" position={Position.Right}  style={{ opacity: 0 }} />
      <Handle type="source" position={Position.Bottom} style={{ opacity: 0 }} />

      {d.verified && (
        <span className="arch-node-verified" title="Has passing tests">
          <SvgIcon name="check" size={10} />
        </span>
      )}

      <div className="arch-node-head">
        <span className="arch-node-icon-box">
          <SvgIcon name={d.icon as string} size={13} />
        </span>
        <span className="arch-node-badge">
          <span className="arch-node-badge-dot" />
          {STATUS_LABELS[d.status as ImplementationStatus] ?? String(d.status)}
        </span>
      </div>

      <span className="arch-node-label">
        {String(d.label)}
        <span className="arch-node-sublabel">{String(d.sublabel)}</span>
      </span>

      {d.tech && <span className="arch-node-tech">{String(d.tech)}</span>}
    </div>
  )
}

// ─── Group node ───────────────────────────────────────────────────────────────

function ArchGroupNode({ data }: NodeProps) {
  const d = data as { label: string; color: string }
  return (
    <div className="arch-group-node" style={{ width: '100%', height: '100%', borderColor: `${d.color}28` }}>
      <div className="arch-group-label" style={{ color: d.color }}>{d.label}</div>
    </div>
  )
}

// ─── Custom edge ──────────────────────────────────────────────────────────────

function ArchEdge({ id, sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition, data, markerEnd }: EdgeProps) {
  const status = ((data as Record<string, unknown>)?.status ?? 'unverified') as ImplementationStatus
  const [edgePath] = getBezierPath({ sourceX, sourceY, sourcePosition, targetX, targetY, targetPosition })

  const color =
    status === 'implemented'  ? '#45c994' :
    status === 'partial'      ? '#f4b740' :
    status === 'planned'      ? 'rgba(167,139,250,0.5)' :
    status === 'placeholder'  ? '#ea8535' :
    '#3a5060'

  return (
    <g>
      <path
        id={id}
        d={edgePath}
        fill="none"
        stroke={color}
        strokeWidth={status === 'implemented' ? 1.5 : 1.2}
        strokeDasharray={status === 'planned' || status === 'placeholder' ? '5 4' : undefined}
        markerEnd={markerEnd}
        style={{ opacity: status === 'planned' ? 0.55 : 0.85 }}
      />
    </g>
  )
}

// ─── Static nodeTypes / edgeTypes maps (defined outside component for stability) ──

const NODE_TYPES = {
  archNode:  ArchNode,
  archGroup: ArchGroupNode,
}

const EDGE_TYPES = {
  archEdge: ArchEdge,
}

// ─── Hand-placed layout positions ────────────────────────────────────────────

const NODE_POSITIONS: Record<string, { x: number; y: number }> = {
  // Network — col 0
  'live-capture':            { x:    0, y:   40 },
  'pcap-replay':             { x:    0, y:  200 },
  'synthetic-source':        { x:    0, y:  360 },
  // Engine parsing / flow — col 1
  'packet-parser':           { x:  210, y:  120 },
  'flow-table':              { x:  210, y:  280 },
  // Engine pipeline + detectors — col 2
  'pipeline':                { x:  410, y:   40 },
  'port-scan-detector':      { x:  410, y:  200 },
  'udp-scan-detector':       { x:  410, y:  340 },
  'syn-flood-detector':      { x:  410, y:  480 },
  'brute-force-detector':    { x:  410, y:  620 },
  'dns-anomaly-detector':    { x:  410, y:  760 },
  'feature-sink':            { x:  410, y:  900 },
  'http-event-sink':         { x:  410, y: 1040 },
  // Contracts — col 3
  'security-event-contract': { x:  620, y:  180 },
  'flow-feature-contract':   { x:  620, y:  900 },
  // Control Plane services — col 4
  'fastapi-server':          { x:  830, y:    0 },
  'auth-service':            { x:  830, y:  150 },
  'event-service':           { x:  830, y:  290 },
  'correlation-service':     { x:  830, y:  430 },
  'incident-service':        { x:  830, y:  570 },
  'task-service':            { x:  830, y:  710 },
  'audit-service':           { x:  830, y:  850 },
  'policy-engine':           { x:  830, y:  990 },
  'websocket':               { x:  830, y: 1130 },
  // Data stores — col 5
  'postgresql':              { x: 1040, y:  500 },
  'redis':                   { x: 1040, y:  680 },
  // ML pipeline — between CP and agents
  'ml-worker':               { x:  620, y: 1060 },
  'isolation-forest':        { x:  620, y: 1200 },
  'training-pipeline':       { x:  620, y: 1340 },
  // Agents — col 6
  'orchestrator':            { x: 1250, y:  130 },
  'investigation-agent':     { x: 1250, y:  280 },
  'threat-intel-agent':      { x: 1250, y:  430 },
  'correlation-agent':       { x: 1250, y:  580 },
  'response-agent':          { x: 1250, y:  730 },
  'llm-integration':         { x: 1250, y:  880 },
  // Frontend — col 7
  'soc-dashboard':           { x: 1460, y:   80 },
  'approvals-ui':            { x: 1460, y:  240 },
  // Infrastructure
  'prometheus':              { x: 1460, y:  450 },
}

// ─── View presets ─────────────────────────────────────────────────────────────

type ViewPreset = 'overview' | 'status' | 'roadmap' | 'data-flow'

const VIEW_PRESET_LABELS: Record<ViewPreset, string> = {
  'overview':  'Overview',
  'status':    'Status',
  'roadmap':   'Roadmap',
  'data-flow': 'Data Flow',
}

function getPresetIds(preset: ViewPreset): Set<string> | null {
  if (preset === 'status') return null
  if (preset === 'roadmap') {
    return new Set(ARCH_NODES.filter(n =>
      n.status === 'planned' || n.status === 'placeholder' || n.status === 'partial'
    ).map(n => n.id))
  }
  if (preset === 'data-flow') {
    return new Set([
      'live-capture', 'pcap-replay', 'synthetic-source',
      'packet-parser', 'flow-table', 'pipeline',
      'port-scan-detector', 'udp-scan-detector', 'syn-flood-detector',
      'http-event-sink', 'security-event-contract',
      'fastapi-server', 'event-service', 'correlation-service', 'postgresql',
      'feature-sink', 'flow-feature-contract', 'ml-worker', 'isolation-forest',
      'orchestrator', 'investigation-agent', 'soc-dashboard',
    ])
  }
  // 'overview' — key nodes only
  return new Set([
    'live-capture', 'packet-parser', 'pipeline',
    'port-scan-detector', 'syn-flood-detector',
    'http-event-sink', 'security-event-contract',
    'fastapi-server', 'event-service', 'correlation-service',
    'incident-service', 'task-service', 'audit-service',
    'postgresql', 'orchestrator', 'investigation-agent',
    'ml-worker', 'isolation-forest', 'soc-dashboard',
  ])
}

// ─── Edge builder (pure function, safe outside hooks) ────────────────────────

function buildEdges(visibleIds: Set<string> | null, selectedId: string | null): Edge[] {
  return ARCH_EDGES
    .filter(e => !visibleIds || (visibleIds.has(e.source) && visibleIds.has(e.target)))
    .map(e => {
      const isConnected = selectedId !== null && (e.source === selectedId || e.target === selectedId)
      const isDimmed    = selectedId !== null && !isConnected
      const color =
        e.status === 'implemented'  ? '#45c994' :
        e.status === 'partial'      ? '#f4b740' :
        e.status === 'planned'      ? 'rgba(167,139,250,0.45)' :
        e.status === 'placeholder'  ? '#ea8535' :
        '#3a5060'
      return {
        id: e.id,
        source: e.source,
        target: e.target,
        type: 'archEdge',
        animated: e.status === 'implemented' && e.animated !== false,
        data: { status: e.status },
        style: { opacity: isDimmed ? 0.07 : 1, stroke: color },
        markerEnd: { type: 'arrowclosed' as const, width: 8, height: 8, color },
      }
    })
}

// ─── Progress bar ─────────────────────────────────────────────────────────────

function ProgressBar() {
  const stats = useMemo(() => computeArchStats(ARCH_NODES), [])
  const items: { status: ImplementationStatus; label: string }[] = [
    { status: 'implemented', label: 'Implemented' },
    { status: 'partial',     label: 'Partial' },
    { status: 'planned',     label: 'Planned' },
    { status: 'placeholder', label: 'Placeholder' },
  ]
  return (
    <div className="arch-progress-bar" role="region" aria-label="Architecture implementation coverage">
      <div className="arch-progress-coverage">
        <span className="arch-progress-coverage-label">Component coverage</span>
        <div className="arch-progress-track">
          <div className="arch-progress-fill" style={{ width: `${stats.coverage}%` }} />
        </div>
        <span className="arch-progress-coverage-value">{stats.coverage}% coverage</span>
      </div>
      <div className="arch-stat-divider" aria-hidden="true" />
      {items.map(item => (
        <div key={item.status} className="arch-stat">
          <span className="arch-stat-dot" style={{ background: STATUS_COLORS[item.status].dot }} />
          <span className="arch-stat-count">{stats.byStatus[item.status]}</span>
          <span className="arch-stat-label">{item.label}</span>
        </div>
      ))}
      <span className="arch-total-count">{stats.total} components</span>
    </div>
  )
}

// ─── Detail panel ─────────────────────────────────────────────────────────────

function DetailPanel({ node, onClose }: { node: ArchNodeData; onClose: () => void }) {
  const sc = STATUS_COLORS[node.status]
  return (
    <div className="arch-detail-panel" role="dialog" aria-label={`${node.label} details`}>
      <div className="arch-detail-head">
        <div className="arch-detail-head-left">
          <span className="arch-detail-icon" style={{ background: sc.bg, borderColor: sc.border, color: sc.text }}>
            <SvgIcon name={node.icon} size={15} />
          </span>
          <div>
            <div className="arch-detail-title">{node.label}</div>
            <span className="arch-detail-sublabel">{node.sublabel}</span>
          </div>
        </div>
        <button className="arch-detail-close" onClick={onClose} aria-label="Close detail panel" type="button">
          <SvgIcon name="x" size={13} />
        </button>
      </div>

      <div className="arch-detail-body">
        {/* Badges */}
        <div className="arch-detail-section">
          <div className="arch-detail-badge-row">
            <span className="arch-detail-badge" style={{ background: sc.bg, borderColor: sc.border, color: sc.text }}>
              <span style={{ width: 5, height: 5, borderRadius: '50%', background: sc.dot, display: 'inline-block' }} />
              {STATUS_LABELS[node.status]}
            </span>
            <span className="arch-detail-badge layer">{LAYER_LABELS[node.layer]}</span>
            <span className="arch-detail-badge type">{node.nodeType}</span>
            {node.verified && (
              <span className="arch-detail-badge verified"><SvgIcon name="check" size={10} /> Tested</span>
            )}
          </div>
        </div>

        <div className="arch-detail-section">
          <div className="arch-detail-section-title">Responsibility</div>
          <p className="arch-detail-text">{node.description}</p>
        </div>

        <div className="arch-detail-section">
          <div className="arch-detail-section-title">What exists</div>
          <p className={`arch-detail-text${node.status === 'planned' ? ' is-planned' : ''}`}>{node.exists}</p>
        </div>

        {node.missing && (
          <div className="arch-detail-section">
            <div className="arch-detail-section-title">Remaining work</div>
            <p className="arch-detail-text is-warning">{node.missing}</p>
          </div>
        )}

        {node.interfaces && (
          <div className="arch-detail-section">
            <div className="arch-detail-section-title">Interface / Contract</div>
            <p className="arch-detail-text">{node.interfaces}</p>
          </div>
        )}

        {node.limitations && (
          <div className="arch-detail-section">
            <div className="arch-detail-section-title">Known limitations</div>
            <div className="arch-detail-note warning">{node.limitations}</div>
          </div>
        )}

        {node.tech && (
          <div className="arch-detail-section">
            <div className="arch-detail-section-title">Technology</div>
            <p className="arch-detail-text">{node.tech}</p>
          </div>
        )}

        {node.evidence.files.length > 0 && (
          <div className="arch-detail-section">
            <div className="arch-detail-section-title">Source files</div>
            <div className="arch-detail-files">
              {node.evidence.files.map(f => (
                <div key={f} className="arch-detail-file">
                  <span className="arch-detail-file-icon"><SvgIcon name="code" size={11} /></span>
                  {f}
                </div>
              ))}
            </div>
          </div>
        )}

        {node.evidence.tests && node.evidence.tests.length > 0 && (
          <div className="arch-detail-section">
            <div className="arch-detail-section-title">Tests</div>
            <div className="arch-detail-files">
              {node.evidence.tests.map(t => (
                <div key={t} className="arch-detail-file">
                  <span className="arch-detail-file-icon"><SvgIcon name="check" size={11} /></span>
                  {t}
                </div>
              ))}
            </div>
          </div>
        )}

        {node.evidence.note && (
          <div className="arch-detail-section">
            <div className="arch-detail-note info">{node.evidence.note}</div>
          </div>
        )}
      </div>
    </div>
  )
}

// ─── Main canvas (inside ReactFlowProvider) ───────────────────────────────────

const FIT_VIEW_OPTS: FitViewOptions = { padding: 0.12, duration: 600 }

function CanvasInner() {
  const { fitView } = useReactFlow()

  const [selectedId,   setSelectedId]   = useState<string | null>(null)
  const [search,       setSearch]       = useState('')
  const [statusFilter, setStatusFilter] = useState<ImplementationStatus | null>(null)
  const [viewPreset,   setViewPreset]   = useState<ViewPreset>('overview')
  const [showPlanned,  setShowPlanned]  = useState(true)
  const searchRef = useRef<HTMLInputElement>(null)

  // Which nodes pass all active filters
  const filteredIds = useMemo<Set<string> | null>(() => {
    const presetSet = getPresetIds(viewPreset)

    const passing = ARCH_NODES.filter(n => {
      if (!showPlanned && n.status === 'planned') return false
      if (statusFilter && n.status !== statusFilter) return false
      const q = search.trim().toLowerCase()
      if (q) {
        return (
          n.label.toLowerCase().includes(q) ||
          n.sublabel.toLowerCase().includes(q) ||
          n.description.toLowerCase().includes(q) ||
          n.layer.toLowerCase().includes(q) ||
          (n.tech ?? '').toLowerCase().includes(q)
        )
      }
      return true
    }).filter(n => !presetSet || presetSet.has(n.id)).map(n => n.id)

    return passing.length === ARCH_NODES.length ? null : new Set(passing)
  }, [search, statusFilter, viewPreset, showPlanned])

  // Connected nodes for selection dimming
  const connectedIds = useMemo(() => {
    const set = new Set<string>()
    if (!selectedId) return set
    set.add(selectedId)
    ARCH_EDGES.forEach(e => {
      if (e.source === selectedId) set.add(e.target)
      if (e.target === selectedId) set.add(e.source)
    })
    return set
  }, [selectedId])

  // Build nodes for React Flow
  const rfNodes: Node[] = useMemo(() => {
    const hasSelection = selectedId !== null
    return ARCH_NODES
      .filter(n => !filteredIds || filteredIds.has(n.id))
      .map(n => ({
        id:       n.id,
        type:     'archNode',
        position: NODE_POSITIONS[n.id] ?? { x: 0, y: 0 },
        data:     {
          ...n,
          selected: n.id === selectedId,
          dimmed:   hasSelection && !connectedIds.has(n.id),
        } as Record<string, unknown>,
        draggable: false,
      }))
  }, [filteredIds, selectedId, connectedIds])

  // Build group background nodes
  const rfGroups: Node[] = useMemo(() => {
    return ARCH_GROUPS.flatMap(g => {
      const memberPos = g.nodeIds
        .filter(id => !filteredIds || filteredIds.has(id))
        .map(id => NODE_POSITIONS[id])
        .filter((p): p is { x: number; y: number } => p !== undefined)
      if (memberPos.length === 0) return []
      const xs = memberPos.map(p => p.x)
      const ys = memberPos.map(p => p.y)
      const minX = Math.min(...xs) - 16
      const minY = Math.min(...ys) - 28
      const maxX = Math.max(...xs) + 194
      const maxY = Math.max(...ys) + 140
      return [{
        id:        g.id,
        type:      'archGroup',
        position:  { x: minX, y: minY },
        style:     { width: maxX - minX, height: maxY - minY },
        data:      { label: g.label, color: LAYER_COLORS[g.layer] } as Record<string, unknown>,
        draggable:  false,
        selectable: false,
        zIndex:    -1,
      }] satisfies Node[]
    })
  }, [filteredIds])

  const allNodes = useMemo(() => [...rfGroups, ...rfNodes], [rfGroups, rfNodes])
  const rfEdges  = useMemo(() => buildEdges(filteredIds, selectedId), [filteredIds, selectedId])

  const handleNodeClick = useCallback((_: React.MouseEvent, node: Node) => {
    if (node.type === 'archGroup') return
    setSelectedId(prev => prev === node.id ? null : node.id)
  }, [])

  const handlePaneClick = useCallback(() => setSelectedId(null), [])

  const handleKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (e.key === 'Escape') {
      setSelectedId(null)
      setSearch('')
      setStatusFilter(null)
    }
  }, [])

  const resetFilters = useCallback(() => {
    setSearch('')
    setStatusFilter(null)
    setShowPlanned(true)
    setViewPreset('overview')
    setSelectedId(null)
    setTimeout(() => fitView(FIT_VIEW_OPTS), 80)
  }, [fitView])

  const hasActiveFilters =
    search.trim() !== '' || statusFilter !== null || !showPlanned || viewPreset !== 'overview'

  const selectedNode = selectedId ? ARCH_NODES.find(n => n.id === selectedId) : null

  const statusFilterOpts: ImplementationStatus[] = ['implemented', 'partial', 'planned', 'placeholder']

  return (
    <div onKeyDown={handleKeyDown}>
      <ProgressBar />

      {/* Controls toolbar */}
      <div className="arch-controls" role="toolbar" aria-label="Architecture explorer controls">
        {/* Search */}
        <div className="arch-search-wrap">
          <span className="arch-search-icon"><SvgIcon name="search" size={13} /></span>
          <input
            ref={searchRef}
            type="search"
            className="arch-search-input"
            placeholder="Search components…"
            value={search}
            onChange={e => { setSearch(e.target.value); setViewPreset('status') }}
            aria-label="Search architecture components"
          />
        </div>

        <div className="arch-controls-divider" aria-hidden="true" />

        {/* Status filters */}
        {statusFilterOpts.map(s => (
          <button
            key={s}
            type="button"
            className={`arch-filter-btn${statusFilter === s ? ' is-active' : ''}`}
            onClick={() => { setStatusFilter(prev => prev === s ? null : s); setViewPreset('status') }}
            aria-pressed={statusFilter === s}
          >
            <span className="arch-filter-dot" style={{ background: STATUS_COLORS[s].dot }} />
            {STATUS_LABELS[s]}
          </button>
        ))}

        <div className="arch-controls-divider" aria-hidden="true" />

        <button
          type="button"
          className={`arch-filter-btn${!showPlanned ? ' is-active' : ''}`}
          onClick={() => setShowPlanned(p => !p)}
          aria-pressed={!showPlanned}
        >
          Hide planned
        </button>

        {hasActiveFilters && (
          <button
            type="button"
            className="arch-filter-btn-reset"
            onClick={resetFilters}
            aria-label="Reset all filters"
          >
            <SvgIcon name="x" size={12} />
            Reset
          </button>
        )}

        {/* View presets */}
        <div className="arch-view-group" role="group" aria-label="View presets">
          {(Object.keys(VIEW_PRESET_LABELS) as ViewPreset[]).map(p => (
            <button
              key={p}
              type="button"
              className={`arch-view-btn${viewPreset === p ? ' is-active' : ''}`}
              onClick={() => {
                setViewPreset(p)
                setSearch('')
                setStatusFilter(null)
                setTimeout(() => fitView(FIT_VIEW_OPTS), 80)
              }}
              aria-pressed={viewPreset === p}
            >
              {VIEW_PRESET_LABELS[p]}
            </button>
          ))}
          <button
            type="button"
            className="arch-view-btn"
            onClick={() => fitView(FIT_VIEW_OPTS)}
            aria-label="Fit view"
            title="Fit view"
          >
            <SvgIcon name="zoom-in" size={13} />
          </button>
        </div>
      </div>

      {/* Canvas */}
      <div className="arch-canvas-wrap">
        <ReactFlow
          nodes={allNodes}
          edges={rfEdges}
          nodeTypes={NODE_TYPES}
          edgeTypes={EDGE_TYPES}
          onNodeClick={handleNodeClick}
          onPaneClick={handlePaneClick}
          fitView
          fitViewOptions={FIT_VIEW_OPTS}
          minZoom={0.1}
          maxZoom={2}
          proOptions={{ hideAttribution: true }}
          panOnScroll={false}
          zoomOnScroll
          zoomOnPinch
          nodesDraggable={false}
          nodesConnectable={false}
          elementsSelectable
          selectNodesOnDrag={false}
        >
          <Background variant={BackgroundVariant.Dots} gap={22} size={1} color="rgba(16,187,224,0.08)" />
          <Controls showInteractive={false} />
          <MiniMap
            nodeColor={node => {
              const d = node.data as { status?: ImplementationStatus }
              return d.status ? (STATUS_COLORS[d.status]?.dot ?? '#3a5060') : '#3a5060'
            }}
            maskColor="rgba(5,9,15,0.75)"
            nodeStrokeWidth={0}
            style={{ width: 140, height: 90 }}
          />
        </ReactFlow>

        {/* Empty state */}
        {rfNodes.length === 0 && (
          <div className="arch-empty-state" aria-live="polite">
            <span className="arch-empty-icon"><SvgIcon name="filter" size={18} /></span>
            <span>No components match the current filters.</span>
            <button type="button" className="arch-filter-btn" onClick={resetFilters} style={{ pointerEvents: 'all' }}>
              Reset filters
            </button>
          </div>
        )}

        {/* Detail panel */}
        {selectedNode && <DetailPanel node={selectedNode} onClose={() => setSelectedId(null)} />}
      </div>

      {/* Legend */}
      <div className="arch-legend" aria-label="Legend">
        <span className="arch-legend-title">Legend</span>
        {(Object.keys(STATUS_LABELS) as ImplementationStatus[]).map(s => (
          <span key={s} className="arch-legend-item">
            <span className={`arch-legend-swatch ${s}`} />
            {STATUS_LABELS[s]}
          </span>
        ))}
        <span className="arch-legend-item"><span className="arch-legend-edge-impl" aria-hidden="true" /> Implemented path</span>
        <span className="arch-legend-item"><span className="arch-legend-edge-planned" aria-hidden="true" /> Planned path</span>
      </div>

      <p className="arch-kbd-hint">
        Click a node to inspect it · <kbd>Esc</kbd> to deselect · scroll or pinch to zoom
      </p>
    </div>
  )
}

// ─── Public export ────────────────────────────────────────────────────────────

export function ArchitectureExplorer() {
  return (
    <section id="architecture" className="arch-explorer-section">
      <div className="arch-explorer-inner">
        <div className="arch-header">
          <div className="arch-header-copy">
            <p className="eyebrow">CONTROL PLANE / INVESTIGATION</p>
            <h2>One workflow. Explicit boundaries.</h2>
            <p>
              Intriqo keeps detection, persistence, investigation, policy, and auditability
              visible as separate, inspectable stages. Click any component to see what's
              implemented, what's remaining, and how it connects to the rest of the system.
            </p>
          </div>
        </div>

        <ReactFlowProvider>
          <CanvasInner />
        </ReactFlowProvider>
      </div>
    </section>
  )
}
