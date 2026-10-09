/**
 * Intriqo Architecture Data Model
 *
 * Evidence-backed implementation status for every meaningful component.
 * Statuses are derived from direct source code inspection — not README claims.
 *
 * Update this file when a component's implementation state changes.
 */

// ─── Types ───────────────────────────────────────────────────────────────────

export type ImplementationStatus =
  | 'implemented'       // Exists and is wired end-to-end
  | 'partial'           // Some functionality exists; meaningful work remains
  | 'planned'           // Documented in architecture; not yet implemented
  | 'placeholder'       // Scaffold exists but logic is explicitly stubbed
  | 'unverified'        // Cannot establish implementation state confidently

export type ArchLayer =
  | 'network'           // Raw traffic sources
  | 'engine'            // C++ IDS engine
  | 'transport'         // Event/feature transport contracts
  | 'control-plane'     // Python FastAPI + PostgreSQL
  | 'agents'            // Autonomous investigation agents
  | 'ml'                // Machine learning pipeline
  | 'frontend'          // React SOC dashboard
  | 'infrastructure'    // Deployment services

export type NodeType =
  | 'source'
  | 'process'
  | 'database'
  | 'api'
  | 'agent'
  | 'model'
  | 'interface'
  | 'service'

export interface ArchEvidence {
  files: string[]
  tests?: string[]
  note?: string
}

export interface ArchNodeData {
  id: string
  label: string
  sublabel: string
  description: string
  layer: ArchLayer
  nodeType: NodeType
  status: ImplementationStatus
  icon: 'network' | 'sliders' | 'layers' | 'server' | 'bot' | 'shield' | 'database' | 'activity' | 'code' | 'terminal' | 'grid'
  tech?: string
  evidence: ArchEvidence
  exists: string        // What currently exists
  missing?: string      // What is missing / remaining
  interfaces?: string   // Interfaces / contracts / protocols
  limitations?: string  // Known gaps or incomplete integrations
  verified?: boolean    // Has passing tests that exercise real behavior
}

export interface ArchEdgeData {
  id: string
  source: string
  target: string
  label?: string
  protocol?: string
  status: ImplementationStatus
  animated?: boolean
}

export interface ArchGroup {
  id: string
  label: string
  layer: ArchLayer
  nodeIds: string[]
  description: string
}

// ─── Nodes ───────────────────────────────────────────────────────────────────

export const ARCH_NODES: ArchNodeData[] = [
  // ── Network sources ──────────────────────────────────────────────────────
  {
    id: 'live-capture',
    label: 'Live Capture',
    sublabel: 'AF_PACKET / libpcap',
    description: 'Captures live packets from a network interface via raw sockets or libpcap.',
    layer: 'network',
    nodeType: 'source',
    status: 'implemented',
    icon: 'network',
    tech: 'C++20 · AF_PACKET',
    evidence: {
      files: ['engine/src/capture/live_source.cpp'],
      note: 'Implemented; requires libpcap + elevated privileges. Not exercised in host env without libpcap.',
    },
    exists: 'live_source.cpp with full AF_PACKET / PCAP capture path.',
    missing: 'Host requires libpcap and privileges; not exercised in current dev environment.',
    interfaces: 'Produces ParsedPacket → PipelineImpl::ingest()',
    verified: false,
  },
  {
    id: 'pcap-replay',
    label: 'PCAP Replay',
    sublabel: 'Offline fixture playback',
    description: 'Replays pre-recorded .pcap files at configurable speed for deterministic testing.',
    layer: 'network',
    nodeType: 'source',
    status: 'implemented',
    icon: 'terminal',
    tech: 'C++20 · libpcap',
    evidence: {
      files: ['engine/src/capture/pcap_source.cpp'],
      tests: ['engine/tests/'],
    },
    exists: 'pcap_source.cpp fully implemented; used in engine integration tests.',
    interfaces: 'Produces ParsedPacket → PipelineImpl::ingest()',
    verified: true,
  },
  {
    id: 'synthetic-source',
    label: 'Synthetic Traffic',
    sublabel: 'Controlled test fixtures',
    description: 'Generates deterministic synthetic packet sequences for unit and integration tests.',
    layer: 'network',
    nodeType: 'source',
    status: 'implemented',
    icon: 'code',
    tech: 'C++20',
    evidence: {
      files: ['engine/src/capture/synthetic_source.cpp'],
      tests: ['engine/tests/'],
    },
    exists: 'synthetic_source.cpp generating deterministic flows for all detector tests.',
    interfaces: 'Produces ParsedPacket → PipelineImpl::ingest()',
    verified: true,
  },

  // ── C++ IDS Engine ────────────────────────────────────────────────────────
  {
    id: 'packet-parser',
    label: 'Packet Parser',
    sublabel: 'IPv4 / TCP / UDP / ICMP',
    description: 'Parses raw bytes into ParsedPacket structs: validates headers, extracts 5-tuple, timestamps.',
    layer: 'engine',
    nodeType: 'process',
    status: 'implemented',
    icon: 'layers',
    tech: 'C++20',
    evidence: {
      files: ['engine/src/capture/parser.cpp'],
      tests: ['engine/tests/test_parser.cpp'],
    },
    exists: 'Full IPv4/TCP/UDP/ICMP parsing with validation.',
    interfaces: 'Input: raw bytes. Output: ParsedPacket with 5-tuple + timestamps.',
    verified: true,
  },
  {
    id: 'flow-table',
    label: 'Flow Table',
    sublabel: 'Bidirectional flow tracking',
    description: 'Tracks bidirectional network flows with bounded capacity, idle expiry, and eviction.',
    layer: 'engine',
    nodeType: 'process',
    status: 'implemented',
    icon: 'grid',
    tech: 'C++20',
    evidence: {
      files: ['engine/src/flow/flow_table.cpp'],
      tests: ['engine/tests/test_flow_table.cpp'],
    },
    exists: 'Bounded flow table with idle-expiry, capacity eviction, and statistics counters.',
    interfaces: 'Input: ParsedPacket. Output: FlowUpdate (new/expired/evicted flows) → detectors.',
    verified: true,
  },
  {
    id: 'pipeline',
    label: 'Detection Pipeline',
    sublabel: 'Ingest → detect → export',
    description: 'Orchestrates the full per-packet path: flow update → detector evaluation → feature export.',
    layer: 'engine',
    nodeType: 'process',
    status: 'implemented',
    icon: 'sliders',
    tech: 'C++20',
    evidence: {
      files: ['engine/src/pipeline/pipeline_impl.cpp'],
      tests: ['engine/tests/'],
    },
    exists: 'PipelineImpl with ingest, flush, maintain, statistics, and feature export paths.',
    interfaces: 'Coordinates flow table, detector registry, event callback, and feature sink.',
    verified: true,
  },
  {
    id: 'port-scan-detector',
    label: 'PORT_SCAN Detector',
    sublabel: 'Stateful TCP port-scan detection',
    description: 'Detects TCP port scans using a configurable time-window, unique-port threshold, and attempt count.',
    layer: 'engine',
    nodeType: 'process',
    status: 'implemented',
    icon: 'shield',
    tech: 'C++20',
    evidence: {
      files: ['engine/src/detection/port_scan_detector.cpp'],
      tests: ['engine/tests/test_port_scan_detector.cpp'],
    },
    exists: 'Full stateful window-based detection; thread-safe; bounded state.',
    interfaces: 'Emits PORT_SCAN SecurityEvent JSON on threshold breach.',
    verified: true,
  },
  {
    id: 'udp-scan-detector',
    label: 'UDP_SCAN Detector',
    sublabel: 'UDP port-scan detection',
    description: 'Reuses PortScanDetector with Protocol::UDP to detect UDP port scanning.',
    layer: 'engine',
    nodeType: 'process',
    status: 'implemented',
    icon: 'shield',
    tech: 'C++20',
    evidence: {
      files: ['engine/src/detection/port_scan_detector.cpp'],
      note: 'Shares implementation with PORT_SCAN; differentiated by protocol config.',
    },
    exists: 'UDP variant reusing PortScanDetector with Protocol::UDP.',
    interfaces: 'Emits UDP_SCAN SecurityEvent JSON.',
    verified: true,
  },
  {
    id: 'syn-flood-detector',
    label: 'SYN_FLOOD Detector',
    sublabel: 'TCP SYN flood detection',
    description: 'Detects TCP SYN flood attacks by tracking SYN rate per source within a sliding window.',
    layer: 'engine',
    nodeType: 'process',
    status: 'implemented',
    icon: 'shield',
    tech: 'C++20',
    evidence: {
      files: ['engine/src/detection/syn_flood_detector.cpp'],
      tests: ['engine/tests/test_syn_flood_detector.cpp'],
    },
    exists: 'Full stateful SYN flood detection with configurable thresholds.',
    interfaces: 'Emits SYN_FLOOD SecurityEvent JSON.',
    verified: true,
  },
  {
    id: 'brute-force-detector',
    label: 'BRUTE_FORCE Detector',
    sublabel: 'Credential brute-force detection',
    description: 'Planned detector for identifying repeated authentication failures targeting the same destination.',
    layer: 'engine',
    nodeType: 'process',
    status: 'planned',
    icon: 'shield',
    tech: 'C++20',
    evidence: {
      files: [],
      note: 'BRUTE_FORCE referenced in security_event_v1.json contract examples; no source in engine/src/.',
    },
    exists: 'Not implemented. Event type referenced in contract schema as a future type.',
    missing: 'Full detector implementation needed.',
  },
  {
    id: 'dns-anomaly-detector',
    label: 'DNS Anomaly Detector',
    sublabel: 'DNS-based anomaly detection',
    description: 'Planned detector for DNS tunneling, exfiltration, and anomalous query patterns.',
    layer: 'engine',
    nodeType: 'process',
    status: 'planned',
    icon: 'shield',
    tech: 'C++20',
    evidence: {
      files: [],
      note: 'DNS_ANOMALY referenced in security_event_v1.json contract; not in engine/src/.',
    },
    exists: 'Not implemented.',
    missing: 'Full detector implementation needed.',
  },
  {
    id: 'feature-sink',
    label: 'Feature Sink',
    sublabel: 'FlowFeatureRecord → JSONL',
    description: 'Exports per-flow feature records (v1/v2) as JSONL for the ML pipeline.',
    layer: 'engine',
    nodeType: 'process',
    status: 'implemented',
    icon: 'activity',
    tech: 'C++20 · JSONL',
    evidence: {
      files: ['engine/src/transport/flow_feature_sink.cpp'],
      tests: ['engine/tests/'],
    },
    exists: 'FlowFeatureSink writing v1 and v2 records; bounded worker queue; flush on shutdown.',
    interfaces: 'Outputs JSONL file consumed by ml/src/consumer.py.',
    verified: true,
  },
  {
    id: 'http-event-sink',
    label: 'HTTP Event Sink',
    sublabel: 'SecurityEvent → Control Plane',
    description: 'Sends SecurityEvent JSON to the control plane via plain HTTP POST using a raw POSIX socket.',
    layer: 'engine',
    nodeType: 'process',
    status: 'implemented',
    icon: 'server',
    tech: 'C++20 · HTTP/1.1',
    evidence: {
      files: ['engine/src/transport/event_sink.cpp'],
      note: 'Plain HTTP only (no TLS); synchronous POST per event.',
    },
    exists: 'Raw POSIX socket HTTP POST; synchronous; no TLS.',
    limitations: 'Plain HTTP only; synchronous per-event; no retry queue.',
    interfaces: 'Posts SecurityEvent JSON to POST /api/v1/events.',
    verified: true,
  },

  // ── Transport / Contracts ─────────────────────────────────────────────────
  {
    id: 'security-event-contract',
    label: 'SecurityEvent Contract',
    sublabel: 'JSON Schema v1',
    description: 'Versioned JSON Schema defining the canonical cross-boundary SecurityEvent format.',
    layer: 'transport',
    nodeType: 'interface',
    status: 'implemented',
    icon: 'layers',
    tech: 'JSON Schema draft-07',
    evidence: {
      files: ['contracts/events/security_event_v1.json'],
    },
    exists: 'Fully specified: event_id, event_type, severity, timestamp, addresses, description, details.',
    interfaces: 'Used by C++ engine emitter and Python control plane validator.',
    verified: true,
  },
  {
    id: 'flow-feature-contract',
    label: 'FlowFeature Contract',
    sublabel: 'JSONL schema v1/v2',
    description: 'Versioned schema for per-flow feature records exported by the engine for ML inference.',
    layer: 'transport',
    nodeType: 'interface',
    status: 'implemented',
    icon: 'layers',
    tech: 'JSON Schema · JSONL',
    evidence: {
      files: ['contracts/features/flow_features_v1.json', 'contracts/features/flow_features_v2.json'],
    },
    exists: 'Two versioned schemas; used by C++ feature sink and Python ML consumer.',
    interfaces: 'Engine writes JSONL; ML worker reads and validates on ingestion.',
    verified: true,
  },

  // ── Control Plane ─────────────────────────────────────────────────────────
  {
    id: 'fastapi-server',
    label: 'FastAPI Server',
    sublabel: 'REST API · Python 3.10+',
    description: 'FastAPI application exposing authenticated REST endpoints for events, incidents, tasks, findings, and audit.',
    layer: 'control-plane',
    nodeType: 'api',
    status: 'implemented',
    icon: 'server',
    tech: 'Python · FastAPI · Uvicorn',
    evidence: {
      files: [
        'control-plane/src/intriqo/api/v1/events.py',
        'control-plane/src/intriqo/api/v1/incidents.py',
        'control-plane/src/intriqo/api/v1/agent_tasks.py',
        'control-plane/src/intriqo/api/v1/findings.py',
        'control-plane/src/intriqo/api/v1/audit.py',
        'control-plane/src/intriqo/api/v1/auth.py',
      ],
      tests: ['control-plane/tests/'],
    },
    exists: '6 API modules; all CRUD operations; JWT auth on all routes.',
    interfaces: 'REST API at /api/v1/; consumed by engine HTTP sink, agents, and React dashboard.',
    verified: true,
  },
  {
    id: 'auth-service',
    label: 'Auth / RBAC',
    sublabel: 'JWT · Roles · Email verify',
    description: 'JWT authentication with role-based access control (ANALYST, ADMIN) and email verification.',
    layer: 'control-plane',
    nodeType: 'service',
    status: 'implemented',
    icon: 'shield',
    tech: 'Python · JWT · RBAC',
    evidence: {
      files: ['control-plane/src/intriqo/auth/service.py', 'control-plane/src/intriqo/auth/dependencies.py'],
      tests: ['control-plane/tests/test_rbac.py'],
    },
    exists: 'Full auth service: JWT, RBAC, email verification, password reset.',
    interfaces: 'Dependency-injected into all API routes.',
    verified: true,
  },
  {
    id: 'event-service',
    label: 'Event Ingestion',
    sublabel: 'Validate · deduplicate · persist',
    description: 'Validates incoming SecurityEvents, deduplicates by event_id, persists to PostgreSQL, triggers correlation.',
    layer: 'control-plane',
    nodeType: 'service',
    status: 'implemented',
    icon: 'activity',
    tech: 'Python · SQLAlchemy',
    evidence: {
      files: ['control-plane/src/intriqo/services/event_service.py'],
      tests: ['control-plane/tests/'],
    },
    exists: 'Deduplication (duplicate_event_id guard), ORM persistence, correlation trigger, audit record.',
    interfaces: 'Input: SecurityEventCreate schema. Output: persisted SecurityEvent ORM.',
    verified: true,
  },
  {
    id: 'correlation-service',
    label: 'Correlation Engine',
    sublabel: 'Deterministic event→incident',
    description: 'Groups PORT_SCAN, UDP_SCAN, SYN_FLOOD events into incidents using a 5-minute window and PG advisory locks.',
    layer: 'control-plane',
    nodeType: 'service',
    status: 'implemented',
    icon: 'layers',
    tech: 'Python · PostgreSQL advisory locks',
    evidence: {
      files: ['control-plane/src/intriqo/services/correlation_service.py'],
      tests: ['control-plane/tests/'],
    },
    exists: 'Window-based correlation with advisory lock serialization. ML_ANOMALY events use analyst-link path only.',
    interfaces: 'Called by event_service after persistence; links event to existing or new Incident.',
    verified: true,
  },
  {
    id: 'incident-service',
    label: 'Incident Lifecycle',
    sublabel: 'State machine · OPEN → CLOSED',
    description: 'Manages incident state transitions: OPEN → INVESTIGATING → CONTAINED → RESOLVED → CLOSED / FALSE_POSITIVE.',
    layer: 'control-plane',
    nodeType: 'service',
    status: 'implemented',
    icon: 'shield',
    tech: 'Python · SQLAlchemy',
    evidence: {
      files: ['control-plane/src/intriqo/services/incident_service.py'],
      tests: ['control-plane/tests/'],
    },
    exists: 'Full status machine with validation, linking, and audit trail.',
    interfaces: 'Consumed by incidents API. Links events, tasks, and findings.',
    verified: true,
  },
  {
    id: 'task-service',
    label: 'Agent Task Manager',
    sublabel: 'Idempotent task dispatch',
    description: 'Creates and manages AgentTasks with idempotency keys, status transitions, and finding submission.',
    layer: 'control-plane',
    nodeType: 'service',
    status: 'implemented',
    icon: 'bot',
    tech: 'Python · SQLAlchemy',
    evidence: {
      files: ['control-plane/src/intriqo/services/agent_task_service.py'],
      tests: ['control-plane/tests/'],
    },
    exists: 'Task creation with idempotency, status transitions (PENDING→IN_PROGRESS→COMPLETED/FAILED), finding links.',
    interfaces: 'Agents poll GET /agent-tasks?status=PENDING; submit PATCH for status; POST /findings.',
    verified: true,
  },
  {
    id: 'audit-service',
    label: 'Audit Logging',
    sublabel: 'Append-only audit trail',
    description: 'Records every mutation (event ingested, incident created, task status changed, finding submitted) as an audit log entry.',
    layer: 'control-plane',
    nodeType: 'service',
    status: 'implemented',
    icon: 'activity',
    tech: 'Python · PostgreSQL',
    evidence: {
      files: ['control-plane/src/intriqo/services/audit_service.py'],
      tests: ['control-plane/tests/'],
    },
    exists: 'All mutations recorded; queryable by resource_type + resource_id; exposed via GET /audit.',
    interfaces: 'Called by all services on state change. Read by SOC dashboard audit page.',
    verified: true,
  },
  {
    id: 'policy-engine',
    label: 'Policy Engine',
    sublabel: 'ALLOW / DENY / HUMAN_APPROVAL',
    description: 'Evaluates ActionRequests from agents and returns PolicyDecisions. Currently a placeholder with hardcoded rules.',
    layer: 'control-plane',
    nodeType: 'service',
    status: 'placeholder',
    icon: 'shield',
    tech: 'Python',
    evidence: {
      files: ['control-plane/src/intriqo/policy/policy_engine.py'],
      note: 'Source code explicitly states "This implementation is a placeholder".',
    },
    exists: 'PolicyEngine.evaluate() method; hardcoded HUMAN_APPROVAL for BLOCK_IP/ISOLATE_HOST, ALLOW for CREATE_TICKET.',
    missing: 'No rule store, no dynamic policy evaluation, no persistence of decisions.',
    limitations: 'Hardcoded rules only. Production implementation requires rule store and deterministic evaluation.',
    interfaces: 'ActionRequest → PolicyDecision (ALLOW/DENY/HUMAN_APPROVAL).',
    verified: false,
  },
  {
    id: 'postgresql',
    label: 'PostgreSQL',
    sublabel: 'Primary data store',
    description: 'Primary relational store for all security events, incidents, tasks, findings, and audit logs.',
    layer: 'control-plane',
    nodeType: 'database',
    status: 'implemented',
    icon: 'database',
    tech: 'PostgreSQL · SQLAlchemy · Alembic',
    evidence: {
      files: ['control-plane/src/intriqo/db/models/', 'control-plane/alembic/versions/'],
      note: '5 Alembic migrations; all core tables present.',
    },
    exists: '5 Alembic migrations; tables: security_events, incidents, incident_events, agent_tasks, findings, audit_log, users.',
    interfaces: 'All services use AsyncSession via SQLAlchemy ORM.',
    verified: true,
  },
  {
    id: 'redis',
    label: 'Redis',
    sublabel: 'Deferred — not yet used',
    description: 'Redis service is defined in Docker Compose but no application component uses it in Core v1.',
    layer: 'control-plane',
    nodeType: 'service',
    status: 'planned',
    icon: 'database',
    tech: 'Redis',
    evidence: {
      files: ['docker-compose.yml'],
      note: 'Docker service defined; no application imports or usage found per ADR-006.',
    },
    exists: 'Docker service definition only.',
    missing: 'Caching, pub/sub, or task queue integration deferred until benchmarks justify it.',
    limitations: 'Per ADR-006, distributed infrastructure is deferred.',
  },
  {
    id: 'websocket',
    label: 'Real-time Push',
    sublabel: 'WebSocket / SSE — planned',
    description: 'Planned real-time event push to the dashboard. Currently the frontend uses explicit manual polling.',
    layer: 'control-plane',
    nodeType: 'service',
    status: 'planned',
    icon: 'activity',
    tech: 'WebSocket / SSE',
    evidence: {
      files: [],
      note: 'No WebSocket or SSE endpoint found in any API module.',
    },
    exists: 'Not implemented. Frontend uses manual Refresh button.',
    missing: 'WebSocket or SSE endpoint; client-side subscription; reconnect logic.',
  },

  // ── Investigation Agents ──────────────────────────────────────────────────
  {
    id: 'orchestrator',
    label: 'Agent Orchestrator',
    sublabel: 'Task routing · dispatch',
    description: 'Polls control plane for PENDING tasks, routes them to the correct agent, and aggregates results.',
    layer: 'agents',
    nodeType: 'agent',
    status: 'implemented',
    icon: 'bot',
    tech: 'Python',
    evidence: {
      files: [
        'agents/src/intriqo_agents/orchestrator/orchestrator.py',
        'agents/src/intriqo_agents/orchestrator/registry.py',
        'agents/src/intriqo_agents/orchestrator/main.py',
      ],
      tests: ['agents/tests/'],
    },
    exists: 'AgentOrchestrator, AgentRegistry, polling entry point. Dispatches INVESTIGATION tasks.',
    interfaces: 'Polls GET /agent-tasks?status=PENDING; calls InvestigationAgent.execute_task().',
    verified: true,
  },
  {
    id: 'investigation-agent',
    label: 'Investigation Agent',
    sublabel: 'Evidence gathering · findings',
    description: 'Fetches event context, constructs structured evidence, and submits an idempotent Finding for PORT_SCAN, UDP_SCAN, SYN_FLOOD, and ML_ANOMALY events.',
    layer: 'agents',
    nodeType: 'agent',
    status: 'implemented',
    icon: 'bot',
    tech: 'Python',
    evidence: {
      files: ['agents/src/intriqo_agents/investigation/agent.py'],
      tests: ['agents/tests/'],
    },
    exists: 'Full investigation paths for PORT_SCAN, UDP_SCAN, SYN_FLOOD, ML_ANOMALY. Submits structured Finding.',
    interfaces: 'Input: AgentTask. Output: Finding submitted to POST /findings.',
    verified: true,
  },
  {
    id: 'threat-intel-agent',
    label: 'Threat Intel Agent',
    sublabel: 'IP / domain reputation',
    description: 'Planned agent for enriching events with IP and domain reputation from external threat feeds.',
    layer: 'agents',
    nodeType: 'agent',
    status: 'planned',
    icon: 'bot',
    tech: 'Python',
    evidence: {
      files: ['agents/src/intriqo_agents/threat_intelligence/'],
      note: 'Directory exists but is empty.',
    },
    exists: 'Empty directory placeholder only.',
    missing: 'Feed integration, IP/domain lookup tools, enrichment logic.',
  },
  {
    id: 'correlation-agent',
    label: 'Correlation Agent',
    sublabel: 'Multi-event attack reconstruction',
    description: 'Planned agent for reconstructing multi-event attack sequences and building incident context.',
    layer: 'agents',
    nodeType: 'agent',
    status: 'planned',
    icon: 'bot',
    tech: 'Python',
    evidence: {
      files: ['agents/src/intriqo_agents/correlation/'],
      note: 'Directory exists but is empty.',
    },
    exists: 'Empty directory placeholder only.',
    missing: 'Attack graph reasoning, multi-event stitching logic.',
  },
  {
    id: 'response-agent',
    label: 'Response Agent',
    sublabel: 'Action proposal · policy check',
    description: 'Planned agent for proposing containment actions (BLOCK_IP, ISOLATE_HOST) subject to policy approval.',
    layer: 'agents',
    nodeType: 'agent',
    status: 'planned',
    icon: 'bot',
    tech: 'Python',
    evidence: {
      files: ['agents/src/intriqo_agents/response/'],
      note: 'Directory exists but is empty.',
    },
    exists: 'Empty directory placeholder only.',
    missing: 'Action proposal logic, policy integration, execution verification.',
  },
  {
    id: 'llm-integration',
    label: 'LLM Integration',
    sublabel: 'Language model reasoning',
    description: 'Planned integration point for LLM-assisted reasoning in investigation and correlation agents.',
    layer: 'agents',
    nodeType: 'service',
    status: 'planned',
    icon: 'layers',
    tech: 'Python · LLM API',
    evidence: {
      files: ['agents/src/intriqo_agents/llm/'],
      note: 'Directory exists but is empty.',
    },
    exists: 'Empty directory placeholder only.',
    missing: 'LLM client, prompt templates, context management, response parsing.',
  },

  // ── ML Pipeline ───────────────────────────────────────────────────────────
  {
    id: 'ml-worker',
    label: 'ML Worker',
    sublabel: 'JSONL → inference → CP POST',
    description: 'Reads FlowFeatureRecord JSONL, runs Isolation Forest inference, deduplicates, and posts ML_ANOMALY events to the control plane.',
    layer: 'ml',
    nodeType: 'process',
    status: 'implemented',
    icon: 'activity',
    tech: 'Python · scikit-learn',
    evidence: {
      files: ['ml/src/intriqo_ml/ml_worker.py', 'ml/src/intriqo_ml/inference_v2.py'],
      tests: ['ml/tests/'],
    },
    exists: 'ml_worker.py with dedup ledger; inference_v2.py with SHA-256 artifact locking.',
    interfaces: 'Reads JSONL from feature sink output; POSTs ML_ANOMALY SecurityEvents to /api/v1/events.',
    verified: true,
  },
  {
    id: 'isolation-forest',
    label: 'Isolation Forest',
    sublabel: 'Anomaly detection model',
    description: 'Hash-locked Isolation Forest model for detecting anomalous flows from FlowFeatureRecord v2.',
    layer: 'ml',
    nodeType: 'model',
    status: 'implemented',
    icon: 'sliders',
    tech: 'scikit-learn · IsolationForest',
    evidence: {
      files: ['ml/src/intriqo_ml/inference_v2.py'],
      note: 'LockedArtifactLoader verifies SHA-256; disabled by default.',
    },
    exists: 'Inference with locked artifact verification. Disabled by default; opt-in via env var.',
    limitations: 'Disabled by default. Artifact must be provided; no committed model artifact in repo.',
    interfaces: 'Input: FlowFeatureRecord v2 array. Output: anomaly score → ML_ANOMALY event.',
    verified: true,
  },
  {
    id: 'training-pipeline',
    label: 'Training Pipeline',
    sublabel: 'Dataset → model artifact',
    description: 'Training pipeline using CICIDS2017 dataset to produce Isolation Forest artifacts.',
    layer: 'ml',
    nodeType: 'process',
    status: 'partial',
    icon: 'code',
    tech: 'Python · scikit-learn · pandas',
    evidence: {
      files: ['ml/training/', 'datasets/'],
      note: 'Directories and documentation exist; no committed model artifacts in repo.',
    },
    exists: 'Training directory with scikit-learn experiments; dataset ingestion docs for CICIDS2017.',
    missing: 'No committed model artifacts; training pipeline not fully automated.',
    limitations: 'CICIDS2017 dataset must be separately acquired and preprocessed.',
  },

  // ── Frontend ──────────────────────────────────────────────────────────────
  {
    id: 'soc-dashboard',
    label: 'SOC Dashboard',
    sublabel: 'React · TypeScript · Vite',
    description: 'React single-page application with full event/incident/task/finding/audit workflow views.',
    layer: 'frontend',
    nodeType: 'interface',
    status: 'implemented',
    icon: 'grid',
    tech: 'React 18 · TypeScript · Vite',
    evidence: {
      files: ['frontend/dashboard/src/features/pages.tsx'],
      tests: ['frontend/dashboard/src/features/auth.test.ts'],
    },
    exists: 'Full SOC workflow: events, incidents, tasks, findings, audit log, dashboard summary.',
    interfaces: 'Consumes all /api/v1/ REST endpoints. Auth via JWT stored in session.',
    verified: true,
  },
  {
    id: 'approvals-ui',
    label: 'Approvals UI',
    sublabel: 'Human approval workflow — planned',
    description: 'Planned UI for reviewing and approving HUMAN_APPROVAL policy decisions from the response agent.',
    layer: 'frontend',
    nodeType: 'interface',
    status: 'planned',
    icon: 'shield',
    tech: 'React · TypeScript',
    evidence: {
      files: ['frontend/dashboard/src/features/approvals/'],
      note: 'Directory exists but is empty.',
    },
    exists: 'Empty directory placeholder only.',
    missing: 'Policy decision queue view, approval/reject UI, action execution feedback.',
  },

  // ── Infrastructure ────────────────────────────────────────────────────────
  {
    id: 'prometheus',
    label: 'Prometheus / Grafana',
    sublabel: 'Observability — optional profile',
    description: 'Prometheus + Grafana services are defined in Docker Compose under an optional observability profile but are not integrated into the application.',
    layer: 'infrastructure',
    nodeType: 'service',
    status: 'planned',
    icon: 'activity',
    tech: 'Prometheus · Grafana',
    evidence: {
      files: ['docker-compose.yml'],
      note: 'Both services defined under profile "observability"; no metrics endpoints in application code.',
    },
    exists: 'Docker service definitions only.',
    missing: 'Metrics endpoints in application; Grafana dashboards; alert rules.',
  },
]

// ─── Edges ───────────────────────────────────────────────────────────────────

export const ARCH_EDGES: ArchEdgeData[] = [
  // Traffic sources → parser
  { id: 'e-live-parser',      source: 'live-capture',       target: 'packet-parser',           label: 'raw bytes',         protocol: 'AF_PACKET',      status: 'implemented' },
  { id: 'e-pcap-parser',      source: 'pcap-replay',        target: 'packet-parser',           label: 'raw bytes',         protocol: 'PCAP',           status: 'implemented' },
  { id: 'e-synth-parser',     source: 'synthetic-source',   target: 'packet-parser',           label: 'raw bytes',         protocol: 'in-process',     status: 'implemented' },

  // Parser → flow table → pipeline
  { id: 'e-parser-flow',      source: 'packet-parser',      target: 'flow-table',              label: 'ParsedPacket',      protocol: 'in-process',     status: 'implemented' },
  { id: 'e-flow-pipeline',    source: 'flow-table',         target: 'pipeline',                label: 'FlowUpdate',        protocol: 'in-process',     status: 'implemented' },

  // Pipeline → detectors
  { id: 'e-pipe-ps',          source: 'pipeline',           target: 'port-scan-detector',      label: 'NetworkFlow',       protocol: 'in-process',     status: 'implemented' },
  { id: 'e-pipe-udp',         source: 'pipeline',           target: 'udp-scan-detector',       label: 'NetworkFlow',       protocol: 'in-process',     status: 'implemented' },
  { id: 'e-pipe-syn',         source: 'pipeline',           target: 'syn-flood-detector',      label: 'NetworkFlow',       protocol: 'in-process',     status: 'implemented' },
  { id: 'e-pipe-bf',          source: 'pipeline',           target: 'brute-force-detector',    label: 'NetworkFlow',       protocol: 'in-process',     status: 'planned',    animated: false },
  { id: 'e-pipe-dns',         source: 'pipeline',           target: 'dns-anomaly-detector',    label: 'NetworkFlow',       protocol: 'in-process',     status: 'planned',    animated: false },

  // Detectors → HTTP event sink
  { id: 'e-ps-sink',          source: 'port-scan-detector', target: 'http-event-sink',         label: 'SecurityEvent',     protocol: 'callback',       status: 'implemented' },
  { id: 'e-udp-sink',         source: 'udp-scan-detector',  target: 'http-event-sink',         label: 'SecurityEvent',     protocol: 'callback',       status: 'implemented' },
  { id: 'e-syn-sink',         source: 'syn-flood-detector', target: 'http-event-sink',         label: 'SecurityEvent',     protocol: 'callback',       status: 'implemented' },

  // Pipeline → feature sink → ML worker
  { id: 'e-pipe-feat',        source: 'pipeline',           target: 'feature-sink',            label: 'FlowFeatureRecord', protocol: 'in-process',     status: 'implemented' },
  { id: 'e-feat-contract',    source: 'feature-sink',       target: 'flow-feature-contract',   label: 'JSONL',             protocol: 'file write',     status: 'implemented' },
  { id: 'e-feat-worker',      source: 'flow-feature-contract', target: 'ml-worker',            label: 'JSONL read',        protocol: 'file',           status: 'implemented' },

  // HTTP sink → CP via SecurityEvent contract
  { id: 'e-sink-contract',    source: 'http-event-sink',    target: 'security-event-contract', label: 'JSON POST',         protocol: 'HTTP/1.1',       status: 'implemented' },
  { id: 'e-contract-cp',      source: 'security-event-contract', target: 'fastapi-server',     label: 'POST /events',      protocol: 'HTTP REST',      status: 'implemented' },

  // ML worker → CP
  { id: 'e-ml-cp',            source: 'ml-worker',          target: 'fastapi-server',          label: 'ML_ANOMALY event',  protocol: 'HTTP REST',      status: 'implemented' },
  { id: 'e-iso-worker',       source: 'isolation-forest',   target: 'ml-worker',               label: 'anomaly score',     protocol: 'in-process',     status: 'implemented' },

  // CP internal services
  { id: 'e-api-auth',         source: 'fastapi-server',     target: 'auth-service',            label: 'JWT verify',        protocol: 'dependency',     status: 'implemented' },
  { id: 'e-api-eventsvc',     source: 'fastapi-server',     target: 'event-service',           label: 'ingest',            protocol: 'service call',   status: 'implemented' },
  { id: 'e-eventsvc-corr',    source: 'event-service',      target: 'correlation-service',     label: 'correlate',         protocol: 'service call',   status: 'implemented' },
  { id: 'e-corr-incident',    source: 'correlation-service',target: 'incident-service',        label: 'create/link',       protocol: 'service call',   status: 'implemented' },
  { id: 'e-incident-task',    source: 'incident-service',   target: 'task-service',            label: 'create task',       protocol: 'service call',   status: 'implemented' },
  { id: 'e-eventsvc-audit',   source: 'event-service',      target: 'audit-service',           label: 'record',            protocol: 'service call',   status: 'implemented' },
  { id: 'e-incident-audit',   source: 'incident-service',   target: 'audit-service',           label: 'record',            protocol: 'service call',   status: 'implemented' },
  { id: 'e-task-audit',       source: 'task-service',       target: 'audit-service',           label: 'record',            protocol: 'service call',   status: 'implemented' },

  // Services → PostgreSQL
  { id: 'e-eventsvc-pg',      source: 'event-service',      target: 'postgresql',              label: 'persist',           protocol: 'SQLAlchemy',     status: 'implemented' },
  { id: 'e-incident-pg',      source: 'incident-service',   target: 'postgresql',              label: 'persist',           protocol: 'SQLAlchemy',     status: 'implemented' },
  { id: 'e-task-pg',          source: 'task-service',       target: 'postgresql',              label: 'persist',           protocol: 'SQLAlchemy',     status: 'implemented' },
  { id: 'e-audit-pg',         source: 'audit-service',      target: 'postgresql',              label: 'persist',           protocol: 'SQLAlchemy',     status: 'implemented' },

  // Agents ↔ CP
  { id: 'e-orch-cp',          source: 'orchestrator',       target: 'fastapi-server',          label: 'poll tasks',        protocol: 'HTTP REST',      status: 'implemented' },
  { id: 'e-inv-cp',           source: 'investigation-agent',target: 'fastapi-server',          label: 'submit finding',    protocol: 'HTTP REST',      status: 'implemented' },
  { id: 'e-orch-inv',         source: 'orchestrator',       target: 'investigation-agent',     label: 'dispatch',          protocol: 'in-process',     status: 'implemented' },
  { id: 'e-orch-ti',          source: 'orchestrator',       target: 'threat-intel-agent',      label: 'dispatch',          protocol: 'in-process',     status: 'planned',    animated: false },
  { id: 'e-orch-corr',        source: 'orchestrator',       target: 'correlation-agent',       label: 'dispatch',          protocol: 'in-process',     status: 'planned',    animated: false },
  { id: 'e-orch-resp',        source: 'orchestrator',       target: 'response-agent',          label: 'dispatch',          protocol: 'in-process',     status: 'planned',    animated: false },
  { id: 'e-resp-policy',      source: 'response-agent',     target: 'policy-engine',           label: 'ActionRequest',     protocol: 'in-process',     status: 'planned',    animated: false },
  { id: 'e-inv-llm',          source: 'investigation-agent',target: 'llm-integration',         label: 'reasoning',         protocol: 'API call',       status: 'planned',    animated: false },

  // Frontend → CP
  { id: 'e-dash-cp',          source: 'soc-dashboard',      target: 'fastapi-server',          label: 'REST read/write',   protocol: 'HTTP REST',      status: 'implemented' },
  { id: 'e-approvals-cp',     source: 'approvals-ui',       target: 'policy-engine',           label: 'approval decision', protocol: 'HTTP REST',      status: 'planned',    animated: false },
]

// ─── Groups ───────────────────────────────────────────────────────────────────

export const ARCH_GROUPS: ArchGroup[] = [
  {
    id: 'grp-network',
    label: 'Network Sources',
    layer: 'network',
    description: 'Live capture, PCAP replay, and synthetic traffic generators',
    nodeIds: ['live-capture', 'pcap-replay', 'synthetic-source'],
  },
  {
    id: 'grp-engine',
    label: 'C++ IDS Engine',
    layer: 'engine',
    description: 'C++20 packet parsing, flow tracking, and detection pipeline',
    nodeIds: ['packet-parser', 'flow-table', 'pipeline', 'port-scan-detector', 'udp-scan-detector', 'syn-flood-detector', 'brute-force-detector', 'dns-anomaly-detector', 'feature-sink', 'http-event-sink'],
  },
  {
    id: 'grp-transport',
    label: 'Contracts',
    layer: 'transport',
    description: 'Versioned JSON Schema contracts at subsystem boundaries',
    nodeIds: ['security-event-contract', 'flow-feature-contract'],
  },
  {
    id: 'grp-control-plane',
    label: 'Control Plane',
    layer: 'control-plane',
    description: 'Python FastAPI services + PostgreSQL persistence',
    nodeIds: ['fastapi-server', 'auth-service', 'event-service', 'correlation-service', 'incident-service', 'task-service', 'audit-service', 'policy-engine', 'postgresql', 'redis', 'websocket'],
  },
  {
    id: 'grp-agents',
    label: 'Investigation Agents',
    layer: 'agents',
    description: 'Autonomous SOC agent platform',
    nodeIds: ['orchestrator', 'investigation-agent', 'threat-intel-agent', 'correlation-agent', 'response-agent', 'llm-integration'],
  },
  {
    id: 'grp-ml',
    label: 'ML Pipeline',
    layer: 'ml',
    description: 'Anomaly detection model and inference worker',
    nodeIds: ['ml-worker', 'isolation-forest', 'training-pipeline'],
  },
  {
    id: 'grp-frontend',
    label: 'SOC Dashboard',
    layer: 'frontend',
    description: 'React TypeScript analyst-facing interface',
    nodeIds: ['soc-dashboard', 'approvals-ui'],
  },
  {
    id: 'grp-infra',
    label: 'Infrastructure',
    layer: 'infrastructure',
    description: 'Deployment and observability services',
    nodeIds: ['prometheus'],
  },
]

// ─── Status helpers ───────────────────────────────────────────────────────────

export const STATUS_LABELS: Record<ImplementationStatus, string> = {
  implemented:  'Implemented',
  partial:      'Partial',
  planned:      'Planned',
  placeholder:  'Placeholder',
  unverified:   'Unverified',
}

export const STATUS_COLORS: Record<ImplementationStatus, { border: string; bg: string; text: string; dot: string }> = {
  implemented:  { border: '#1a4a3a', bg: 'rgba(69,201,148,0.07)',  text: '#45c994', dot: '#45c994' },
  partial:      { border: '#4a3a10', bg: 'rgba(244,183,64,0.07)',  text: '#f4b740', dot: '#f4b740' },
  planned:      { border: '#2a1f4a', bg: 'rgba(139,92,246,0.07)', text: '#a78bfa', dot: '#a78bfa' },
  placeholder:  { border: '#4a2a10', bg: 'rgba(234,133,53,0.07)', text: '#ea8535', dot: '#ea8535' },
  unverified:   { border: '#2a3a40', bg: 'rgba(110,132,144,0.07)',text: '#6e8490', dot: '#6e8490' },
}

export const LAYER_LABELS: Record<ArchLayer, string> = {
  'network':       'Network',
  'engine':        'IDS Engine',
  'transport':     'Contracts',
  'control-plane': 'Control Plane',
  'agents':        'Agents',
  'ml':            'ML Pipeline',
  'frontend':      'Frontend',
  'infrastructure':'Infrastructure',
}

export const LAYER_COLORS: Record<ArchLayer, string> = {
  'network':       '#10bbe0',
  'engine':        '#58d9ef',
  'transport':     '#a78bfa',
  'control-plane': '#45c994',
  'agents':        '#f4b740',
  'ml':            '#ea8535',
  'frontend':      '#10bbe0',
  'infrastructure':'#6e8490',
}

// ─── Computed stats ───────────────────────────────────────────────────────────

export function computeArchStats(nodes: ArchNodeData[]) {
  const total = nodes.length
  const byStatus = {
    implemented:  nodes.filter(n => n.status === 'implemented').length,
    partial:      nodes.filter(n => n.status === 'partial').length,
    planned:      nodes.filter(n => n.status === 'planned').length,
    placeholder:  nodes.filter(n => n.status === 'placeholder').length,
    unverified:   nodes.filter(n => n.status === 'unverified').length,
  }
  // Component coverage = implemented + partial (partial counts as 0.5)
  const coverage = Math.round(((byStatus.implemented + byStatus.partial * 0.5) / total) * 100)
  return { total, byStatus, coverage }
}
