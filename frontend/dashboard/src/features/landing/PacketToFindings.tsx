import { Icon } from '@/components/ui'
import { soundEffects } from './soundEffects'

interface PipelineStage {
  step: string
  title: string
  subtitle: string
  description: string
  icon: 'network' | 'sliders' | 'layers' | 'server' | 'bot' | 'shield'
  badge: string
}

const STAGES: PipelineStage[] = [
  {
    step: '01',
    title: 'Network Traffic',
    subtitle: 'Raw wire packets',
    description: 'Continuous packet capture via raw sockets or PCAP tap with zero packet drops.',
    icon: 'network',
    badge: 'AF_PACKET / PCAP',
  },
  {
    step: '02',
    title: 'C++ IDS Engine',
    subtitle: 'High-speed detection',
    description: 'Deterministic flow tracking, IPv4/TCP state machine, and sub-millisecond port scan detection.',
    icon: 'sliders',
    badge: 'C++20 Engine',
  },
  {
    step: '03',
    title: 'SecurityEvent',
    subtitle: 'Typed JSON contract',
    description: 'Structured event schema preserving 5-tuple, protocol timestamps, and detection rule signatures.',
    icon: 'layers',
    badge: 'JSON Schema v1',
  },
  {
    step: '04',
    title: 'Control Plane',
    subtitle: 'State & correlation',
    description: 'FastAPI service validating signatures, managing incident correlation, and event persistence.',
    icon: 'server',
    badge: 'Python / FastAPI',
  },
  {
    step: '05',
    title: 'Investigation Agents',
    subtitle: 'Autonomous triage',
    description: 'Specialized SOC agents analyzing telemetry, host context, and attack graph relationships.',
    icon: 'bot',
    badge: 'Multi-Agent Core',
  },
  {
    step: '06',
    title: 'Findings',
    subtitle: 'Audited verdict',
    description: 'Formal finding report with cryptographic hash, remediation guidance, and compliance log.',
    icon: 'shield',
    badge: 'SOC Audit Ledger',
  },
]

export function PacketToFindings() {
  return (
    <section className="packet-findings-section" id="pipeline">
      <div className="container">
        <div className="packet-findings-header">
          <p className="eyebrow">
            <span className="status-pulse" />
            FROM PACKETS TO FINDINGS
          </p>
          <h2>A deterministic pipeline from wire to verdict.</h2>
          <p>
            Unlike black-box SIEM solutions, Intriqo gives every layer a defined responsibility
            and an explicit typed handoff, ensuring every finding is verifiable down to the original packet.
          </p>
        </div>

        <div className="technical-pipeline-grid">
          {STAGES.map((stage) => (
            <article
              key={stage.step}
              className="tech-pipeline-card"
              onMouseEnter={() => soundEffects.playHover()}
            >
              <div className="tech-card-header">
                <span className="tech-card-step-num">{stage.step}</span>
                <span className="tech-card-icon">
                  <Icon name={stage.icon} size={18} />
                </span>
              </div>
              <h3>{stage.title}</h3>
              <p>{stage.description}</p>
              <span className="tech-card-badge">{stage.badge}</span>
            </article>
          ))}
        </div>
      </div>
    </section>
  )
}
