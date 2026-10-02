import { useEffect, useState } from 'react'
import { Icon } from '@/components/ui'
import { soundEffects } from './soundEffects'

interface PipelineStep {
  id: string
  label: string
  sublabel: string
  icon: 'network' | 'server' | 'alert' | 'bot' | 'check'
  contractNote: string
}

const PIPELINE_STEPS: PipelineStep[] = [
  {
    id: 'event',
    label: 'SecurityEvent',
    sublabel: 'C++ IDS Ingestion',
    icon: 'network',
    contractNote: 'Typed JSON contract generated from raw flow packets',
  },
  {
    id: 'control-plane',
    label: 'Control Plane',
    sublabel: 'FastAPI / PostgreSQL',
    icon: 'server',
    contractNote: 'Authenticated event queue & persistent state validation',
  },
  {
    id: 'incident',
    label: 'Incident',
    sublabel: 'Correlation Engine',
    icon: 'alert',
    contractNote: 'Automated clustering into actionable incident tickets',
  },
  {
    id: 'agent',
    label: 'Investigation Agent',
    sublabel: 'Autonomous Triage',
    icon: 'bot',
    contractNote: 'Multi-agent execution inspecting indicators and context',
  },
  {
    id: 'finding',
    label: 'Finding',
    sublabel: 'Audited Verdict',
    icon: 'check',
    contractNote: 'Structured conclusion with cryptographic audit trail',
  },
]

export function HeroPipeline() {
  const [activeStepIndex, setActiveStepIndex] = useState(0)
  const [isPaused, setIsPaused] = useState(false)
  const [reducedMotion, setReducedMotion] = useState(false)

  useEffect(() => {
    if (typeof window === 'undefined') return
    const mq = window.matchMedia('(prefers-reduced-motion: reduce)')
    setReducedMotion(mq.matches)
    const handler = (e: MediaQueryListEvent) => setReducedMotion(e.matches)
    mq.addEventListener('change', handler)
    return () => mq.removeEventListener('change', handler)
  }, [])

  useEffect(() => {
    if (isPaused || reducedMotion) return

    const interval = window.setInterval(() => {
      setActiveStepIndex((prev) => (prev + 1) % PIPELINE_STEPS.length)
    }, 2800)

    return () => window.clearInterval(interval)
  }, [isPaused, reducedMotion])

  const currentStep = PIPELINE_STEPS[activeStepIndex]

  const handleStepSelect = (index: number) => {
    setActiveStepIndex(index)
    soundEffects.playClick()
  }

  return (
    <div
      className="hero-overlays-container"
      onMouseEnter={() => setIsPaused(true)}
      onMouseLeave={() => setIsPaused(false)}
      role="region"
      aria-label="Intriqo Control Plane Pipeline Visualization"
    >
      {/* Floating SecurityEvent Card */}
      <aside className="hero-event-card" aria-label="Sample SecurityEvent contract representation">
        <div className="hero-event-card-header">
          <span className="hero-event-badge hero-event-badge-high">
            <span className="hero-event-dot" />
            HIGH
          </span>
          <span className="hero-event-type-badge">SecurityEvent</span>
        </div>

        <div className="hero-event-body">
          <div className="hero-event-title">PORT_SCAN</div>
          <div className="hero-event-flow mono">
            <span className="flow-ip">10.0.0.1</span>
            <span className="flow-arrow">→</span>
            <span className="flow-ip">10.0.0.2</span>
          </div>
          <div className="hero-event-details">
            <span className="detail-tag">10 ports targeted</span>
            <span className="detail-tag detail-tag-dim">TCP SYN</span>
          </div>
        </div>

        <div className="hero-event-footer">
          <span className="hero-event-caption">Architecture Demonstration</span>
          <span className="hero-event-status">
            <span className="status-pulse" /> IDS Capture
          </span>
        </div>
      </aside>

      {/* Control Plane Vertical Floating Pipeline */}
      <div className="hero-pipeline-panel">
        <div className="hero-pipeline-header">
          <span className="pipeline-kicker">CONTROL PLANE PIPELINE</span>
          <button
            type="button"
            className="pipeline-cycle-status"
            onClick={() => {
              setIsPaused((p) => !p)
              soundEffects.playClick()
            }}
            title={isPaused ? 'Resume animation' : 'Pause animation'}
            aria-label={isPaused ? 'Resume pipeline cycle' : 'Pause pipeline cycle'}
          >
            <span className={`status-indicator ${isPaused ? 'is-paused' : 'is-active'}`} />
            {isPaused ? 'PAUSED' : 'AUTO-CYCLE'}
          </button>
        </div>

        <div className="hero-pipeline-track">
          {PIPELINE_STEPS.map((step, index) => {
            const isActive = index === activeStepIndex
            const isCompleted = index < activeStepIndex

            return (
              <div key={step.id} className="hero-pipeline-node-wrapper">
                <button
                  type="button"
                  onClick={() => handleStepSelect(index)}
                  onMouseEnter={() => soundEffects.playHover()}
                  className={`hero-pipeline-node ${isActive ? 'is-active' : ''} ${isCompleted ? 'is-completed' : ''}`}
                  aria-pressed={isActive}
                  aria-label={`Pipeline step ${index + 1}: ${step.label} (${step.sublabel})`}
                >
                  <div className="node-icon-box">
                    <Icon name={step.icon} size={15} />
                  </div>
                  <div className="node-info">
                    <div className="node-label">
                      <span>{step.label}</span>
                      {isActive && <span className="node-active-tag">ACTIVE</span>}
                    </div>
                    <div className="node-sublabel">{step.sublabel}</div>
                  </div>
                </button>

                {index < PIPELINE_STEPS.length - 1 && (
                  <div className={`hero-pipeline-connector ${index < activeStepIndex ? 'is-completed' : ''} ${index === activeStepIndex ? 'is-active' : ''}`}>
                    <div className="connector-line" />
                    <div className="connector-arrow">
                      <Icon name="chevron-down" size={12} />
                    </div>
                  </div>
                )}
              </div>
            )
          })}
        </div>

        {/* Current Active Step Contract Explainer */}
        <div className="hero-pipeline-footer">
          <div className="pipeline-step-note mono">
            <span className="note-prompt">$</span> {currentStep.contractNote}
          </div>
        </div>
      </div>
    </div>
  )
}
