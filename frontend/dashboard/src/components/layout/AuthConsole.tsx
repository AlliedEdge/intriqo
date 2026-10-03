import { useEffect, useRef, type ReactNode } from 'react'
import { Link } from 'react-router-dom'
import ConstellationGrid from '@/components/ConstellationGrid'
import { Card, Logo } from '@/components/ui'
import './auth-console.css'

export type AuthConsolePhase = 'idle' | 'verifying' | 'denied'

export interface AuthConsoleProps {
  title: string
  description?: string
  scope?: string
  phase?: AuthConsolePhase
  children: ReactNode
}

/**
 * Full-viewport auth shell.
 *
 * ConstellationGrid fills 100 vw × 100 vh as a fixed background.
 * The card is centered over it. Pointer events across the window drive the
 * canvas; leaving the window or ending a touch parks the cursor off-screen.
 */
export function AuthConsole({
  title,
  description,
  children,
}: AuthConsoleProps) {
  const mouseRef = useRef<{ x: number; y: number }>({ x: -1000, y: -1000 })
  const cardRef = useRef<HTMLElement>(null)

  useEffect(() => {
    const onMove = (e: MouseEvent) => {
      mouseRef.current = { x: e.clientX, y: e.clientY }
    }
    const onLeave = () => {
      mouseRef.current = { x: -1000, y: -1000 }
    }
    const onTouchMove = (e: TouchEvent) => {
      if (e.touches.length > 0) {
        mouseRef.current = { x: e.touches[0].clientX, y: e.touches[0].clientY }
      }
    }
    const onTouchEnd = () => {
      mouseRef.current = { x: -1000, y: -1000 }
    }

    // Track the entire window so the whole page is interactive
    window.addEventListener('mousemove',  onMove)
    window.addEventListener('mouseleave', onLeave)
    window.addEventListener('touchmove',  onTouchMove, { passive: true })
    window.addEventListener('touchend',   onTouchEnd)

    return () => {
      window.removeEventListener('mousemove',  onMove)
      window.removeEventListener('mouseleave', onLeave)
      window.removeEventListener('touchmove',  onTouchMove)
      window.removeEventListener('touchend',   onTouchEnd)
    }
  }, [])

  return (
    <div className="auth-console">

      {/* ── Full-viewport constellation background ───────────────────── */}
      <ConstellationGrid
        mouseRef={mouseRef}
        className="auth-console__canvas"
      />

      {/* Radial vignette: darkens edges, keeps card readable */}
      <div className="auth-console__scrim" aria-hidden="true" />

      <header className="auth-console__topbar">
        <Link to="/" className="auth-console__brand" aria-label="Intriqo home">
          <Logo />
        </Link>
      </header>

      {/* ── Centered stage ───────────────────────────────────────────── */}
      <main className="auth-console__stage">
        <div className="auth-console__stack">

          {/* Card */}
          <Card className="auth-console__card" ref={cardRef}>
            <span className="auth-console__corner auth-console__corner--tl" aria-hidden="true" />
            <span className="auth-console__corner auth-console__corner--tr" aria-hidden="true" />
            <span className="auth-console__corner auth-console__corner--bl" aria-hidden="true" />
            <span className="auth-console__corner auth-console__corner--br" aria-hidden="true" />

            <h1 className="auth-console__title">{title}</h1>
            {description && <p className="auth-console__subtitle">{description}</p>}

            {children}
          </Card>

        </div>
      </main>

    </div>
  )
}
