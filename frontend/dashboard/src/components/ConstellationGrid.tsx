import { useEffect, useRef, type MutableRefObject } from 'react'

interface ConstellationNode {
  x: number
  y: number
  vx: number
  vy: number
  baseX: number
  baseY: number
  radius: number
  label: string
  pulse: number
}

export interface ConstellationGridProps {
  /**
   * A mutable ref whose `.current` holds the mouse position in page-client
   * coordinates. The parent is responsible for updating it; the canvas reads
   * it every frame. Set to `{ x: -1000, y: -1000 }` when no interaction is
   * desired (e.g. cursor is outside the card).
   */
  mouseRef: MutableRefObject<{ x: number; y: number }>
  className?: string
}

const SPACING   = 55    // grid dot spacing (px)
const SPRING_K  = 18    // spring stiffness
const DAMPING   = 0.82  // velocity decay per frame
const CONN_DIST = 75    // max distance for drawing a connection line
const REPEL_R   = 220   // mouse repulsion radius

export default function ConstellationGrid({ mouseRef, className }: ConstellationGridProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null)

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d', { alpha: false })
    if (!ctx) return

    let rafId: number
    let width = 0
    let height = 0
    let nodes: ConstellationNode[] = []

    // ---------- sizing ----------
    const resize = () => {
      const dpr = Math.min(window.devicePixelRatio || 1, 2)
      width  = window.innerWidth
      height = window.innerHeight
      canvas.width  = width  * dpr
      canvas.height = height * dpr
      canvas.style.width  = `${width}px`
      canvas.style.height = `${height}px`
      ctx.scale(dpr, dpr)
      initNodes()
    }

    // ---------- nodes ----------
    const initNodes = () => {
      nodes = []
      const cols = Math.ceil(width  / SPACING) + 1
      const rows = Math.ceil(height / SPACING) + 1
      for (let i = 0; i < cols; i++) {
        for (let j = 0; j < rows; j++) {
          const x = i * SPACING
          const y = j * SPACING
          nodes.push({
            x, y,
            vx: 0, vy: 0,
            baseX: x, baseY: y,
            radius: Math.random() * 1.2 + 1.2,
            label: `${(i * 7).toString(16).toUpperCase()}:${(j * 11).toString(16).toUpperCase()}`,
            pulse: Math.random() * Math.PI * 2,
          })
        }
      }
    }

    // ---------- render loop ----------
    let lastTime = performance.now()
    let prevX = -1000, prevY = -1000

    const render = (now: number) => {
      const dt = Math.min((now - lastTime) / 1000, 0.05)
      lastTime = now

      const mx = mouseRef.current.x
      const my = mouseRef.current.y

      // cursor velocity for shockwave intensity
      const mvx = (mx - prevX) / (dt * 1000 || 1)
      const mvy = (my - prevY) / (dt * 1000 || 1)
      prevX = mx; prevY = my
      const speed = Math.sqrt(mvx * mvx + mvy * mvy)

      // ---------- clear ----------
      ctx.fillStyle = '#030407'
      ctx.fillRect(0, 0, width, height)

      // ---------- physics ----------
      for (let i = 0; i < nodes.length; i++) {
        const n = nodes[i]
        n.pulse += dt * 3

        const dx   = mx - n.x
        const dy   = my - n.y
        const dist = Math.sqrt(dx * dx + dy * dy)

        // repulsion
        if (dist < REPEL_R && dist > 0) {
          const power = 1 - dist / REPEL_R
          const force = power * (1500 + speed * 150)
          const angle = Math.atan2(dy, dx)
          n.vx -= Math.cos(angle) * force * dt
          n.vy -= Math.sin(angle) * force * dt
        }

        // spring back to home
        n.vx += (n.baseX - n.x) * SPRING_K * dt
        n.vy += (n.baseY - n.y) * SPRING_K * dt

        // damping + integrate
        n.vx *= DAMPING
        n.vy *= DAMPING
        n.x  += n.vx * dt * 60
        n.y  += n.vy * dt * 60
      }

      // ---------- connections ----------
      const connDistSq = CONN_DIST * CONN_DIST
      for (let i = 0; i < nodes.length; i++) {
        const n = nodes[i]
        for (let j = i + 1; j < nodes.length; j++) {
          const n2  = nodes[j]
          const ndx = n.x - n2.x
          const ndy = n.y - n2.y
          const dsq = ndx * ndx + ndy * ndy
          if (dsq < connDistSq) {
            const alpha = (1 - Math.sqrt(dsq) / CONN_DIST) * 0.18
            ctx.strokeStyle = `rgba(255,255,255,${alpha})`
            ctx.lineWidth   = 0.7
            ctx.beginPath()
            ctx.moveTo(n.x, n.y)
            ctx.lineTo(n2.x, n2.y)
            ctx.stroke()
          }
        }
      }

      // ---------- nodes ----------
      for (let i = 0; i < nodes.length; i++) {
        const n     = nodes[i]
        const dx    = mx - n.x
        const dy    = my - n.y
        const dist  = Math.sqrt(dx * dx + dy * dy)
        const isNear = dist < REPEL_R

        const baseAlpha = isNear
          ? 0.95
          : 0.25 + Math.sin(n.pulse) * 0.1

        ctx.fillStyle = isNear
          ? `rgba(56,189,248,${baseAlpha})`
          : `rgba(255,255,255,${baseAlpha})`

        const r = isNear
          ? n.radius * 2.2
          : n.radius + Math.sin(n.pulse) * 0.3

        ctx.beginPath()
        ctx.arc(n.x, n.y, Math.max(0.5, r), 0, Math.PI * 2)
        ctx.fill()

        // proximity pulse rings + hex label
        if (dist < 90) {
          const pulseRing = ((n.pulse * 20) % 30) + 4
          const ringAlpha = (1 - pulseRing / 34) * 0.4
          ctx.strokeStyle = `rgba(56,189,248,${ringAlpha})`
          ctx.lineWidth   = 1
          ctx.beginPath()
          ctx.arc(n.x, n.y, pulseRing, 0, Math.PI * 2)
          ctx.stroke()

          ctx.font      = '8px ui-monospace, SFMono-Regular, Consolas, monospace'
          ctx.fillStyle = 'rgba(56,189,248,0.85)'
          ctx.fillText(n.label, n.x + 10, n.y - 10)
        }
      }

      rafId = requestAnimationFrame(render)
    }

    // ---------- boot ----------
    resize()
    window.addEventListener('resize', resize)
    rafId = requestAnimationFrame(render)

    return () => {
      cancelAnimationFrame(rafId)
      window.removeEventListener('resize', resize)
    }
  }, [mouseRef])

  return (
    <canvas
      ref={canvasRef}
      className={className}
      aria-hidden="true"
    />
  )
}
