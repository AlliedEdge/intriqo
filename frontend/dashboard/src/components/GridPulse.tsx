import * as React from 'react'
import { cn } from '@/lib/utils'

export type GridPulseProps = Omit<React.ComponentPropsWithoutRef<'div'>, 'children'> & {
  /** Cell size in px. The hairlines and the lit cells share it. */
  cell?: number
  /** How far from the pointer a cell can still catch light, in cells. */
  reach?: number
  /** How many cells light on their own each beat, so the grid is never dead. */
  ambient?: number
  /** A lid, so a fast sweep cannot light the whole field at once. */
  maxLit?: number
  /** Elements whose text the light should hold back from. */
  avoid?: string
}

// Intriqo palette: cyan highlights, the red section accent, and the deep
// slate used in the pelican mark. Keeping this list explicit prevents the
// effect from drifting into unrelated rainbow hues.
const LOGO_COLOURS = ['#58d9ef', '#10bbe0', '#11b7dd', '#dc2626', '#0db6dc', '#2a3d4e']
const FAINT = 0.13
const FADE = 2.2
const PAD = 5
const FADE_IN = 160
const FADE_OUT = 750

type Cell = {
  col: number
  row: number
  colour: string
  dim: number
  born: number
  until: number
}

const easeOut = (t: number) => 1 - (1 - t) ** 2
const easeIn = (t: number) => t * t

/**
 * A fine grid that takes colour where the pointer passes and lets it go a
 * moment later, with a few cells lighting on their own. The canvas is
 * decorative and transparent to pointer events.
 */
export function GridPulse({
  cell = 24,
  reach = 2.6,
  ambient = 2,
  maxLit = 180,
  avoid = '[data-grid-avoid]',
  className,
  style,
  ...props
}: GridPulseProps) {
  const box = React.useRef<HTMLDivElement>(null)
  const canvas = React.useRef<HTMLCanvasElement>(null)

  React.useEffect(() => {
    const el = box.current
    const paper = canvas.current
    const ctx = paper?.getContext('2d')
    if (!el || !paper || !ctx) return
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return

    let cols = 1
    let rows = 1
    let width = 0
    let height = 0
    let clear: DOMRect[] = []
    const cells = new Map<string, Cell>()

    const measureText = () => {
      const bounds = el.getBoundingClientRect()
      const scope = el.parentElement ?? document
      clear = [...scope.querySelectorAll(avoid)].flatMap((node) => {
        const range = document.createRange()
        range.selectNodeContents(node)
        const lines = [...range.getClientRects()].filter((rect) => rect.width > 0 && rect.height > 0)
        const boxes = lines.length > 0 ? lines : [node.getBoundingClientRect()]
        return boxes.map((rect) => new DOMRect(
          rect.left - bounds.left - PAD,
          rect.top - bounds.top - PAD,
          rect.width + PAD * 2,
          rect.height + PAD * 2,
        ))
      })
    }

    let frame = 0
    const draw = (now: number) => {
      frame = 0
      ctx.clearRect(0, 0, width, height)
      for (const [key, current] of cells) {
        let alpha: number
        if (now < current.until) {
          alpha = easeOut(Math.min(1, (now - current.born) / FADE_IN))
        } else {
          const t = (now - current.until) / FADE_OUT
          if (t >= 1) {
            cells.delete(key)
            continue
          }
          alpha = 1 - easeIn(t)
        }
        ctx.globalAlpha = alpha * current.dim
        ctx.fillStyle = current.colour
        ctx.fillRect(current.col * cell + 1, current.row * cell + 1, cell - 1, cell - 1)
      }
      ctx.globalAlpha = 1
      if (cells.size > 0) frame = requestAnimationFrame(draw)
    }
    const wake = () => {
      if (!frame) frame = requestAnimationFrame(draw)
    }

    const measure = () => {
      width = el.clientWidth
      height = el.clientHeight
      cols = Math.max(1, Math.ceil(width / cell))
      rows = Math.max(1, Math.ceil(height / cell))
      const dpr = Math.min(window.devicePixelRatio || 1, 2)
      paper.width = Math.round(width * dpr)
      paper.height = Math.round(height * dpr)
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
      measureText()
      wake()
    }

    const brightness = (col: number, row: number) => {
      const x = col * cell + cell / 2
      const y = row * cell + cell / 2
      let nearest = Number.POSITIVE_INFINITY
      for (const rect of clear) {
        const dx = Math.max(rect.left - x, 0, x - rect.right)
        const dy = Math.max(rect.top - y, 0, y - rect.bottom)
        nearest = Math.min(nearest, Math.hypot(dx, dy))
        if (nearest === 0) break
      }
      if (nearest === Number.POSITIVE_INFINITY) return 1
      return FAINT + (1 - FAINT) * Math.min(1, nearest / (FADE * cell))
    }

    const ink = (row: number) => {
      const progress = rows > 1 ? Math.min(1, row / (rows - 1)) : 0
      const base = Math.min(LOGO_COLOURS.length - 1, Math.floor(progress * LOGO_COLOURS.length))
      const nudge = Math.random() > 0.78 ? 1 : 0
      return LOGO_COLOURS[Math.min(LOGO_COLOURS.length - 1, base + nudge)]
    }

    const light = (col: number, row: number, hold: number) => {
      if (col < 0 || row < 0 || col >= cols || row >= rows || cells.size >= maxLit) return
      const key = `${col},${row}`
      const now = performance.now()
      const lit = cells.get(key)
      if (lit && now < lit.until) return
      let born = now
      if (lit) {
        const faded = 1 - easeIn(Math.min(1, (now - lit.until) / FADE_OUT))
        born = now - (1 - Math.sqrt(1 - faded)) * FADE_IN
      }
      cells.set(key, {
        col,
        row,
        colour: lit?.colour ?? ink(row),
        dim: brightness(col, row),
        born,
        until: now + hold,
      })
      wake()
    }

    let pending = 0
    let at: { x: number; y: number } | null = null
    const paint = () => {
      pending = 0
      if (!at) return
      const centerCol = Math.floor(at.x / cell)
      const centerRow = Math.floor(at.y / cell)
      const span = Math.ceil(reach)
      for (let dy = -span; dy <= span; dy += 1) {
        for (let dx = -span; dx <= span; dx += 1) {
          const away = Math.hypot(dx, dy)
          if (away > reach || Math.random() > 1 - away / (reach + 0.6)) continue
          light(centerCol + dx, centerRow + dy, 260 + Math.random() * 900)
        }
      }
    }
    const onMove = (event: PointerEvent) => {
      const bounds = el.getBoundingClientRect()
      at = { x: event.clientX - bounds.left, y: event.clientY - bounds.top }
      if (!pending) pending = requestAnimationFrame(paint)
    }

    let visible = true
    let beat = 0
    const drift = () => {
      beat = window.setTimeout(drift, 1400 + Math.random() * 1800)
      if (!visible || document.hidden) return
      for (let index = 0; index < ambient; index += 1) {
        light(Math.floor(Math.random() * cols), Math.floor(Math.random() * rows), 900 + Math.random() * 1600)
      }
    }
    beat = window.setTimeout(drift, 500)

    const sight = new IntersectionObserver(([entry]) => {
      visible = entry?.isIntersecting ?? true
    })
    sight.observe(el)
    const resize = new ResizeObserver(measure)
    resize.observe(el)
    let recheck = 0
    const copy = new MutationObserver(() => {
      if (!recheck) {
        recheck = requestAnimationFrame(() => {
          recheck = 0
          measureText()
        })
      }
    })
    copy.observe(el.parentElement ?? document.body, { childList: true, subtree: true, characterData: true })
    measure()
    document.fonts?.ready.then(measureText).catch(() => {})
    window.addEventListener('pointermove', onMove, { passive: true })

    return () => {
      sight.disconnect()
      resize.disconnect()
      copy.disconnect()
      cancelAnimationFrame(recheck)
      cancelAnimationFrame(frame)
      cancelAnimationFrame(pending)
      clearTimeout(beat)
      window.removeEventListener('pointermove', onMove)
    }
  }, [cell, reach, ambient, maxLit, avoid])

  return (
    <div
      ref={box}
      aria-hidden="true"
      data-slot="grid-pulse"
      className={cn('grid-pulse', className)}
      style={{
        '--grid-pulse-cell': `${cell}px`,
        backgroundImage: 'linear-gradient(to right, var(--grid-pulse-line) 1px, transparent 1px), linear-gradient(to bottom, var(--grid-pulse-line) 1px, transparent 1px)',
        backgroundSize: 'var(--grid-pulse-cell) var(--grid-pulse-cell)',
        ...style,
      } as React.CSSProperties}
      {...props}
    >
      <canvas ref={canvas} className="grid-pulse-canvas" />
    </div>
  )
}
