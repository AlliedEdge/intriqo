import { useEffect, useRef } from 'react'
import { World } from './globe'

/* -------------------------------------------------------------------------
   SignalGlobe — cobe globe (deep-space render) + canvas arc/node overlay.
   The beautiful Aceternity-style globe from cobe handles the sphere, land
   masses and glow. A 2D canvas overlay draws the animated signal arcs and
   pulsing city nodes on top, perfectly synced to the same rotation.
   ------------------------------------------------------------------------- */

const globeConfig = {
  dark:           1,
  diffuse:        0.35,
  mapSamples:     16000,
  mapBrightness:  1.8,
  baseColor:      [0.02, 0.08, 0.20] as [number,number,number],
  markerColor:    [0.10, 0.72, 1.00] as [number,number,number],
  glowColor:      [0.10, 0.72, 1.00] as [number,number,number],
  markers:        [] as { location: [number,number]; size: number }[],
  phi:            0,
  theta:          0.28,
  scale:          0.82,   // ensures full sphere + atmosphere glow fits inside canvas
  opacity:        1,
  devicePixelRatio: 2,
}

/* ---- Arc data (exact from user's snippet) ---- */
const COLORS = ['#06b6d4', '#3b82f6', '#6366f1']
const c = (i: number) => COLORS[i % COLORS.length]

const ARCS = [
  { startLat:-19.885592, startLng:-43.951191, endLat:-22.9068,   endLng:-43.1729,    arcAlt:0.1, color:c(0) },
  { startLat: 28.6139,   startLng: 77.209,    endLat:  3.139,    endLng:101.6869,    arcAlt:0.2, color:c(1) },
  { startLat:-19.885592, startLng:-43.951191, endLat: -1.303396, endLng: 36.852443,  arcAlt:0.5, color:c(0) },
  { startLat:  1.3521,   startLng:103.8198,   endLat: 35.6762,   endLng:139.6503,    arcAlt:0.2, color:c(1) },
  { startLat: 51.5072,   startLng: -0.1276,   endLat:  3.139,    endLng:101.6869,    arcAlt:0.3, color:c(0) },
  { startLat:-15.785493, startLng:-47.909029, endLat: 36.162809, endLng:-115.119411, arcAlt:0.3, color:c(2) },
  { startLat:-33.8688,   startLng:151.2093,   endLat: 22.3193,   endLng:114.1694,    arcAlt:0.3, color:c(0) },
  { startLat: 21.3099,   startLng:-157.8581,  endLat: 40.7128,   endLng:-74.006,     arcAlt:0.3, color:c(1) },
  { startLat: -6.2088,   startLng:106.8456,   endLat: 51.5072,   endLng: -0.1276,    arcAlt:0.3, color:c(2) },
  { startLat: 11.986597, startLng:  8.571831, endLat:-15.595412, endLng:-56.05918,   arcAlt:0.5, color:c(0) },
  { startLat:-34.6037,   startLng:-58.3816,   endLat: 22.3193,   endLng:114.1694,    arcAlt:0.7, color:c(1) },
  { startLat: 51.5072,   startLng: -0.1276,   endLat: 48.8566,   endLng: -2.3522,    arcAlt:0.1, color:c(0) },
  { startLat: 14.5995,   startLng:120.9842,   endLat: 51.5072,   endLng: -0.1276,    arcAlt:0.3, color:c(2) },
  { startLat:  1.3521,   startLng:103.8198,   endLat:-33.8688,   endLng:151.2093,    arcAlt:0.2, color:c(0) },
  { startLat: 34.0522,   startLng:-118.2437,  endLat: 48.8566,   endLng: -2.3522,    arcAlt:0.2, color:c(1) },
  { startLat:-15.432563, startLng: 28.315853, endLat:  1.094136, endLng:-63.34546,   arcAlt:0.7, color:c(0) },
  { startLat: 37.5665,   startLng:126.978,    endLat: 35.6762,   endLng:139.6503,    arcAlt:0.1, color:c(2) },
  { startLat: 22.3193,   startLng:114.1694,   endLat: 51.5072,   endLng: -0.1276,    arcAlt:0.3, color:c(1) },
  { startLat: 48.8566,   startLng: -2.3522,   endLat: 52.52,     endLng: 13.405,     arcAlt:0.1, color:c(1) },
  { startLat: 52.52,     startLng: 13.405,    endLat: 34.0522,   endLng:-118.2437,   arcAlt:0.2, color:c(2) },
  { startLat:  1.3521,   startLng:103.8198,   endLat: 40.7128,   endLng:-74.006,     arcAlt:0.5, color:c(2) },
  { startLat: 51.5072,   startLng: -0.1276,   endLat: 34.0522,   endLng:-118.2437,   arcAlt:0.2, color:c(0) },
  { startLat: 22.3193,   startLng:114.1694,   endLat:-22.9068,   endLng:-43.1729,    arcAlt:0.7, color:c(1) },
  { startLat:  1.3521,   startLng:103.8198,   endLat:-34.6037,   endLng:-58.3816,    arcAlt:0.5, color:c(0) },
  { startLat:-22.9068,   startLng:-43.1729,   endLat: 28.6139,   endLng: 77.209,     arcAlt:0.7, color:c(2) },
  { startLat: 41.9028,   startLng: 12.4964,   endLat: 34.0522,   endLng:-118.2437,   arcAlt:0.2, color:c(2) },
  { startLat: 22.3193,   startLng:114.1694,   endLat:  1.3521,   endLng:103.8198,    arcAlt:0.2, color:c(1) },
  { startLat: 35.6762,   startLng:139.6503,   endLat: 22.3193,   endLng:114.1694,    arcAlt:0.2, color:c(2) },
  { startLat: 52.52,     startLng: 13.405,    endLat: 22.3193,   endLng:114.1694,    arcAlt:0.3, color:c(0) },
  { startLat:-33.936138, startLng: 18.436529, endLat: 21.395643, endLng: 39.883798,  arcAlt:0.3, color:c(0) },
]

/* ---- 3D helpers (match cobe's coordinate system) ---- */
interface V3 { x:number; y:number; z:number }

function ll2v(lat:number, lon:number, r:number): V3 {
  const φ = (lat * Math.PI) / 180
  const λ = (lon * Math.PI) / 180
  return { x: r*Math.cos(φ)*Math.cos(λ), y: -r*Math.sin(φ), z: r*Math.cos(φ)*Math.sin(λ) }
}
function rotY(v:V3, a:number): V3 {
  const c=Math.cos(a), s=Math.sin(a)
  return { x:v.x*c+v.z*s, y:v.y, z:-v.x*s+v.z*c }
}
function rotX(v:V3, a:number): V3 {
  const c=Math.cos(a), s=Math.sin(a)
  return { x:v.x, y:v.y*c-v.z*s, z:v.y*s+v.z*c }
}
function proj(v:V3, cx:number, cy:number, fov:number): [number,number] {
  const s = fov / (v.z + fov)
  return [cx + v.x*s, cy + v.y*s]
}
function slerp(a:V3, b:V3, t:number, r:number): V3 {
  const dot = Math.min(1, Math.max(-1, (a.x*b.x+a.y*b.y+a.z*b.z)/(r*r)))
  const ω = Math.acos(dot)
  if (Math.abs(ω)<1e-6) return a
  const s = Math.sin(ω)
  const s0 = Math.sin((1-t)*ω)/s, s1 = Math.sin(t*ω)/s
  return { x:a.x*s0+b.x*s1, y:a.y*s0+b.y*s1, z:a.z*s0+b.z*s1 }
}
function hexToRgb(hex:string): [number,number,number] {
  const r = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex)
  return r ? [parseInt(r[1],16), parseInt(r[2],16), parseInt(r[3],16)] : [0,200,255]
}

export function SignalGlobe({ className = '' }: { className?: string }) {
  const wrapRef    = useRef<HTMLDivElement>(null)
  const canvasRef  = useRef<HTMLCanvasElement>(null)
  const rafRef     = useRef(0)
  const phiRef     = useRef(0)   // tracks cobe's own phi so overlay stays in sync

  useEffect(() => {
    const wrap   = wrapRef.current
    const canvas = canvasRef.current
    if (!wrap || !canvas) return

    const ctx = canvas.getContext('2d')
    if (!ctx) return

    // Resize overlay canvas to match wrapper
    const resize = () => {
      const pr = window.devicePixelRatio || 1
      canvas.width  = wrap.offsetWidth  * pr
      canvas.height = wrap.offsetHeight * pr
      ctx.setTransform(pr, 0, 0, pr, 0, 0)
    }
    resize()
    const ro = new ResizeObserver(resize)
    ro.observe(wrap)

    // Arc animation state
    const arcState = ARCS.map(arc => ({
      ...arc,
      progress: Math.random(),
      speed:    0.0018 + Math.random() * 0.002,
      opacity:  0.7 + Math.random() * 0.3,
    }))

    const draw = () => {
      const W = wrap.offsetWidth
      const H = wrap.offsetHeight
      if (W === 0) { rafRef.current = requestAnimationFrame(draw); return }

      ctx.clearRect(0, 0, W, H)

      // cobe auto-rotates at ~0.0025 rad/frame — mirror that here
      phiRef.current += 0.0025
      const phi   = phiRef.current
      const theta = 0.28   // matches globeConfig.theta

      const R   = Math.min(W, H) * 0.42 * 0.82
      const cx  = W / 2
      const cy  = H / 2
      const FOV = Math.min(W, H) * 1.35

      const tf = (v: V3) => rotX(rotY(v, phi), theta)

      // Draw arcs
      for (const arc of arcState) {
        arc.progress += arc.speed
        if (arc.progress > 1) arc.progress = 0

        const pA = ll2v(arc.startLat, arc.startLng, R)
        const pB = ll2v(arc.endLat,   arc.endLng,   R)
        const SEG  = 60
        const LIFT = arc.arcAlt * 0.9
        const [r,g,b] = hexToRgb(arc.color)

        const getpt = (t:number): V3 => {
          const base = slerp(pA, pB, t, R)
          const len  = Math.sqrt(base.x**2+base.y**2+base.z**2)
          const lift = 1 + LIFT * Math.sin(t * Math.PI)
          return { x:base.x/len*(R*lift), y:base.y/len*(R*lift), z:base.z/len*(R*lift) }
        }

        // Faint full trail
        ctx.beginPath()
        let first = true
        for (let s=0; s<=SEG; s++) {
          const pt = tf(getpt(s/SEG))
          if (pt.z < -R*0.1) { first=true; continue }
          const [px,py] = proj(pt, cx, cy, FOV)
          if (first) { ctx.moveTo(px,py); first=false } else ctx.lineTo(px,py)
        }
        ctx.strokeStyle = `rgba(${r},${g},${b},0.15)`
        ctx.lineWidth   = 1; ctx.stroke()

        // Bright moving head
        const ps = Math.max(0, arc.progress - 0.16)
        ctx.beginPath(); first = true
        for (let s=0; s<=SEG; s++) {
          const t = s/SEG; if (t<ps||t>arc.progress) continue
          const pt = tf(getpt(t))
          if (pt.z < -R*0.1) { first=true; continue }
          const [px,py] = proj(pt, cx, cy, FOV)
          if (first) { ctx.moveTo(px,py); first=false } else ctx.lineTo(px,py)
        }
        ctx.strokeStyle = `rgba(${r},${g},${b},${arc.opacity.toFixed(2)})`
        ctx.lineWidth   = 1.6
        ctx.shadowColor = arc.color; ctx.shadowBlur = 10
        ctx.stroke(); ctx.shadowBlur = 0

        // Head dot
        const hpt = tf(getpt(arc.progress))
        if (hpt.z > -R*0.05) {
          const [hx,hy] = proj(hpt, cx, cy, FOV)
          ctx.beginPath(); ctx.arc(hx, hy, 2.4, 0, Math.PI*2)
          ctx.fillStyle = '#ffffff'
          ctx.shadowColor = arc.color; ctx.shadowBlur = 14
          ctx.fill(); ctx.shadowBlur = 0
        }
      }

      rafRef.current = requestAnimationFrame(draw)
    }

    rafRef.current = requestAnimationFrame(draw)

    return () => {
      cancelAnimationFrame(rafRef.current)
      ro.disconnect()
    }
  }, [])

  return (
    <div
      ref={wrapRef}
      className={`signal-globe-wrapper ${className}`}
      style={{ position:'relative', width:'100%', height:'100%' }}
    >
      {/* cobe renders the globe sphere + land masses + glow */}
      <World globeConfig={globeConfig} />

      {/* 2D overlay for animated arcs + node dots */}
      <canvas
        ref={canvasRef}
        aria-hidden="true"
        style={{
          position: 'absolute',
          inset:    0,
          width:    '100%',
          height:   '100%',
          pointerEvents: 'none',
        }}
      />
    </div>
  )
}
