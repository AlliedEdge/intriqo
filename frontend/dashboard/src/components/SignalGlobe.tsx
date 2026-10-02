import { useEffect, useRef } from 'react'

/* -------------------------------------------------------------------------
   SignalGlobe — Cybernetic 3-D digital signal sphere with electric blue
   and cyan glowing aesthetic, glowing telemetry nodes (shiny dots),
   dynamic data arcs, radar scan rings, and orbital telemetry rings.
   Pure Canvas — zero dependencies.
   ------------------------------------------------------------------------- */

interface Vec3 { x: number; y: number; z: number }

function rotY(v: Vec3, a: number): Vec3 {
  const c = Math.cos(a), s = Math.sin(a)
  return { x: v.x * c + v.z * s, y: v.y, z: -v.x * s + v.z * c }
}

function rotX(v: Vec3, a: number): Vec3 {
  const c = Math.cos(a), s = Math.sin(a)
  return { x: v.x, y: v.y * c - v.z * s, z: v.y * s + v.z * c }
}

function project(v: Vec3, cx: number, cy: number, fov: number): [number, number, number] {
  const z = v.z + fov
  const s = fov / z
  return [cx + v.x * s, cy + v.y * s, s]
}

// lat/lon degrees → unit sphere * r
function ll(lat: number, lon: number, r: number): Vec3 {
  const φ = (lat * Math.PI) / 180
  const λ = (lon * Math.PI) / 180
  return { x: r * Math.cos(φ) * Math.cos(λ), y: -r * Math.sin(φ), z: r * Math.cos(φ) * Math.sin(λ) }
}

// Great-circle slerp
function slerp(a: Vec3, b: Vec3, t: number, r: number): Vec3 {
  const dot = Math.min(1, Math.max(-1, (a.x*b.x + a.y*b.y + a.z*b.z) / (r * r)))
  const ω = Math.acos(dot)
  if (Math.abs(ω) < 1e-6) return a
  const s = Math.sin(ω)
  const s0 = Math.sin((1 - t) * ω) / s
  const s1 = Math.sin(t * ω) / s
  return { x: a.x*s0 + b.x*s1, y: a.y*s0 + b.y*s1, z: a.z*s0 + b.z*s1 }
}

// Global detection and telemetry sensor nodes [lat, lon]
const NODES: [number, number][] = [
  [40.7, -74.0],    // New York
  [51.5, -0.1],     // London
  [35.7, 139.7],    // Tokyo
  [-33.9, 151.2],   // Sydney
  [1.3, 103.8],     // Singapore
  [55.7, 37.6],     // Moscow
  [19.1, 72.9],     // Mumbai
  [25.2, 55.3],     // Dubai
  [37.8, -122.4],   // San Francisco
  [-23.5, -46.6],   // São Paulo
  [48.8, 2.3],      // Paris
  [52.5, 13.4],     // Berlin
  [22.3, 114.2],    // Hong Kong
  [31.2, 121.5],    // Shanghai
  [37.5, 127.0],    // Seoul
  [-37.8, 144.9],   // Melbourne
  [43.6, -79.4],    // Toronto
  [47.6, -122.3],   // Seattle
  [34.0, -118.2],   // Los Angeles
  [-34.6, -58.4],   // Buenos Aires
  [59.3, 18.1],     // Stockholm
  [28.6, 77.2],     // New Delhi
  [13.7, 100.5],    // Bangkok
  [-1.3, 36.8],     // Nairobi
  [-33.9, 18.4],    // Cape Town
  [64.1, -21.9],    // Reykjavik
  [32.0, 34.8],     // Tel Aviv
  [41.0, 28.9],     // Istanbul
]

// Dynamic arc pairs between nodes
const ARC_PAIRS: [number, number][] = [
  [0, 1],   [1, 10],  [10, 11], [11, 5],
  [8, 0],   [17, 8],  [18, 0],  [16, 0],
  [1, 2],   [2, 14],  [14, 13], [13, 12],
  [12, 4],  [4, 6],   [6, 7],   [7, 1],
  [4, 3],   [3, 15],  [0, 9],   [9, 19],
  [1, 20],  [20, 25], [6, 21],  [4, 22],
  [7, 26],  [26, 27], [27, 10], [7, 23],
  [23, 24],
]

interface Arc {
  from: number
  to: number
  progress: number
  speed: number
  opacity: number
  width: number
}

interface ScanRing {
  node: number
  r: number
  maxR: number
  speed: number
}

interface PulseNode {
  node: number
  phase: number
  speed: number
  baseScale: number
  flare: boolean
}

export function SignalGlobe({ className = '' }: { className?: string }) {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const rafRef = useRef(0)
  const yawRef = useRef(0)
  const dragRef = useRef(0)
  const velRef = useRef(0)

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')
    if (!ctx) return

    // HiDPI resize handling
    const resize = () => {
      const pr = window.devicePixelRatio || 1
      const rect = canvas.getBoundingClientRect()
      canvas.width = Math.max(1, Math.floor(rect.width * pr))
      canvas.height = Math.max(1, Math.floor(rect.height * pr))
      ctx.setTransform(pr, 0, 0, pr, 0, 0)
    }
    resize()
    const ro = new ResizeObserver(resize)
    ro.observe(canvas)

    // Interactive drag to spin with smooth inertia
    let dragging = false
    let lastX = 0

    const onDown = (e: MouseEvent) => {
      dragging = true
      lastX = e.clientX
      velRef.current = 0
    }

    const onUp = () => {
      dragging = false
    }

    const onMove = (e: MouseEvent) => {
      if (!dragging) return
      const dx = (e.clientX - lastX) * 0.0065
      dragRef.current += dx
      velRef.current = dx * 0.65
      lastX = e.clientX
    }

    canvas.addEventListener('mousedown', onDown)
    window.addEventListener('mouseup', onUp)
    window.addEventListener('mousemove', onMove)

    // Arcs
    const arcs: Arc[] = ARC_PAIRS.map(([f, t]) => ({
      from: f,
      to: t,
      progress: Math.random(),
      speed: 0.002 + Math.random() * 0.0025,
      opacity: 0.65 + Math.random() * 0.35,
      width: 1.1 + Math.random() * 0.8,
    }))

    // Expanding sonar scan rings
    const rings: ScanRing[] = [0, 1, 2, 4, 6, 8, 12, 18].map((nodeIdx) => ({
      node: nodeIdx,
      r: Math.random() * 18,
      maxR: 22 + Math.random() * 10,
      speed: 0.22 + Math.random() * 0.1,
    }))

    // Pulse nodes
    const pulses: PulseNode[] = NODES.map((_, i) => ({
      node: i,
      phase: Math.random() * Math.PI * 2,
      speed: 0.035 + Math.random() * 0.035,
      baseScale: 0.85 + Math.random() * 0.45,
      flare: i % 4 === 0, // Key hubs get brilliant diamond glints
    }))

    const orbitSpeed = 0.008
    let orbitAngle = 0
    let gTime = 0  // global clock for XYZ drift

    // Z-axis roll rotation
    function rotZ(v: Vec3, a: number): Vec3 {
      const c = Math.cos(a), s = Math.sin(a)
      return { x: v.x * c - v.y * s, y: v.x * s + v.y * c, z: v.z }
    }

    const draw = () => {
      const W = canvas.getBoundingClientRect().width
      const H = canvas.getBoundingClientRect().height
      if (W === 0 || H === 0) {
        rafRef.current = requestAnimationFrame(draw)
        return
      }

      const cx = W / 2
      const cy = H / 2
      const R = Math.min(W, H) * 0.38
      const FOV = Math.min(W, H) * 1.35

      ctx.clearRect(0, 0, W, H)
      gTime += 0.006  // advance time for multi-axis motion

      // Primary YAW auto-rotation + drag inertia
      if (!dragging) {
        velRef.current *= 0.94
        dragRef.current += velRef.current
        yawRef.current += 0.003
      }
      const yaw = yawRef.current + dragRef.current
      orbitAngle += orbitSpeed

      // ── True XYZ 3D motion ──
      // PITCH (X-axis): gentle nod — two sine waves at coprime frequencies
      const pitch = 0.22
        + Math.sin(gTime * 0.68) * 0.14
        + Math.sin(gTime * 0.41 + 1.2) * 0.06
      // ROLL (Z-axis): slow side-wobble that reveals depth parallax
      const roll  = Math.sin(gTime * 0.52 + 0.8) * 0.10
        + Math.cos(gTime * 0.29 + 2.1) * 0.04

      // Combined 3D pipeline: Yaw → Pitch → Roll
      const tf = (v: Vec3) => rotZ(rotX(rotY(v, yaw), pitch), roll)

      // ── 1. Outer atmosphere glow — subtle red, matches section bg ──
      const atm = ctx.createRadialGradient(cx, cy, R * 0.88, cx, cy, R * 1.28)
      atm.addColorStop(0,   'rgba(220, 38, 38, 0.0)')
      atm.addColorStop(0.5, 'rgba(220, 38, 38, 0.07)')
      atm.addColorStop(1,   'transparent')
      ctx.beginPath()
      ctx.arc(cx, cy, R * 1.28, 0, Math.PI * 2)
      ctx.fillStyle = atm
      ctx.fill()

      // ── 2. Sphere fill — solid match to section bg so back-face never shows through ──
      ctx.beginPath()
      ctx.arc(cx, cy, R, 0, Math.PI * 2)
      ctx.fillStyle = '#080f16'
      ctx.fill()

      // Clip subsequent sphere interior elements to the globe disk
      ctx.save()
      ctx.beginPath()
      ctx.arc(cx, cy, R - 0.5, 0, Math.PI * 2)
      ctx.clip()

      // ── 3. Electric Blue Latitude Wireframe ──
      const LAT_N = 14
      for (let i = 1; i < LAT_N; i++) {
        const lat = -90 + (180 / LAT_N) * i
        const isEquator = i === LAT_N / 2
        const SEG = 180
        ctx.beginPath()
        let first = true
        for (let s = 0; s <= SEG; s++) {
          const lon = -180 + (360 / SEG) * s
          const tv = tf(ll(lat, lon, R))
          if (tv.z < 0) {
            first = true
            continue
          }
          const [px, py] = project(tv, cx, cy, FOV)
          const depth = Math.max(0, tv.z / R) // 0..1
          const alpha = (isEquator ? 0.55 : 0.28) + depth * (isEquator ? 0.45 : 0.35)
          ctx.strokeStyle = `rgba(255, 255, 255, ${alpha.toFixed(3)})`
          ctx.lineWidth = isEquator ? 1.4 : 0.8 + depth * 0.45
          if (first) {
            ctx.moveTo(px, py)
            first = false
          } else {
            ctx.lineTo(px, py)
          }
        }
        ctx.stroke()
      }

      // ── 4. Electric Blue Longitude Wireframe ──
      const LON_N = 20
      for (let i = 0; i < LON_N; i++) {
        const lon = -180 + (360 / LON_N) * i
        const SEG = 180
        ctx.beginPath()
        let first = true
        for (let s = 0; s <= SEG; s++) {
          const lat = -90 + (180 / SEG) * s
          const tv = tf(ll(lat, lon, R))
          if (tv.z < 0) {
            first = true
            continue
          }
          const [px, py] = project(tv, cx, cy, FOV)
          const depth = Math.max(0, tv.z / R)
          const alpha = 0.22 + depth * 0.40
          ctx.strokeStyle = `rgba(255, 255, 255, ${alpha.toFixed(3)})`
          ctx.lineWidth = 0.7 + depth * 0.38
          if (first) {
            ctx.moveTo(px, py)
            first = false
          } else {
            ctx.lineTo(px, py)
          }
        }
        ctx.stroke()
      }

      ctx.restore() // End globe disk clip

      // ── 5. Outer rim — very faint, no hard edge ──
      ctx.beginPath()
      ctx.arc(cx, cy, R, 0, Math.PI * 2)
      ctx.strokeStyle = 'rgba(255, 255, 255, 0.12)'
      ctx.lineWidth = 1
      ctx.shadowBlur = 0
      ctx.stroke()

      // ── 6. Luminous Data Stream Arcs ──
      for (const arc of arcs) {
        arc.progress += arc.speed
        if (arc.progress > 1) arc.progress = 0

        const [lat1, lon1] = NODES[arc.from]
        const [lat2, lon2] = NODES[arc.to]
        const pA = ll(lat1, lon1, R)
        const pB = ll(lat2, lon2, R)
        const SEG = 54
        const LIFT = 0.12 // Elevated path

        const getArcPt = (t: number): Vec3 => {
          const base = slerp(pA, pB, t, R)
          const len = Math.sqrt(base.x ** 2 + base.y ** 2 + base.z ** 2)
          const lift = 1 + LIFT * Math.sin(t * Math.PI)
          return {
            x: (base.x / len) * (R * lift),
            y: (base.y / len) * (R * lift),
            z: (base.z / len) * (R * lift),
          }
        }

        // Faint full arc trajectory trail
        ctx.beginPath()
        let first = true
        for (let s = 0; s <= SEG; s++) {
          const pt = tf(getArcPt(s / SEG))
          if (pt.z < -R * 0.15) {
            first = true
            continue
          }
          const [px, py] = project(pt, cx, cy, FOV)
          if (first) {
            ctx.moveTo(px, py)
            first = false
          } else {
            ctx.lineTo(px, py)
          }
        }
        ctx.strokeStyle = 'rgba(16, 187, 224, 0.18)'
        ctx.lineWidth = arc.width * 0.6
        ctx.stroke()

        // Luminous moving laser head segment
        const HEAD = 0.2
        const ps = Math.max(0, arc.progress - HEAD)
        const pe = arc.progress
        ctx.beginPath()
        first = true
        for (let s = 0; s <= SEG; s++) {
          const t = s / SEG
          if (t < ps || t > pe) continue
          const pt = tf(getArcPt(t))
          if (pt.z < -R * 0.15) {
            first = true
            continue
          }
          const [px, py] = project(pt, cx, cy, FOV)
          if (first) {
            ctx.moveTo(px, py)
            first = false
          } else {
            ctx.lineTo(px, py)
          }
        }
        ctx.strokeStyle = `rgba(0, 229, 255, ${arc.opacity.toFixed(2)})`
        ctx.lineWidth = arc.width * 1.2
        ctx.shadowColor = '#00e5ff'
        ctx.shadowBlur = 10
        ctx.stroke()
        ctx.shadowBlur = 0

        // Bright laser head particle
        const hp = tf(getArcPt(arc.progress))
        if (hp.z > -R * 0.1) {
          const [hx, hy] = project(hp, cx, cy, FOV)
          ctx.beginPath()
          ctx.arc(hx, hy, 2.2, 0, Math.PI * 2)
          ctx.fillStyle = '#ffffff'
          ctx.shadowColor = '#00e5ff'
          ctx.shadowBlur = 12
          ctx.fill()
          ctx.shadowBlur = 0
        }
      }

      // ── 7. Expanding Radar Scan Rings (Sonar Pulses) ──
      for (const ring of rings) {
        ring.r += ring.speed
        const progress = ring.r / ring.maxR
        const opacity = Math.max(0, 1 - progress)
        if (ring.r > ring.maxR) {
          ring.r = 0
        }
        const [lat, lon] = NODES[ring.node]
        const tv = tf(ll(lat, lon, R))
        if (tv.z < 0) continue
        const [npx, npy, nsc] = project(tv, cx, cy, FOV)
        const sr = ring.r * nsc * R * 0.038
        ctx.beginPath()
        ctx.arc(npx, npy, sr, 0, Math.PI * 2)
        ctx.strokeStyle = `rgba(0, 229, 255, ${(opacity * 0.7).toFixed(2)})`
        ctx.lineWidth = 1.1
        ctx.shadowColor = '#00e5ff'
        ctx.shadowBlur = 6
        ctx.stroke()
        ctx.shadowBlur = 0
      }

      // ── 8. Shiny Glowing Blue Telemetry Dots (Nodes) ──
      for (const pn of pulses) {
        pn.phase += pn.speed
        const [lat, lon] = NODES[pn.node]
        const tv = tf(ll(lat, lon, R))
        if (tv.z < -R * 0.02) continue // Hide backside nodes

        const depth = Math.max(0.1, (tv.z + R) / (2 * R)) // 0.1..1
        const [npx, npy, nsc] = project(tv, cx, cy, FOV)
        const pulse = Math.sin(pn.phase)
        const alpha = Math.min(1, depth * 1.5)
        const radius = (1 + 0.35 * pulse) * pn.baseScale * 2.8 * nsc

        // 8a. Shiny Outer Halo (Cyan aura)
        const haloR = radius * 4.2
        const glow = ctx.createRadialGradient(npx, npy, 0, npx, npy, haloR)
        glow.addColorStop(0, `rgba(0, 229, 255, ${(alpha * 0.75).toFixed(2)})`)
        glow.addColorStop(0.4, `rgba(16, 187, 224, ${(alpha * 0.32).toFixed(2)})`)
        glow.addColorStop(1, 'transparent')
        ctx.beginPath()
        ctx.arc(npx, npy, haloR, 0, Math.PI * 2)
        ctx.fillStyle = glow
        ctx.fill()

        // 8b. Electric Blue Core
        ctx.beginPath()
        ctx.arc(npx, npy, radius * 1.1, 0, Math.PI * 2)
        ctx.fillStyle = `rgba(0, 210, 255, ${alpha.toFixed(2)})`
        ctx.shadowColor = '#00e5ff'
        ctx.shadowBlur = 10
        ctx.fill()
        ctx.shadowBlur = 0

        // 8c. Shiny Brilliant White/Cyan Specular Center
        ctx.beginPath()
        ctx.arc(npx, npy, radius * 0.52, 0, Math.PI * 2)
        ctx.fillStyle = `rgba(255, 255, 255, ${Math.min(1, alpha * 1.2).toFixed(2)})`
        ctx.fill()

        // 8d. Star Glint / Specular Cross Flare on Key Nodes
        if (pn.flare && pulse > 0.45 && depth > 0.4) {
          const flareLen = (6 + pulse * 4) * nsc
          const flareAlpha = (pulse - 0.45) * 1.8 * alpha
          ctx.strokeStyle = `rgba(255, 255, 255, ${Math.min(1, flareAlpha).toFixed(2)})`
          ctx.lineWidth = 1
          ctx.beginPath()
          // Horizontal ray
          ctx.moveTo(npx - flareLen, npy)
          ctx.lineTo(npx + flareLen, npy)
          // Vertical ray
          ctx.moveTo(npx, npy - flareLen)
          ctx.lineTo(npx, npy + flareLen)
          ctx.stroke()
        }
      }

      // ── 9. Orbiting spark satellites ──
      for (let i = 0; i < 2; i++) {
        const sparkAngle = orbitAngle + (i * Math.PI)
        const orbitR2 = R * 1.18
        const orbitTilt2 = -0.35
        const sparkRaw: Vec3 = {
          x: orbitR2 * Math.cos(sparkAngle),
          y: orbitR2 * Math.sin(sparkAngle) * Math.sin(orbitTilt2),
          z: orbitR2 * Math.sin(sparkAngle) * Math.cos(orbitTilt2),
        }
        const sparkPt = rotY(sparkRaw, yaw * 0.4)
        if (sparkPt.z > -orbitR2 * 0.3) {
          const [spx, spy] = project(sparkPt, cx, cy, FOV)
          ctx.beginPath()
          ctx.arc(spx, spy, 2, 0, Math.PI * 2)
          ctx.fillStyle = '#ffffff'
          ctx.shadowColor = '#dc2626'
          ctx.shadowBlur = 8
          ctx.fill()
          ctx.shadowBlur = 0
        }
      }

      rafRef.current = requestAnimationFrame(draw)
    }

    rafRef.current = requestAnimationFrame(draw)

    return () => {
      cancelAnimationFrame(rafRef.current)
      ro.disconnect()
      canvas.removeEventListener('mousedown', onDown)
      window.removeEventListener('mouseup', onUp)
      window.removeEventListener('mousemove', onMove)
    }
  }, [])

  return (
    <canvas
      ref={canvasRef}
      className={`signal-globe-canvas ${className}`}
      aria-hidden="true"
      style={{
        display: 'block',
        width: '100%',
        height: '100%',
        cursor: 'grab',
      }}
    />
  )
}
