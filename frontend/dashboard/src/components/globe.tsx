import { useEffect, useRef, useState } from 'react'
import createGlobe, { type COBEOptions } from 'cobe'

/* -------------------------------------------------------------------------
   Cobe globe component — adapted for Vite + React (no Next.js).
   -------------------------------------------------------------------------  */

export type GlobeConfig = Partial<Omit<COBEOptions, 'width' | 'height' | 'onRender'>>

export interface Position {
  order: number
  startLat: number; startLng: number
  endLat: number;   endLng: number
  arcAlt: number
  color: string
}

export function Globe({ globeConfig }: { globeConfig: GlobeConfig }) {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const initialSizeRef = useRef({ width: 0, height: 0, pixelRatio: 1 })
  const phiRef    = useRef(globeConfig.phi ?? 0)

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return

    const onResize = () => {
      const pixelRatio = window.devicePixelRatio || 1
      initialSizeRef.current = {
        // clientWidth/clientHeight are the CSS dimensions and are not
        // affected by the wrapper's floating transform.
        width: Math.max(1, canvas.clientWidth),
        height: Math.max(1, canvas.clientHeight),
        pixelRatio,
      }
    }
    window.addEventListener('resize', onResize)
    onResize()

    const globe = createGlobe(canvas, {
      // COBE's shader dimensions must use the same pixel ratio as the
      // backing canvas. Hardcoding 2 makes the sphere render in a corner on
      // standard-DPI displays because Phenomenon creates a smaller canvas.
      devicePixelRatio: initialSizeRef.current.pixelRatio,
      width:  initialSizeRef.current.width * initialSizeRef.current.pixelRatio,
      height: initialSizeRef.current.height * initialSizeRef.current.pixelRatio,
      phi:    globeConfig.phi    ?? 0,
      theta:  globeConfig.theta  ?? 0.3,
      dark:   globeConfig.dark   ?? 1,
      diffuse:       globeConfig.diffuse       ?? 0.4,
      mapSamples:    globeConfig.mapSamples    ?? 16000,
      mapBrightness: globeConfig.mapBrightness ?? 1.2,
      baseColor:     globeConfig.baseColor     ?? [0.0, 0.12, 0.28],
      markerColor:   globeConfig.markerColor   ?? [0.1, 0.72, 1.0],
      glowColor:     globeConfig.glowColor     ?? [0.1, 0.72, 1.0],
      markers:       globeConfig.markers       ?? [],
      scale:         globeConfig.scale         ?? 1,
      opacity:       globeConfig.opacity       ?? 1,
      offset:        globeConfig.offset        ?? [0, 0],
      onRender(state) {
        phiRef.current += 0.0025
        state.phi    = phiRef.current
        // Read the actual backing dimensions so CSS resizes and fractional
        // device pixel ratios stay aligned with the WebGL viewport.
        state.width  = canvas.width
        state.height = canvas.height
      },
    })

    // Fade in
    setTimeout(() => { canvas.style.opacity = '1' }, 100)

    return () => {
      globe.destroy()
      window.removeEventListener('resize', onResize)
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  return (
    <canvas
      ref={canvasRef}
      style={{
        width:      '100%',
        height:     '100%',
        opacity:    0,
        transition: 'opacity 1.2s ease',
        display:    'block',
      }}
    />
  )
}

export function World({ globeConfig }: { globeConfig: GlobeConfig }) {
  const [mounted, setMounted] = useState(false)
  useEffect(() => { setMounted(true) }, [])
  if (!mounted) return null
  return <Globe globeConfig={globeConfig} />
}
