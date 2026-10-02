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
  const widthRef  = useRef(0)
  const phiRef    = useRef(globeConfig.phi ?? 0)

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return

    const onResize = () => {
      if (canvas.parentElement) widthRef.current = canvas.parentElement.offsetWidth
    }
    window.addEventListener('resize', onResize)
    onResize()

    const globe = createGlobe(canvas, {
      devicePixelRatio: window.devicePixelRatio || 2,
      width:  (widthRef.current || 600) * 2,
      height: (widthRef.current || 600) * 2,
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
        state.width  = widthRef.current * 2
        state.height = widthRef.current * 2
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
