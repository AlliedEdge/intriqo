import { useEffect, useId, useState } from 'react'
import logoUrl from '../../../../assets/branding/intriqo-logo.svg'
import './PelicanNetworkScene.css'

type PelicanScenePhase = 'idle' | 'targeted' | 'dive' | 'transmit' | 'reset'

const nextPhase: Record<PelicanScenePhase, PelicanScenePhase> = {
  idle: 'targeted',
  targeted: 'dive',
  dive: 'transmit',
  transmit: 'reset',
  reset: 'idle',
}

const phaseDurationMs: Record<PelicanScenePhase, number> = {
  idle: 3_000,
  targeted: 1_100,
  dive: 1_200,
  transmit: 2_500,
  reset: 1_100,
}

const phaseLabel: Record<PelicanScenePhase, string> = {
  idle: 'scanning the lake',
  targeted: 'targeting an anomalous signal',
  dive: 'capturing the signal',
  transmit: 'transmitting a security event',
  reset: 'returning to watch',
}

export interface PelicanNetworkSceneProps {
  className?: string
}

function usePrefersReducedMotion(): boolean {
  const [reducedMotion, setReducedMotion] = useState(false)

  useEffect(() => {
    const mediaQuery = window.matchMedia('(prefers-reduced-motion: reduce)')
    const updatePreference = () => setReducedMotion(mediaQuery.matches)

    updatePreference()
    mediaQuery.addEventListener('change', updatePreference)
    return () => mediaQuery.removeEventListener('change', updatePreference)
  }, [])

  return reducedMotion
}

export function PelicanNetworkScene({ className = '' }: PelicanNetworkSceneProps) {
  const [phase, setPhase] = useState<PelicanScenePhase>('idle')
  const reducedMotion = usePrefersReducedMotion()
  const sceneId = `pelican-scene-${useId().replace(/:/g, '')}`
  const titleId = `${sceneId}-title`
  const descriptionId = `${sceneId}-description`

  useEffect(() => {
    if (reducedMotion) {
      setPhase('idle')
      return
    }

    const timeoutId = window.setTimeout(() => setPhase(nextPhase[phase]), phaseDurationMs[phase])
    return () => window.clearTimeout(timeoutId)
  }, [phase, reducedMotion])

  const rootClassName = [
    'pelican-scene',
    `pelican-scene-phase-${phase}`,
    reducedMotion ? 'pelican-scene-motionless' : '',
    className,
  ].filter(Boolean).join(' ')

  return (
    <svg
      className={rootClassName}
      viewBox="0 0 960 520"
      role="img"
      aria-labelledby={`${titleId} ${descriptionId}`}
      data-phase={phase}
      preserveAspectRatio="xMidYMid meet"
    >
      <title id={titleId}>Intriqo pelican network</title>
      <desc id={descriptionId}>
        A calm lake scene where the Intriqo pelican watches four signals, catches one, and carries its SecurityEvent to the control plane. The scene is currently {phaseLabel[phase]}.
      </desc>

      <defs>
        <linearGradient id={`${sceneId}-sky`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="#edf5f5" />
          <stop offset="68%" stopColor="#dcecee" />
          <stop offset="100%" stopColor="#c8dfe2" />
        </linearGradient>
        <linearGradient id={`${sceneId}-water`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="#a9cdd1" />
          <stop offset="48%" stopColor="#83b5bd" />
          <stop offset="100%" stopColor="#5c8e9d" />
        </linearGradient>
        <linearGradient id={`${sceneId}-pelican-body`} x1="0" y1="0" x2="1" y2="1">
          <stop offset="0%" stopColor="#f8faf8" />
          <stop offset="100%" stopColor="#dbe6e5" />
        </linearGradient>
        <filter id={`${sceneId}-card-shadow`} x="-20%" y="-30%" width="140%" height="170%">
          <feDropShadow dx="0" dy="5" stdDeviation="7" floodColor="#274b5a" floodOpacity="0.18" />
        </filter>
      </defs>

      <g id="sky" className="pelican-scene-sky-background">
        <rect width="960" height="320" fill={`url(#${sceneId}-sky)`} />
        <g id="background" className="pelican-scene-background">
          <circle className="pelican-scene-sun" cx="753" cy="88" r="28" />
          <path className="pelican-scene-mountain-back" d="M0 260L108 190L162 235L252 142L350 254L461 176L553 252L665 132L784 248L884 169L960 235V320H0Z" />
          <path className="pelican-scene-distant-bank" d="M0 277 C128 258 220 268 333 255 C466 240 548 267 658 253 C767 239 851 250 960 236 V320 H0Z" />
          <path className="pelican-scene-reeds" d="M22 318C29 291 27 270 22 246M31 318C43 288 51 277 65 259M885 318C877 285 880 263 891 236M902 318C911 283 928 268 944 252" />
        </g>
        <g className="pelican-scene-sky-grid" aria-hidden="true">
          <path d="M50 106H910" />
          <path d="M50 144H910" />
          <path d="M50 182H910" />
          <path d="M50 220H910" />
          <path d="M202 88V257" />
          <path d="M386 88V257" />
          <path d="M570 88V257" />
          <path d="M754 88V257" />
        </g>
        <text className="pelican-scene-kicker" x="46" y="48">INTRIQO / NETWORK OBSERVABILITY</text>
        <text className="pelican-scene-sky-note" x="46" y="70">quietly watching the surface</text>
      </g>

      <g id="water" className="pelican-scene-water">
        <path d="M0 290 C133 302 229 286 355 299 C491 313 597 285 715 297 C819 307 891 293 960 300 V520 H0Z" fill={`url(#${sceneId}-water)`} />
        <path className="pelican-scene-water-current pelican-scene-water-current-one" d="M-40 345 C121 321 245 370 390 342 S670 320 1000 350" />
        <path className="pelican-scene-water-current pelican-scene-water-current-two" d="M-50 409 C105 386 242 431 418 405 S733 385 1010 415" />
        <path className="pelican-scene-water-current pelican-scene-water-current-three" d="M-45 466 C104 444 254 483 421 461 S720 445 1000 470" />
        <path className="pelican-scene-water-shore" d="M0 304 C120 315 233 299 350 310 C482 323 604 296 716 308 C830 319 895 304 960 311" />
        <text className="pelican-scene-water-note" x="46" y="493">SIGNALS MOVE LIKE WATER</text>
      </g>

      <g id="water-signals" className="pelican-scene-water-signals" aria-hidden="true">
        <path className="pelican-scene-signal-route" d="M472 350 C558 342 610 300 676 267 C729 240 772 198 812 157" />
        <path className="pelican-scene-signal-pulse" d="M472 350 C558 342 610 300 676 267 C729 240 772 198 812 157" />
        <g className="pelican-scene-signal-radar" transform="translate(472 350)">
          <circle r="22" />
          <circle r="34" />
          <path d="M-46 0H-35 M35 0H46 M0-46V-35 M0 35V46" />
        </g>
        <path className="pelican-scene-signal-wave" d="M401 385 C420 375 441 375 460 385" />
        <path className="pelican-scene-signal-wave" d="M389 398 C415 385 444 385 470 398" />
      </g>

      <g id="fish-1" className="pelican-scene-fish pelican-scene-fish-1" transform="translate(146 358) scale(.7)">
        <path className="pelican-scene-fish-body" d="M0 0 C15-16 39-17 59 0 C39 17 15 16 0 0Z" />
        <path className="pelican-scene-fish-tail" d="M56 0 L77-18 L72 0 L77 18Z" />
        <path className="pelican-scene-fish-fin" d="M28-9 L40-23 L45-5Z" />
        <circle className="pelican-scene-fish-eye" cx="17" cy="-4" r="2.5" />
      </g>

      <g id="fish-2" className="pelican-scene-fish pelican-scene-fish-2" transform="translate(443 350) scale(.95)">
        <path className="pelican-scene-fish-body" d="M0 0 C15-16 39-17 59 0 C39 17 15 16 0 0Z" />
        <path className="pelican-scene-fish-tail" d="M56 0 L77-18 L72 0 L77 18Z" />
        <path className="pelican-scene-fish-fin" d="M28-9 L40-23 L45-5Z" />
        <circle className="pelican-scene-fish-eye" cx="17" cy="-4" r="2.5" />
        <circle className="pelican-scene-fish-highlight" cx="36" cy="0" r="35" />
        <text className="pelican-scene-fish-tag" x="-4" y="-45">anomaly / 04</text>
      </g>

      <g id="fish-3" className="pelican-scene-fish pelican-scene-fish-3" transform="translate(629 410) scale(.58)">
        <path className="pelican-scene-fish-body" d="M0 0 C15-16 39-17 59 0 C39 17 15 16 0 0Z" />
        <path className="pelican-scene-fish-tail" d="M56 0 L77-18 L72 0 L77 18Z" />
        <path className="pelican-scene-fish-fin" d="M28-9 L40-23 L45-5Z" />
        <circle className="pelican-scene-fish-eye" cx="17" cy="-4" r="2.5" />
      </g>

      <g id="fish-4" className="pelican-scene-fish pelican-scene-fish-4" transform="translate(777 336) scale(.72)">
        <path className="pelican-scene-fish-body" d="M0 0 C15-16 39-17 59 0 C39 17 15 16 0 0Z" />
        <path className="pelican-scene-fish-tail" d="M56 0 L77-18 L72 0 L77 18Z" />
        <path className="pelican-scene-fish-fin" d="M28-9 L40-23 L45-5Z" />
        <circle className="pelican-scene-fish-eye" cx="17" cy="-4" r="2.5" />
      </g>

      <g id="pelican" className="pelican-scene-pelican">
        <ellipse className="pelican-scene-pelican-shadow" cx="426" cy="382" rx="128" ry="12" />
        <path className="pelican-scene-pelican-body" d="M320 247 C307 279 310 323 335 354 C360 385 415 393 461 375 C501 359 519 322 506 286 C497 260 475 244 446 232 C402 214 337 218 320 247Z" fill={`url(#${sceneId}-pelican-body)`} />
        <path className="pelican-scene-pelican-neck-bridge" d="M398 204 C407 230 414 251 432 271 C447 288 464 301 480 305 C464 320 439 320 417 305 C395 290 377 261 366 230Z" />
        <path className="pelican-scene-pelican-wing" d="M446 246 C493 256 516 290 511 329 C507 359 482 378 449 384 C466 348 456 294 419 260Z" />
        <path className="pelican-scene-pelican-feather" d="M448 278 C475 294 486 316 481 342 M435 286 C456 307 463 330 456 353 M421 292 C437 315 440 336 431 357" />
        <path className="pelican-scene-pelican-tail" d="M337 350 C316 365 303 380 294 397 C327 386 353 380 377 373Z" />
        <path className="pelican-scene-pelican-chest-line" d="M361 245 C340 280 342 323 369 355" />
        <path className="pelican-scene-pelican-leg" d="M386 370V387 M430 374V388" />
        <path className="pelican-scene-pelican-foot" d="M373 388H400 M417 389H445" />
        {/* The official mark is the pelican's face: preserve its cyan/slate eye and beak exactly. */}
        <image
          className="pelican-scene-logo-face"
          href={logoUrl}
          x="286"
          y="78"
          width="225"
          height="225"
          preserveAspectRatio="xMidYMid meet"
        />
        <circle className="pelican-scene-pelican-signal" cx="484" cy="242" r="5" />
      </g>

      <g id="event-card" className="pelican-scene-event-card" filter={`url(#${sceneId}-card-shadow)`}>
        <rect className="pelican-scene-event-card-surface" x="470" y="220" width="210" height="112" rx="12" />
        <circle className="pelican-scene-event-card-severity" cx="491" cy="244" r="5" />
        <text className="pelican-scene-event-card-severity-label" x="503" y="248">HIGH</text>
        <text className="pelican-scene-event-card-title" x="488" y="273">PORT_SCAN</text>
        <text className="pelican-scene-event-card-meta" x="488" y="292">10.0.0.1 → 10.0.0.2</text>
        <path className="pelican-scene-event-card-rule" d="M488 305H662" />
        <text className="pelican-scene-event-card-foot" x="488" y="322">SecurityEvent</text>
      </g>

      <g id="control-plane" className="pelican-scene-control-plane">
        <rect className="pelican-scene-control-plane-surface" x="744" y="102" width="144" height="101" rx="16" />
        <circle className="pelican-scene-control-plane-node" cx="812" cy="146" r="17" />
        <circle className="pelican-scene-control-plane-node-core" cx="812" cy="146" r="5" />
        <path className="pelican-scene-control-plane-orbit" d="M782 146C782 127 796 116 812 116C828 116 842 127 842 146C842 165 828 176 812 176C796 176 782 165 782 146Z" />
        <text className="pelican-scene-control-plane-title" x="760" y="186">CONTROL PLANE</text>
        <text className="pelican-scene-control-plane-meta" x="760" y="199">event ingest / live</text>
      </g>
    </svg>
  )
}
