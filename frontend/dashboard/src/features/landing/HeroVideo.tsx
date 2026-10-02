import { useEffect, useRef, useState } from 'react'

export interface HeroVideoProps {
  className?: string
  poster?: string
  onPlayingChange?: (playing: boolean) => void
}

export function HeroVideo({
  className = '',
  poster = '/assets/hero/intriqo-pelican-hero-poster.webp',
  onPlayingChange,
}: HeroVideoProps) {
  const videoRef = useRef<HTMLVideoElement>(null)
  const [isLoaded, setIsLoaded] = useState(false)
  const [isPlaying, setIsPlaying] = useState(false)
  const [reducedMotion, setReducedMotion] = useState(false)

  // Detect prefers-reduced-motion preference
  useEffect(() => {
    if (typeof window === 'undefined') return
    const mediaQuery = window.matchMedia('(prefers-reduced-motion: reduce)')
    setReducedMotion(mediaQuery.matches)

    const updateMotion = (e: MediaQueryListEvent) => {
      setReducedMotion(e.matches)
    }

    mediaQuery.addEventListener('change', updateMotion)
    return () => mediaQuery.removeEventListener('change', updateMotion)
  }, [])

  // Manage video playback according to motion preference
  useEffect(() => {
    const video = videoRef.current
    if (!video) return

    if (reducedMotion) {
      video.pause()
      setIsPlaying(false)
      onPlayingChange?.(false)
      return
    }

    const playPromise = video.play()
    if (playPromise !== undefined) {
      playPromise
        .then(() => {
          setIsPlaying(true)
          onPlayingChange?.(true)
        })
        .catch(() => {
          // If browser policy restricts autoplay, we remain gracefully in poster mode
          setIsPlaying(false)
          onPlayingChange?.(false)
        })
    }
  }, [reducedMotion, onPlayingChange])

  return (
    <div className={`hero-video-container ${className}`} aria-hidden="true">
      {/* High-res cinematic poster fallback / backdrop */}
      <picture className={`hero-video-poster ${isLoaded && isPlaying ? 'is-faded' : ''}`}>
        <source srcSet="/assets/hero/intriqo-pelican-hero-poster.webp" type="image/webp" />
        <img
          src="/assets/hero/intriqo-pelican-hero-poster.jpg"
          alt="Intriqo pelican watching the lake with fish swimming underwater"
          className="hero-video-poster-img"
          loading="eager"
        />
      </picture>

      {/* Cinematic Pelican Hero Video */}
      <video
        ref={videoRef}
        className={`hero-video-element ${isLoaded ? 'is-ready' : ''}`}
        autoPlay={!reducedMotion}
        muted
        loop
        playsInline
        preload="metadata"
        poster={poster}
        onLoadedData={() => setIsLoaded(true)}
        onPlay={() => {
          setIsPlaying(true)
          onPlayingChange?.(true)
        }}
        onPause={() => {
          setIsPlaying(false)
          onPlayingChange?.(false)
        }}
        tabIndex={-1}
      >
        <source src="/assets/hero/intriqo-pelican-hero.webm" type="video/webm" />
        <source src="/assets/hero/intriqo-pelican-hero.mp4" type="video/mp4" />
      </video>

      {/* Cinematic dark gradients to guarantee readability without dimming the pelican */}
      <div className="hero-gradient-overlay" />
      <div className="hero-gradient-left" />
      <div className="hero-gradient-bottom" />
      <div className="hero-ambient-glow" />
    </div>
  )
}
