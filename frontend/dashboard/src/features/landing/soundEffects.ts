// Web Audio API synthesized futuristic sound effects
// 100% client-side, zero external files, zero latency, volume controlled

class SoundEffectsController {
  private ctx: AudioContext | null = null
  private isMuted: boolean = false

  constructor() {
    if (typeof window !== 'undefined') {
      try {
        const stored = localStorage.getItem('intriqo_sound_muted')
        this.isMuted = stored === 'true'
      } catch {
        this.isMuted = false
      }
    }
  }

  private getContext(): AudioContext | null {
    if (typeof window === 'undefined') return null
    if (window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
      return null
    }

    if (!this.ctx) {
      const AudioCtx = window.AudioContext || (window as unknown as { webkitAudioContext: typeof AudioContext }).webkitAudioContext
      if (AudioCtx) {
        this.ctx = new AudioCtx()
      }
    }

    if (this.ctx && this.ctx.state === 'suspended') {
      this.ctx.resume().catch(() => {})
    }

    return this.ctx
  }

  get muted(): boolean {
    return this.isMuted
  }

  set muted(val: boolean) {
    this.isMuted = val
    if (typeof window !== 'undefined') {
      try {
        localStorage.setItem('intriqo_sound_muted', String(val))
      } catch {
        // ignore storage errors
      }
    }
  }

  toggleMute(): boolean {
    this.muted = !this.isMuted
    if (!this.isMuted) {
      this.playChirp()
    }
    return this.isMuted
  }

  // Soft high-tech button click (clean sine pitch drop)
  playClick() {
    if (this.isMuted) return
    const ctx = this.getContext()
    if (!ctx) return

    try {
      const now = ctx.currentTime
      const osc = ctx.createOscillator()
      const gain = ctx.createGain()

      osc.type = 'sine'
      osc.frequency.setValueAtTime(880, now)
      osc.frequency.exponentialRampToValueAtTime(320, now + 0.045)

      gain.gain.setValueAtTime(0.035, now)
      gain.gain.exponentialRampToValueAtTime(0.0008, now + 0.045)

      osc.connect(gain)
      gain.connect(ctx.destination)

      osc.start(now)
      osc.stop(now + 0.045)
    } catch {
      // Audio playback fails silently if blocked
    }
  }

  // Ultra-subtle hover blip (gentle high frequency tick)
  playHover() {
    if (this.isMuted) return
    const ctx = this.getContext()
    if (!ctx) return

    try {
      const now = ctx.currentTime
      const osc = ctx.createOscillator()
      const gain = ctx.createGain()

      osc.type = 'triangle'
      osc.frequency.setValueAtTime(1400, now)
      osc.frequency.exponentialRampToValueAtTime(1800, now + 0.02)

      gain.gain.setValueAtTime(0.012, now)
      gain.gain.exponentialRampToValueAtTime(0.0005, now + 0.02)

      osc.connect(gain)
      gain.connect(ctx.destination)

      osc.start(now)
      osc.stop(now + 0.02)
    } catch {
      // Audio playback fails silently if blocked
    }
  }

  // Futuristic sonar chirp on radar/pipeline activation
  playChirp() {
    if (this.isMuted) return
    const ctx = this.getContext()
    if (!ctx) return

    try {
      const now = ctx.currentTime
      const osc = ctx.createOscillator()
      const gain = ctx.createGain()

      osc.type = 'sine'
      osc.frequency.setValueAtTime(520, now)
      osc.frequency.exponentialRampToValueAtTime(1180, now + 0.08)

      gain.gain.setValueAtTime(0.025, now)
      gain.gain.exponentialRampToValueAtTime(0.0008, now + 0.08)

      osc.connect(gain)
      gain.connect(ctx.destination)

      osc.start(now)
      osc.stop(now + 0.08)
    } catch {
      // Audio playback fails silently if blocked
    }
  }
}

export const soundEffects = new SoundEffectsController()
