import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { Icon, Logo } from '@/components/ui'
import { HeroVideo } from './HeroVideo'
import { soundEffects } from './soundEffects'
import './landing.css'

const GITHUB_URL = 'https://github.com/AlliedEdge/intriqo'
const DOCS_URL = `${GITHUB_URL}/tree/main/docs`
const COMMUNITY_URL = `${GITHUB_URL}/blob/main/CONTRIBUTING.md`

export function LandingHero() {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)
  const [isMuted, setIsMuted] = useState(soundEffects.muted)
  const [isScrolled, setIsScrolled] = useState(() => {
    if (typeof window !== 'undefined') {
      return window.location.search.includes('scrolled=true') || window.scrollY > 15
    }
    return false
  })

  // Listen to window scroll to smoothly transform navbar into a floating capsule
  useEffect(() => {
    const handleScroll = () => {
      // As soon as the user scrolls even a bit (> 15px), transform to capsule
      if (window.location.search.includes('scrolled=true') || window.scrollY > 15) {
        setIsScrolled(true)
      } else {
        setIsScrolled(false)
      }
    }

    window.addEventListener('scroll', handleScroll, { passive: true })
    handleScroll()
    return () => window.removeEventListener('scroll', handleScroll)
  }, [])

  const toggleSound = () => {
    const nextMuted = soundEffects.toggleMute()
    setIsMuted(nextMuted)
  }

  const handleActionClick = () => {
    soundEffects.playClick()
  }

  const handleActionHover = () => {
    soundEffects.playHover()
  }

  return (
    <div className="cinematic-hero-section">
      {/* 1. Full-bleed Hero Background Video & Poster */}
      <HeroVideo />

      {/* 2. Dynamic Sticky Navbar: Full-width square at top, morphs into floating capsule on scroll */}
      <header className={`cinematic-nav-wrapper ${isScrolled ? 'is-capsule' : ''}`}>
        <div className="cinematic-nav-bar">
          <div className="nav-container container">
            <Link
              to="/"
              className="nav-brand-link"
              aria-label="Intriqo Home"
              onClick={handleActionClick}
              onMouseEnter={handleActionHover}
            >
              <Logo />
            </Link>

            {/* Desktop Navigation Links */}
            <nav className="nav-links-menu" aria-label="Main Navigation">
              <a href="#product" className="nav-link-item" onMouseEnter={handleActionHover}>
                Product
              </a>
              <a href="#architecture" className="nav-link-item" onMouseEnter={handleActionHover}>
                Architecture
              </a>
              <a
                href={DOCS_URL}
                target="_blank"
                rel="noreferrer"
                className="nav-link-item"
                onMouseEnter={handleActionHover}
              >
                Docs <Icon name="arrow-up-right" size={13} />
              </a>
              <a
                href={GITHUB_URL}
                target="_blank"
                rel="noreferrer"
                className="nav-link-item"
                onMouseEnter={handleActionHover}
              >
                GitHub <Icon name="github" size={14} />
              </a>
              <a
                href={COMMUNITY_URL}
                target="_blank"
                rel="noreferrer"
                className="nav-link-item"
                onMouseEnter={handleActionHover}
              >
                Community <Icon name="arrow-up-right" size={13} />
              </a>
            </nav>

            {/* Actions & Sound Controller */}
            <div className="nav-actions-group">
              <button
                type="button"
                className={`sound-toggle-btn ${!isMuted ? 'is-active' : ''}`}
                onClick={toggleSound}
                title={isMuted ? 'Enable sound effects' : 'Mute sound effects'}
                aria-label={isMuted ? 'Enable UI sound effects' : 'Mute UI sound effects'}
              >
                <Icon name={isMuted ? 'sliders' : 'activity'} size={14} />
                <span>{isMuted ? 'MUTED' : 'AUDIO'}</span>
              </button>

              <a
                href={`${GITHUB_URL}#quick-start`}
                target="_blank"
                rel="noreferrer"
                className="nav-text-link"
                onClick={handleActionClick}
                onMouseEnter={handleActionHover}
              >
                <Icon name="download" size={14} />
                Download
              </a>

              <Link
                to="/login"
                className="button button-secondary button-sm"
                onClick={handleActionClick}
                onMouseEnter={handleActionHover}
              >
                Sign in
              </Link>

              <Link
                to="/signup"
                className="button button-primary button-sm"
                onClick={handleActionClick}
                onMouseEnter={handleActionHover}
              >
                Get started
              </Link>

              {/* Mobile Menu Hamburger */}
              <button
                type="button"
                className="mobile-nav-toggle"
                aria-label="Toggle navigation menu"
                onClick={() => {
                  setMobileMenuOpen((o) => !o)
                  handleActionClick()
                }}
              >
                <Icon name={mobileMenuOpen ? 'x' : 'menu'} size={20} />
              </button>
            </div>
          </div>

          {/* Mobile Navigation Drawer */}
          {mobileMenuOpen && (
            <div className="mobile-nav-drawer" role="navigation" aria-label="Mobile Navigation">
              <a href="#product" onClick={() => setMobileMenuOpen(false)}>
                Product
              </a>
              <a href="#architecture" onClick={() => setMobileMenuOpen(false)}>
                Architecture
              </a>
              <a href={DOCS_URL} target="_blank" rel="noreferrer" onClick={() => setMobileMenuOpen(false)}>
                Documentation
              </a>
              <a href={GITHUB_URL} target="_blank" rel="noreferrer" onClick={() => setMobileMenuOpen(false)}>
                GitHub Repository
              </a>
              <a href={COMMUNITY_URL} target="_blank" rel="noreferrer" onClick={() => setMobileMenuOpen(false)}>
                Community & Contributing
              </a>
              <div style={{ display: 'flex', gap: '10px', marginTop: '8px' }}>
                <Link to="/login" className="button button-secondary button-sm" style={{ flex: 1 }} onClick={() => setMobileMenuOpen(false)}>
                  Sign in
                </Link>
                <Link to="/signup" className="button button-primary button-sm" style={{ flex: 1 }} onClick={() => setMobileMenuOpen(false)}>
                  Get started
                </Link>
              </div>
            </div>
          )}
        </div>
      </header>

      {/* 3. Hero Content Area: Clean, dominant copy on left, cinematic pelican lake view across center and right */}
      <div className="hero-content-area">
        <div className="hero-copy-block">
          <h1 className="hero-headline">
            <span>Detect.</span>
            <span>Investigate.</span>
            <span className="hero-headline-accent">Understand.</span>
          </h1>

          <p className="hero-description-text">
            Intriqo is an open-source autonomous, multi-agent SOC. A high-performance
            C++ IDS turns network traffic into SecurityEvent JSON for the Python
            control plane, connecting detection, triage, and auditability.
          </p>

          <div className="hero-cta-group">
            <Link
              to="/signup"
              className="hero-btn-primary"
              onClick={handleActionClick}
              onMouseEnter={handleActionHover}
            >
              Get started <Icon name="arrow-right" size={17} />
            </Link>

            <a
              href={GITHUB_URL}
              target="_blank"
              rel="noreferrer"
              className="hero-btn-secondary"
              onClick={handleActionClick}
              onMouseEnter={handleActionHover}
            >
              <Icon name="github" size={17} />
              View on GitHub
            </a>

            <Link
              to="/dashboard"
              className="hero-btn-ghost"
              onClick={handleActionClick}
              onMouseEnter={handleActionHover}
            >
              <Icon name="grid" size={16} />
              Open Dashboard
            </Link>
          </div>

          <div className="hero-checklist">
            <span className="hero-checklist-item">
              <Icon name="check" size={14} /> C++ IPv4 & flow detection
            </span>
            <span className="hero-checklist-item">
              <Icon name="check" size={14} /> SecurityEvent JSON contracts
            </span>
            <span className="hero-checklist-item">
              <Icon name="check" size={14} /> Audit-ready workflow
            </span>
          </div>
        </div>
      </div>

      {/* 4. Organic Lake Wave Transition precisely at the bottom edge */}
      <div className="hero-bottom-transition" aria-hidden="true">
        <svg
          className="hero-transition-wave"
          viewBox="0 0 1440 80"
          preserveAspectRatio="none"
          fill="none"
        >
          <path
            d="M0,32 C360,78 720,12 1080,54 C1260,72 1380,38 1440,46 L1440,80 L0,80 Z"
            fill="var(--bg)"
          />
        </svg>
      </div>
    </div>
  )
}
