import * as React from "react"

// ---------------------------------------------------------------------------
// Sizing helpers (no beam math needed anymore)
// ---------------------------------------------------------------------------

const clamp = (v: number, lo: number, hi: number): number =>
  v < lo ? lo : v > hi ? hi : v

const fitSize = (measuredAt100: number, target: number, cap: number): number => {
  if (!(measuredAt100 > 0) || !(target > 0)) return 0
  return cap > 0 ? Math.min((100 * target) / measuredAt100, cap) : (100 * target) / measuredAt100
}

const baselineAt = (ascent: number, descent: number): number => {
  if (!(ascent > 0) || !(descent >= 0)) return 0.8
  return clamp(((100 - ascent - descent) / 2 + ascent) / 100, 0.5, 1.2)
}

const wordHeight = (fontSize: number, baseline: number, cut: number): number =>
  Math.max(0, fontSize * (baseline + clamp(Number.isFinite(cut) ? cut : 0, -0.4, 0.4)))

const measureBaseline = (family: string, weight: number, text: string): number => {
  try {
    const ctx = document.createElement("canvas").getContext("2d")
    if (!ctx) return 0.8
    ctx.font = weight + " 100px " + family
    const m = ctx.measureText(text)
    return baselineAt(m.fontBoundingBoxAscent, m.fontBoundingBoxDescent)
  } catch {
    return 0.8
  }
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type SocialIcon = "x" | "linkedin" | "youtube" | "instagram" | "github" | "dribbble"

type FooterSocial = {
  label: string
  href?: string
  icon: SocialIcon | React.ReactNode
}

type FooterLink   = { label: string; href?: string }
type FooterColumn = { title: string; links: FooterLink[] }
type FooterAuthor = { name: string; href: string }

// ---------------------------------------------------------------------------
// Icons
// ---------------------------------------------------------------------------

const ICONS: Record<SocialIcon, React.ReactNode> = {
  x: (
    <path
      d="M17.6 3.5h2.9l-6.3 7.2 7.4 9.8h-5.8l-4.5-5.9-5.2 5.9H3.2l6.7-7.7L2.8 3.5h5.9l4.1 5.4 4.8-5.4Zm-1 15.3h1.6L7.9 5.1H6.2l10.4 13.7Z"
      fill="none" stroke="currentColor" strokeWidth="1.1" strokeLinejoin="round"
    />
  ),
  linkedin: (
    <g fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <rect x="3.5" y="3.5" width="17" height="17" rx="2.5" />
      <path d="M8 10.5V16M12 16v-5.5M12 13c0-1.6 1-2.6 2.4-2.6s2.1.9 2.1 2.4V16" />
      <circle cx="8" cy="7.7" r=".55" fill="currentColor" />
    </g>
  ),
  youtube: (
    <g fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round">
      <rect x="2.75" y="5.5" width="18.5" height="13" rx="4" />
      <path d="M10.2 9.3v5.4l4.6-2.7-4.6-2.7Z" />
    </g>
  ),
  instagram: (
    <g fill="none" stroke="currentColor" strokeWidth="1.5">
      <rect x="3.5" y="3.5" width="17" height="17" rx="5" />
      <circle cx="12" cy="12" r="3.9" />
      <circle cx="17.1" cy="6.9" r=".6" fill="currentColor" stroke="none" />
    </g>
  ),
  github: (
    <path
      d="M9 19c-4.3 1.4-4.3-2.5-6-3m12 5v-3.5c0-1 .1-1.4-.5-2 2.8-.3 5.5-1.4 5.5-6a4.6 4.6 0 0 0-1.3-3.2 4.2 4.2 0 0 0-.1-3.2s-1.1-.3-3.5 1.3a12.3 12.3 0 0 0-6.2 0C6.5 2.8 5.4 3.1 5.4 3.1a4.2 4.2 0 0 0-.1 3.2A4.6 4.6 0 0 0 4 9.5c0 4.6 2.7 5.7 5.5 6-.6.6-.6 1.2-.5 2V21"
      fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"
    />
  ),
  dribbble: (
    <g fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round">
      <circle cx="12" cy="12" r="8.5" />
      <path d="M8.6 4.2c3.4 4.4 5.4 9.6 6.1 15.6M3.6 10.6c5.6.3 10.4-1 13.9-4.4M5.6 17.6c3.4-4.2 8.6-5.6 14.8-3.6" />
    </g>
  ),
}

const isIconName = (v: unknown): v is SocialIcon => typeof v === "string" && v in ICONS

const Arrow = () => (
  <svg viewBox="0 0 12 12" aria-hidden="true">
    <path d="M2.5 9.5l7-7M4 2.5h5.5V8" fill="none" stroke="currentColor"
      strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" />
  </svg>
)

// ---------------------------------------------------------------------------
// CSS — dark flat background, no glow, no beam, no wash
// Accent cyan #10bbe0 used only for interactive elements and the top rule.
// INTRIQO wordmark: solid white, no gradient, bottom-cropped.
// ---------------------------------------------------------------------------

const CSS =
  // Root
  ".iqf{position:relative;isolation:isolate;overflow:hidden;container-type:inline-size;" +
  "background:#2a2a2a;color:#e8edf5;font-family:var(--iqf-sans);-webkit-font-smoothing:antialiased}" +
  ":where(.iqf) a{color:inherit;text-decoration:none}" +
  ":where(.iqf) button{font:inherit;color:inherit;background:none;border:0;padding:0;margin:0;cursor:pointer}" +
  ":where(.iqf) ul{list-style:none;margin:0;padding:0}" +
  ":where(.iqf) p{margin:0}" +
  ".iqf svg{max-width:none;display:block}" +
  ".iqf .sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}" +

  // Top hairline — single 1px cyan line, no animation
  ".iqf-rule{position:absolute;left:0;right:0;top:0;height:1px;background:rgba(16,187,224,.28)}" +

  // Layout grid
  ".iqf-inner{position:relative;z-index:2;box-sizing:border-box;max-width:1180px;margin:0 auto;" +
  "padding:clamp(52px,9cqw,112px) clamp(20px,6cqw,88px) 0;" +
  "display:grid;grid-template-columns:minmax(0,1.62fr) minmax(0,.9fr) minmax(0,.9fr) minmax(0,.9fr);" +
  "column-gap:clamp(20px,3.5cqw,44px);row-gap:44px}" +

  // Section label — cyan text, hairline beneath
  ".iqf-label{font-size:11px;line-height:1;letter-spacing:.08em;text-transform:uppercase;" +
  "color:#10bbe0;padding-bottom:13px;position:relative;display:block}" +
  ".iqf-label::after{content:'';position:absolute;left:0;right:0;bottom:0;height:1px;" +
  "background:linear-gradient(90deg,rgba(16,187,224,.35),transparent);" +
  "transform-origin:0 50%;transform:scaleX(var(--iqf-line,1));" +
  "transition:transform 1.1s cubic-bezier(.2,.7,.1,1) var(--iqf-d,0ms)}" +
  ".iqf[data-in='false'] .iqf-label::after{--iqf-line:0}" +

  ".iqf-col{min-width:0}" +
  ".iqf-col:nth-child(1){max-width:400px}" +

  // Scroll-in fade + rise
  ".iqf-fade{transition:opacity .9s ease var(--iqf-d,0ms),translate .9s cubic-bezier(.2,.7,.1,1) var(--iqf-d,0ms)}" +
  ".iqf[data-in='false'] .iqf-fade{opacity:0;translate:0 14px}" +

  // Social buttons — flat dark square, cyan border+icon on hover
  ".iqf-socials{display:flex;flex-wrap:wrap;gap:10px;margin-top:13px}" +
  ".iqf-soc{position:relative;width:31px;height:31px;display:grid;place-items:center;border-radius:5px;" +
  "color:rgba(232,237,245,.38);background:rgba(255,255,255,.04);" +
  "box-shadow:inset 0 0 0 1px rgba(255,255,255,.1);" +
  "transition:color .22s,box-shadow .25s,translate .3s cubic-bezier(.2,.8,.2,1),background .25s}" +
  ".iqf-soc svg{width:17px;height:17px}" +
  ".iqf-soc:hover,.iqf-soc:focus-visible{color:#10bbe0;translate:0 -2px;" +
  "background:rgba(16,187,224,.06);box-shadow:inset 0 0 0 1px rgba(16,187,224,.55)}" +
  ".iqf-soc:focus-visible{outline:none}" +
  ".iqf-tip{position:absolute;z-index:5;left:50%;top:calc(100% + 9px);translate:-50% -4px;" +
  "white-space:nowrap;font-size:11px;line-height:1;padding:5px 8px;border-radius:4px;" +
  "background:#10bbe0;color:#031117;opacity:0;pointer-events:none;transition:opacity .2s,translate .25s}" +
  ".iqf-tip::after{content:'';position:absolute;left:50%;bottom:100%;margin-left:-4px;" +
  "border:4px solid transparent;border-bottom-color:#10bbe0}" +
  ".iqf-soc:hover .iqf-tip,.iqf-soc:focus-visible .iqf-tip{opacity:1;translate:-50% 0}" +

  // Authors — equal weight, everyone the same
  ".iqf-authors{margin-top:20px}" +
  ".iqf-authors-label{font-size:10.5px;letter-spacing:.08em;text-transform:uppercase;" +
  "color:rgba(232,237,245,.3);margin-bottom:10px;display:block}" +
  ".iqf-author-list{display:flex;flex-direction:column;gap:6px}" +
  ".iqf-author{display:inline-flex;align-items:center;gap:9px;text-decoration:none;" +
  "transition:translate .28s cubic-bezier(.2,.8,.2,1)}" +
  ".iqf-author:hover{translate:3px 0}" +
  ".iqf-author-avatar{flex:0 0 auto;width:22px;height:22px;border-radius:50%;display:grid;place-items:center;" +
  "border:1px solid rgba(16,187,224,.3);background:rgba(16,187,224,.08);" +
  "font-size:9.5px;font-weight:700;color:rgba(16,187,224,.8);line-height:1}" +
  ".iqf-author-name{font-size:13px;line-height:1.3;color:rgba(232,237,245,.68);font-weight:400;" +
  "transition:color .22s}" +
  ".iqf-author:hover .iqf-author-name{color:#e8edf5}" +
  ".iqf-author-gh{width:12px;height:12px;flex:0 0 auto;opacity:0;color:rgba(16,187,224,.7);" +
  "transition:opacity .22s,translate .28s cubic-bezier(.2,.8,.2,1);translate:-4px 0}" +
  ".iqf-author:hover .iqf-author-gh{opacity:1;translate:0 0}" +

  // Link columns
  ".iqf-links{margin-top:13px;display:flex;flex-direction:column}" +
  ".iqf-link{position:relative;display:inline-flex;align-items:center;gap:8px;padding:5.5px 0;" +
  "font-size:14px;line-height:21px;color:rgba(232,237,245,.55);transition:color .22s}" +
  ".iqf-link-t{display:inline-block;transition:translate .32s cubic-bezier(.2,.8,.2,1)}" +
  ".iqf-link::before{content:'';position:absolute;left:0;top:50%;width:6px;height:1px;" +
  "background:#10bbe0;transform:scaleX(0);transform-origin:0 50%;" +
  "transition:transform .32s cubic-bezier(.2,.8,.2,1)}" +
  ".iqf-link svg{width:12px;height:12px;opacity:0;translate:-6px 0;color:#10bbe0;" +
  "transition:opacity .22s,translate .32s cubic-bezier(.2,.8,.2,1)}" +
  ".iqf-link:hover,.iqf-link:focus-visible{color:#e8edf5;outline:none}" +
  ".iqf-link:hover::before,.iqf-link:focus-visible::before{transform:scaleX(1)}" +
  ".iqf-link:hover .iqf-link-t,.iqf-link:focus-visible .iqf-link-t{translate:12px 0}" +
  ".iqf-link:hover svg,.iqf-link:focus-visible svg{opacity:1;translate:10px 0}" +
  ".iqf-link:focus-visible .iqf-link-t{text-decoration:underline;text-underline-offset:4px;" +
  "text-decoration-color:rgba(16,187,224,.7)}" +

  // Wordmark — pure white, no gradient, bottom-cropped
  ".iqf-word{position:relative;z-index:1;overflow:hidden;margin-top:clamp(32px,8cqw,104px)}" +
  ".iqf-word-box{padding:0 clamp(20px,6cqw,88px);max-width:1180px;margin:0 auto;box-sizing:border-box}" +
  ".iqf-word-in{display:inline-flex;white-space:nowrap;font-weight:var(--iqf-ww);line-height:1;" +
  "letter-spacing:-.045em;user-select:none;-webkit-user-select:none}" +
  // Each letter wrapper: slides up on reveal
  ".iqf-lw{display:inline-block;translate:0 0;" +
  "transition:translate 1.3s cubic-bezier(.16,.84,.2,1) var(--iqf-d,0ms)}" +
  ".iqf[data-in='false'] .iqf-lw{translate:0 88%}" +
  // Letter: solid white, hop on click, subtle lift on hover
  ".iqf-l{display:inline-block;cursor:pointer;color:#ffffff;" +
  "transition:transform .45s cubic-bezier(.2,.9,.25,1.2);transform-origin:50% 100%}" +
  ".iqf-l:hover{transform:translateY(-.048em)}" +
  ".iqf-l.is-hop{animation:iqf-hop .72s cubic-bezier(.2,.8,.2,1)}" +
  "@keyframes iqf-hop{" +
  "0%{transform:translateY(0) scale(1,1)}" +
  "18%{transform:translateY(.02em) scale(1.07,.88)}" +
  "45%{transform:translateY(-.16em) scale(.96,1.06)}" +
  "70%{transform:translateY(.01em) scale(1.02,.97)}" +
  "100%{transform:translateY(-.048em) scale(1,1)}}" +
  // Bottom fade: letterforms sink into the background
  ".iqf-foot{position:absolute;left:0;right:0;bottom:0;height:40%;z-index:2;pointer-events:none;" +
  "background:linear-gradient(180deg,transparent,rgba(42,42,42,.6) 48%,#2a2a2a)}" +

  // Responsive
  "@container (max-width:820px){" +
  ".iqf-inner{grid-template-columns:minmax(0,1fr) minmax(0,1fr);row-gap:38px}" +
  ".iqf-col:nth-child(1){grid-column:1 / -1;max-width:none}}" +
  "@container (max-width:520px){.iqf-inner{grid-template-columns:1fr}}" +

  // Reduced motion
  "@media (prefers-reduced-motion:reduce){" +
  ".iqf .iqf-lw,.iqf .iqf-fade,.iqf .iqf-label::after,.iqf .iqf-l,.iqf .iqf-soc," +
  ".iqf .iqf-link-t,.iqf .iqf-link svg,.iqf .iqf-author{transition:none!important;animation:none!important}" +
  ".iqf[data-in='false'] .iqf-lw,.iqf[data-in='false'] .iqf-fade{translate:none;opacity:1}" +
  ".iqf[data-in='false'] .iqf-label::after{--iqf-line:1}}"

// ---------------------------------------------------------------------------
// Intriqo data
// ---------------------------------------------------------------------------

const GITHUB_BASE = "https://github.com"

const INTRIQO_AUTHORS: FooterAuthor[] = [
  { name: "Rayan Mohammed Rafeeq", href: `${GITHUB_BASE}/Rayan-Mohammed-Rafeeq` },
  { name: "Hemanth Kumar",          href: `${GITHUB_BASE}/hemanth-kumar-n-1` },
  { name: "Sumit Patil",            href: `${GITHUB_BASE}/sumitpatil93463-png` },
  { name: "Rakshith Y",             href: `${GITHUB_BASE}/rakshithy3185` },
]

const INTRIQO_SOCIALS: FooterSocial[] = [
  { label: "GitHub",     href: "https://github.com/AlliedEdge/intriqo", icon: "github" },
  { label: "X / Twitter", href: "https://x.com/intriqo",                icon: "x" },
  { label: "LinkedIn",   href: "https://linkedin.com/company/intriqo",  icon: "linkedin" },
]

const INTRIQO_COLUMNS: FooterColumn[] = [
  {
    title: "Product",
    links: [
      { label: "Features",     href: "#product" },
      { label: "Architecture", href: "#architecture" },
      { label: "Get Started",  href: "#get-intriqo" },
      { label: "Changelog",    href: "https://github.com/AlliedEdge/intriqo/releases" },
    ],
  },
  {
    title: "Resources",
    links: [
      { label: "Documentation", href: "https://github.com/AlliedEdge/intriqo/tree/main/docs" },
      { label: "Architecture",  href: "https://github.com/AlliedEdge/intriqo/blob/main/docs/architecture/system-architecture.md" },
      { label: "Contributing",  href: "https://github.com/AlliedEdge/intriqo/blob/main/CONTRIBUTING.md" },
      { label: "Open Issues",   href: "https://github.com/AlliedEdge/intriqo/issues" },
    ],
  },
  {
    title: "Connect",
    links: [
      { label: "GitHub",        href: "https://github.com/AlliedEdge/intriqo" },
      { label: "Star the repo", href: "https://github.com/AlliedEdge/intriqo/stargazers" },
      { label: "Fork it",       href: "https://github.com/AlliedEdge/intriqo/fork" },
      { label: "Discussions",   href: "https://github.com/AlliedEdge/intriqo/discussions" },
    ],
  },
]

const SANS =
  '"DM Sans","Inter",ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif'

// ---------------------------------------------------------------------------
// Component props
// ---------------------------------------------------------------------------

type BeamWordmarkFooterProps = {
  company?: string
  year?: number
  socials?: FooterSocial[]
  authors?: FooterAuthor[]
  columns?: FooterColumn[]
  onLinkClick?: (label: string, href?: string) => void
  /** Em below baseline to crop. Default 0.12 shows a little descender space. */
  cut?: number
  fontSans?: string
  wordWeight?: number
  className?: string
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function BeamWordmarkFooter({
  company    = "AlliedEdge",
  year       = new Date().getFullYear(),
  socials    = INTRIQO_SOCIALS,
  authors    = INTRIQO_AUTHORS,
  columns    = INTRIQO_COLUMNS,
  onLinkClick,
  cut        = 0.12,
  fontSans   = SANS,
  wordWeight = 700,
  className  = "",
}: BeamWordmarkFooterProps) {
  const word    = "INTRIQO"
  const letters = React.useMemo(() => Array.from(word), [])

  const rootRef  = React.useRef<HTMLElement>(null)
  const wordRef  = React.useRef<HTMLDivElement>(null)
  const innerRef = React.useRef<HTMLDivElement>(null)

  const [size, setSize] = React.useState(0)
  const [base, setBase] = React.useState(0.8)
  const [seen, setSeen] = React.useState(false)
  const [reduced, setReduced] = React.useState(false)

  // Fit wordmark to full container width
  React.useLayoutEffect(() => {
    const root  = rootRef.current
    const box   = wordRef.current
    const inner = innerRef.current
    if (!root || !box || !inner) return

    let frame = 0

    const fit = () => {
      const wb     = inner.parentElement ?? box
      const pad    = parseFloat(getComputedStyle(wb).paddingLeft) || 0
      const target = wb.clientWidth - pad * 2

      inner.style.fontSize = "100px"
      const measured = inner.offsetWidth
      setBase(measureBaseline(getComputedStyle(inner).fontFamily, wordWeight, word))

      const next = fitSize(measured, target, target * 0.44)
      inner.style.fontSize = next + "px"
      setSize(next)
    }

    const schedule = () => { cancelAnimationFrame(frame); frame = requestAnimationFrame(fit) }
    fit()
    const ro = new ResizeObserver(schedule)
    ro.observe(root)
    let alive = true
    document.fonts?.ready.then(() => alive && schedule())
    return () => { alive = false; cancelAnimationFrame(frame); ro.disconnect() }
  }, [wordWeight])

  // Reveal once when scrolled into view
  React.useEffect(() => {
    const root = rootRef.current
    if (!root) return
    const io = new IntersectionObserver(
      ([e]) => { if (e.isIntersecting) setSeen(true) },
      { threshold: 0.1 }
    )
    io.observe(root)
    return () => io.disconnect()
  }, [])

  // Respect reduced-motion preference
  React.useEffect(() => {
    const mq   = window.matchMedia("(prefers-reduced-motion: reduce)")
    const onMq = () => setReduced(mq.matches)
    onMq()
    mq.addEventListener("change", onMq)
    return () => mq.removeEventListener("change", onMq)
  }, [])

  const hop = (e: React.MouseEvent<HTMLSpanElement>) => {
    if (reduced) return
    const el = e.currentTarget
    el.classList.remove("is-hop")
    void el.offsetWidth
    el.classList.add("is-hop")
  }

  const follow = (e: React.MouseEvent<HTMLAnchorElement>, label: string, href?: string) => {
    if (!href || href === "#" || href.startsWith("#")) e.preventDefault()
    onLinkClick?.(label, href)
  }

  const vars = {
    "--iqf-sans": fontSans,
    "--iqf-ww":   String(wordWeight),
  } as React.CSSProperties

  let d = 0
  const delay = () => ({ "--iqf-d": (d += 65) + "ms" }) as React.CSSProperties

  return (
    <footer
      ref={rootRef}
      className={"iqf " + className}
      style={vars}
      data-in={seen || reduced ? "true" : "false"}
    >
      <style>{CSS}</style>

      {/* Hairline */}
      <div className="iqf-rule" aria-hidden="true" />

      {/* Content */}
      <div className="iqf-inner">

        {/* Col 1 — copyright, socials, authors */}
        <div className="iqf-col">
          <p className="iqf-label" style={delay()}>
            © {year} {company}
          </p>

          {socials.length > 0 && (
            <ul className="iqf-socials">
              {socials.map((s, i) => (
                <li key={s.label + i} className="iqf-fade" style={delay()}>
                  <a
                    className="iqf-soc"
                    href={s.href || "#"}
                    aria-label={s.label}
                    onClick={(e) => follow(e, s.label, s.href)}
                    {...(s.href && /^https?:/.test(s.href) ? { target: "_blank", rel: "noreferrer" } : {})}
                  >
                    <svg viewBox="0 0 24 24" aria-hidden="true">
                      {isIconName(s.icon) ? ICONS[s.icon] : s.icon}
                    </svg>
                    <span className="iqf-tip" aria-hidden="true">{s.label}</span>
                  </a>
                </li>
              ))}
            </ul>
          )}

          {authors.length > 0 && (
            <div className="iqf-authors iqf-fade" style={delay()}>
              <span className="iqf-authors-label">Built by</span>
              <div className="iqf-author-list">
                {authors.map((a, i) => (
                  <a
                    key={i}
                    className="iqf-author"
                    href={a.href}
                    target="_blank"
                    rel="noreferrer"
                  >
                    <span className="iqf-author-avatar" aria-hidden="true">
                      {a.name.charAt(0)}
                    </span>
                    <span className="iqf-author-name">{a.name}</span>
                    <svg className="iqf-author-gh" viewBox="0 0 24 24" aria-hidden="true">
                      <path
                        d="M9 19c-4.3 1.4-4.3-2.5-6-3m12 5v-3.5c0-1 .1-1.4-.5-2 2.8-.3 5.5-1.4 5.5-6a4.6 4.6 0 0 0-1.3-3.2 4.2 4.2 0 0 0-.1-3.2s-1.1-.3-3.5 1.3a12.3 12.3 0 0 0-6.2 0C6.5 2.8 5.4 3.1 5.4 3.1a4.2 4.2 0 0 0-.1 3.2A4.6 4.6 0 0 0 4 9.5c0 4.6 2.7 5.7 5.5 6-.6.6-.6 1.2-.5 2V21"
                        fill="none" stroke="currentColor" strokeWidth="1.5"
                        strokeLinecap="round" strokeLinejoin="round"
                      />
                    </svg>
                  </a>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Link columns */}
        {columns.map((col, ci) => (
          <nav key={col.title + ci} className="iqf-col" aria-label={col.title}>
            <p className="iqf-label" style={delay()}>{col.title}</p>
            <ul className="iqf-links">
              {col.links.map((l, li) => (
                <li key={l.label + li} className="iqf-fade" style={delay()}>
                  <a
                    className="iqf-link"
                    href={l.href || "#"}
                    onClick={(e) => follow(e, l.label, l.href)}
                    {...(l.href && /^https?:/.test(l.href) ? { target: "_blank", rel: "noreferrer" } : {})}
                  >
                    <span className="iqf-link-t">{l.label}</span>
                    <Arrow />
                  </a>
                </li>
              ))}
            </ul>
          </nav>
        ))}
      </div>

      {/* Giant bottom-cropped wordmark */}
      <div
        ref={wordRef}
        className="iqf-word"
        style={{ height: size ? wordHeight(size, base, cut) : "calc(" + (0.8 + cut) * 26 + "cqw)" }}
      >
        <p className="sr-only">{word}</p>
        <div className="iqf-word-box">
          <div ref={innerRef} className="iqf-word-in" aria-hidden="true">
            {letters.map((ch, i) => (
              <span
                key={i}
                className="iqf-lw"
                style={{ "--iqf-d": 240 + i * 70 + "ms" } as React.CSSProperties}
              >
                <span
                  className="iqf-l"
                  onClick={hop}
                  onAnimationEnd={(e) => e.currentTarget.classList.remove("is-hop")}
                >
                  {ch}
                </span>
              </span>
            ))}
          </div>
        </div>
        <div className="iqf-foot" aria-hidden="true" />
      </div>
    </footer>
  )
}
