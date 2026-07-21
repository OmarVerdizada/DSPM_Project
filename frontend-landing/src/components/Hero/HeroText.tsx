import { useEffect, useRef } from 'react'
import { gsap } from 'gsap'
import { COLORS, FONTS, prefersReducedMotion } from '../../utils/constants'
import { useMousePositionRef } from '../../hooks/useMousePosition'
import { lerp } from '../../utils/lerp'

const hasSeenIntro = (): boolean => {
  try {
    return sessionStorage.getItem('sentro-intro-seen') === 'true'
  } catch {
    return false
  }
}

// The gradient shared by the two accent words.
const WORD_GRADIENT = `linear-gradient(135deg, ${COLORS.accentCyan}, ${COLORS.accentBlue}, ${COLORS.accentPurple})`
const gradientWord = {
  background: WORD_GRADIENT,
  WebkitBackgroundClip: 'text',
  WebkitTextFillColor: 'transparent',
  backgroundClip: 'text',
} as const

// Parallax intensity per line — the last line moves most (reads as "closest").
const PARALLAX_FACTORS = [0.4, 0.7, 1.0]

export default function HeroText() {
  const mouseRef = useMousePositionRef()

  const lineWrapRefs = [
    useRef<HTMLDivElement>(null),
    useRef<HTMLDivElement>(null),
    useRef<HTMLDivElement>(null),
  ]
  const lineInnerRefs = [
    useRef<HTMLSpanElement>(null),
    useRef<HTMLSpanElement>(null),
    useRef<HTMLSpanElement>(null),
  ]
  const btnsRef = useRef<HTMLDivElement>(null)

  // ── Sequential entrance (runs after the opening overlay finishes) ──
  useEffect(() => {
    const inners = lineInnerRefs.map((r) => r.current)
    const buttons = btnsRef.current

    if (prefersReducedMotion()) {
      gsap.set([...inners, buttons], { y: 0, opacity: 1 })
      return
    }

    let tl: gsap.core.Timeline | null = null
    const play = () => {
      tl = gsap.timeline({ defaults: { ease: 'power3.out' } })
      tl.set(inners, { y: 40, opacity: 0 })
      tl.set(buttons, { y: 30, opacity: 0 })
      tl.to(inners[0], { y: 0, opacity: 1, duration: 0.6 }, 0.3)
      tl.to(inners[1], { y: 0, opacity: 1, duration: 0.6 }, 0.6)
      tl.to(inners[2], { y: 0, opacity: 1, duration: 0.6 }, 0.9)
      tl.to(buttons, { y: 0, opacity: 1, duration: 0.6 }, 1.35)
    }

    // Hide until the reveal fires so the animation isn't spent behind the overlay.
    gsap.set([...inners, buttons], { opacity: 0 })

    if (hasSeenIntro()) {
      play()
      return () => tl?.kill()
    }

    window.addEventListener('sentro-hero-reveal', play, { once: true })
    return () => {
      window.removeEventListener('sentro-hero-reveal', play)
      tl?.kill()
    }
  }, [])

  // ── Per-line mouse parallax (rAF, lerped) ─────────────────────────
  useEffect(() => {
    if (prefersReducedMotion()) return

    const cur = { x: 0, y: 0 }
    let raf = 0

    const tick = () => {
      const mx = mouseRef.current?.x ?? 0
      const my = mouseRef.current?.y ?? 0
      const tx = (mx / (window.innerWidth || 1) - 0.5) * 2
      const ty = (my / (window.innerHeight || 1) - 0.5) * 2
      cur.x = lerp(cur.x, tx, 0.06)
      cur.y = lerp(cur.y, ty, 0.06)

      lineWrapRefs.forEach((ref, i) => {
        const el = ref.current
        if (!el) return
        const f = PARALLAX_FACTORS[i]
        el.style.transform = `translate3d(${cur.x * 8 * f}px, ${cur.y * 5 * f}px, 0)`
      })

      raf = requestAnimationFrame(tick)
    }
    raf = requestAnimationFrame(tick)

    return () => cancelAnimationFrame(raf)
  }, [mouseRef])

  const scrollToSection = (id: string) => {
    const el = document.getElementById(id)
    if (el) el.scrollIntoView({ behavior: 'smooth' })
  }

  const lineStyle = {
    display: 'block',
    fontSize: 'clamp(44px, 8.5vw, 104px)',
    lineHeight: 1.0,
  } as const

  return (
    <div style={{ maxWidth: '1100px', width: '100%' }}>
      <h1
        style={{
          fontFamily: FONTS.display,
          fontWeight: 700,
          lineHeight: 1.0,
          letterSpacing: '-0.02em',
          color: COLORS.cloudWhite,
          margin: 0,
        }}
      >
        <div ref={lineWrapRefs[0]} style={{ willChange: 'transform' }}>
          <span ref={lineInnerRefs[0]} style={lineStyle}>
            Your Data.
          </span>
        </div>
        <div ref={lineWrapRefs[1]} style={{ willChange: 'transform' }}>
          <span ref={lineInnerRefs[1]} style={lineStyle}>
            Fully <span style={gradientWord}>Visible.</span>
          </span>
        </div>
        <div ref={lineWrapRefs[2]} style={{ willChange: 'transform' }}>
          <span ref={lineInnerRefs[2]} style={lineStyle}>
            Fully <span style={gradientWord}>Secured.</span>
          </span>
        </div>
      </h1>

      {/* CTAs */}
      <div
        ref={btnsRef}
        style={{
          display: 'flex',
          gap: '16px',
          flexWrap: 'wrap',
          justifyContent: 'center',
          marginTop: 'clamp(32px, 4vh, 52px)',
        }}
      >
        <a
          href="/login"
          style={{
            fontFamily: FONTS.body,
            fontSize: '15px',
            fontWeight: 600,
            color: '#ffffff',
            background: COLORS.accentBlue,
            border: 'none',
            borderRadius: '8px',
            padding: '14px 28px',
            textDecoration: 'none',
            display: 'inline-block',
            transition: 'box-shadow 0.25s ease, transform 0.2s ease',
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.boxShadow = `0 0 24px rgba(59,107,245,0.5), 0 0 48px rgba(59,107,245,0.2)`
            e.currentTarget.style.transform = 'translateY(-2px)'
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.boxShadow = 'none'
            e.currentTarget.style.transform = 'translateY(0)'
          }}
        >
          Launch Dashboard
        </a>

        <button
          onClick={() => scrollToSection('how-it-works')}
          style={{
            fontFamily: FONTS.body,
            fontSize: '15px',
            fontWeight: 500,
            color: COLORS.cloudWhite,
            background: 'transparent',
            border: `1px solid ${COLORS.navyLight}`,
            borderRadius: '8px',
            padding: '14px 28px',
            transition: 'border-color 0.25s ease, box-shadow 0.25s ease, transform 0.2s ease',
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.borderColor = COLORS.accentCyan
            e.currentTarget.style.boxShadow = `0 0 16px rgba(0,229,255,0.2)`
            e.currentTarget.style.transform = 'translateY(-2px)'
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.borderColor = COLORS.navyLight
            e.currentTarget.style.boxShadow = 'none'
            e.currentTarget.style.transform = 'translateY(0)'
          }}
        >
          Watch Demo
        </button>
      </div>
    </div>
  )
}
