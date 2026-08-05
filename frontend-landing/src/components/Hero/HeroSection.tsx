import { useEffect, useRef } from 'react'
import { gsap } from 'gsap'
import { ScrollTrigger } from 'gsap/ScrollTrigger'
import { COLORS, FONTS, BREAKPOINTS, prefersReducedMotion } from '../../utils/constants'
import { useMousePositionRef } from '../../hooks/useMousePosition'
import { clamp } from '../../utils/lerp'
import HeroText from './HeroText'
import HeroScene from './HeroScene'

gsap.registerPlugin(ScrollTrigger)

export default function HeroSection() {
  const mouseRef = useMousePositionRef()

  const sectionRef = useRef<HTMLElement>(null)
  const exitWrapRef = useRef<HTMLDivElement>(null)
  const hintRef = useRef<HTMLDivElement>(null)
  // Shared scroll progress (0→1) consumed by the 3D scene to dim the grid as the hero exits
  const progressRef = useRef(0)

  useEffect(() => {
    const section = sectionRef.current
    if (!section || prefersReducedMotion()) return

    // Hero exit: as the section scrolls away, the text scales up + drifts up + fades,
    // the scroll hint fades early, and the grid relaxes back to its resting state.
    const st = ScrollTrigger.create({
      trigger: section,
      start: 'top top',
      end: '+=45%',
      scrub: 1,
      onUpdate: (self) => {
        const p = clamp(self.progress, 0, 1)
        progressRef.current = p

        if (exitWrapRef.current) {
          exitWrapRef.current.style.transform = `translate3d(0, ${-60 * p}px, 0) scale(${1 + 0.15 * p})`
          exitWrapRef.current.style.opacity = String(1 - clamp(p / 0.85, 0, 1))
        }
        if (hintRef.current) {
          hintRef.current.style.opacity = String(1 - clamp(p / 0.1, 0, 1))
        }
      },
    })

    return () => st.kill()
  }, [])

  return (
    <section
      ref={sectionRef}
      id="hero"
      aria-label="Hero"
      style={{
        position: 'relative',
        minHeight: '100vh',
        background: COLORS.navyDeep,
        overflow: 'hidden',
      }}
    >
      {/* ── LAYER 0: Full-bleed isometric 3D world ──────────────────── */}
      <div
        aria-hidden="true"
        style={{ position: 'absolute', inset: 0, zIndex: 0 }}
      >
        <HeroScene mouseRef={mouseRef} progressRef={progressRef} />
      </div>

      {/* ── LAYER 1: Radial vignette — gives the text visual weight ──── */}
      <div
        aria-hidden="true"
        style={{
          position: 'absolute',
          inset: 0,
          zIndex: 1,
          pointerEvents: 'none',
          background:
            'radial-gradient(ellipse 52% 44% at 50% 50%, rgba(7,11,26,0.62) 0%, rgba(7,11,26,0.40) 42%, transparent 74%)',
        }}
      />

      {/* ── LAYER 2: Centered hero text + CTAs (exit-transformed) ────── */}
      <div
        ref={exitWrapRef}
        style={{
          position: 'absolute',
          inset: 0,
          zIndex: 2,
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          textAlign: 'center',
          padding: '0 6vw',
          willChange: 'transform, opacity',
        }}
      >
        <HeroText />
      </div>

      {/* ── LAYER 3: Scroll hint ────────────────────────────────────── */}
      <div
        ref={hintRef}
        aria-hidden="true"
        style={{
          position: 'absolute',
          bottom: '60px',
          left: '50%',
          transform: 'translateX(-50%)',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          gap: '14px',
          zIndex: 3,
          pointerEvents: 'none',
        }}
      >
        <span
          style={{
            fontFamily: FONTS.mono,
            fontSize: '12px',
            letterSpacing: '0.3em',
            textTransform: 'uppercase',
            color: COLORS.cloudMuted,
          }}
        >
          Scroll to discover
        </span>
        <div
          style={{
            position: 'relative',
            width: '1px',
            height: '40px',
            background: 'rgba(0,229,255,0.25)',
            overflow: 'hidden',
          }}
        >
          <span
            style={{
              position: 'absolute',
              top: 0,
              left: '50%',
              width: '4px',
              height: '4px',
              marginLeft: '-2px',
              borderRadius: '50%',
              background: COLORS.accentCyan,
              boxShadow: `0 0 6px ${COLORS.accentCyan}`,
              animation: 'hero-scroll-dot 2s ease-in-out infinite',
            }}
          />
        </div>
      </div>

      <style>{`
        @media (max-width: ${BREAKPOINTS.mobile}px) {
          #hero { min-height: 100vh; }
        }
      `}</style>
    </section>
  )
}
