import { useRef, useEffect } from 'react'
import { Canvas } from '@react-three/fiber'
import { gsap } from 'gsap'
import SentroLogo from '../SentroLogo'
import IntroScene, { type BootState } from './IntroScene'
import { COLORS, FONTS, prefersReducedMotion } from '../../utils/constants'

interface IntroProps {
  onComplete: () => void
}

const BOOT_LINES = [
  '> Initializing SENTRO core...',
  '> Scanning infrastructure...',
  '> Establishing secure channels...',
  '> System ready.',
]

// ─────────────────────────────────────────────────────────────────────────────
// "System boot" intro (~4s):
//   0.0–1.0s  grid draws itself in from the center; particles drift in
//   0.9–2.0s  the SENTRO logo rises cleanly from below; energy ring pulses out
//   2.0–3.2s  terminal boot text types in, line by line
//   3.3–4.1s  boot text fades, logo glows once, overlay fades → hero revealed
// The 3D grid matches the hero scene's grid + camera, so the reveal is seamless.
// ─────────────────────────────────────────────────────────────────────────────
export default function Intro({ onComplete }: IntroProps) {
  const containerRef = useRef<HTMLDivElement>(null)
  const logoWrapRef = useRef<HTMLDivElement>(null)
  const glowRef = useRef<HTMLDivElement>(null)
  const bootWrapRef = useRef<HTMLDivElement>(null)
  const lineRefs = useRef<(HTMLDivElement | null)[]>([])
  const tlRef = useRef<gsap.core.Timeline | null>(null)
  const bootState = useRef<BootState>({ grid: 0, ring: 0, particles: 0 })
  const reduced = prefersReducedMotion()

  useEffect(() => {
    // Reduced motion: skip the whole sequence — show the hero immediately.
    if (reduced) {
      onComplete()
      return
    }

    const tl = gsap.timeline()
    tlRef.current = tl
    const bs = bootState.current

    // ── Stage 1: grid awakens (0–1s) ──────────────────────────────────────
    tl.to(bs, { grid: 1, duration: 1.0, ease: 'power2.inOut' }, 0)
    tl.to(bs, { particles: 1, duration: 0.8, ease: 'power1.inOut' }, 0.3)

    // ── Stage 2: core materializes (0.9–2.0s) ─────────────────────────────
    // Clean vertical rise only — no bounce, no drift.
    tl.fromTo(
      logoWrapRef.current,
      { y: '100vh', opacity: 0 },
      { y: 0, opacity: 1, duration: 1.1, ease: 'power3.out' },
      0.9,
    )
    // Energy ring announces the system as the logo lands.
    tl.to(bs, { ring: 1, duration: 0.9, ease: 'power2.out' }, 1.55)

    // ── Stage 3: boot text (2.0–3.2s) ─────────────────────────────────────
    BOOT_LINES.forEach((text, i) => {
      const proxy = { n: 0 }
      tl.to(
        proxy,
        {
          n: text.length,
          duration: 0.26,
          ease: 'none',
          onUpdate() {
            const el = lineRefs.current[i]
            if (el) el.textContent = text.slice(0, Math.round(proxy.n))
          },
        },
        2.0 + i * 0.31,
      )
    })
    // Soft glow pulse behind the logo as "System ready." lands.
    tl.to(glowRef.current, { opacity: 0.4, duration: 0.3, ease: 'power2.out' }, 3.0)
    tl.to(glowRef.current, { opacity: 0.2, duration: 0.3, ease: 'power2.inOut' }, 3.3)

    // ── Stage 4: reveal (3.3–4.1s) ────────────────────────────────────────
    tl.to(bootWrapRef.current, { opacity: 0, duration: 0.35, ease: 'power2.in' }, 3.35)
    tl.to(containerRef.current, { opacity: 0, duration: 0.6, ease: 'power2.inOut', onComplete }, 3.5)

    return () => { tl.kill() }
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  const handleSkip = () => {
    tlRef.current?.kill()
    gsap.to(containerRef.current, { opacity: 0, duration: 0.3, ease: 'power2.in', onComplete })
  }

  if (reduced) return null

  return (
    <div
      ref={containerRef}
      style={{
        position: 'fixed', inset: 0, zIndex: 9999,
        background: COLORS.navyDeep,
        overflow: 'hidden',
      }}
    >
      {/* 3D boot scene — grid reveal, energy ring, particles */}
      <div aria-hidden="true" style={{ position: 'absolute', inset: 0 }}>
        <Canvas
          camera={{ position: [4.8, 4.7, 9.2], fov: 45, near: 0.1, far: 100 }}
          gl={{ antialias: true, alpha: true }}
          dpr={[1, 1.5]}
          style={{ background: 'transparent' }}
        >
          <IntroScene bootState={bootState} />
        </Canvas>
      </div>

      {/* Centered overlay content */}
      <div style={{
        position: 'absolute', inset: 0,
        display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
        pointerEvents: 'none',
      }}>
        {/* Soft cyan glow behind the logo */}
        <div
          ref={glowRef}
          aria-hidden="true"
          style={{
            position: 'absolute',
            width: '520px', height: '520px',
            borderRadius: '50%',
            background: `radial-gradient(circle, ${COLORS.accentCyan} 0%, transparent 62%)`,
            opacity: 0,
            filter: 'blur(8px)',
          }}
        />

        {/* Logo lockup — the actual SENTRO mark + wordmark, rising as one unit */}
        <div
          ref={logoWrapRef}
          style={{
            position: 'relative', zIndex: 1,
            display: 'flex', flexDirection: 'column', alignItems: 'center',
            gap: '22px',
            userSelect: 'none',
            opacity: 0,
            willChange: 'transform, opacity',
          }}
        >
          <div style={{ filter: `drop-shadow(0 0 26px rgba(0,229,255,0.28))` }}>
            <SentroLogo size={168} withGlow={false} lightColor="#cff0ff" glowBlur={1.6} />
          </div>
          <span
            style={{
              fontFamily: FONTS.display,
              fontWeight: 600,
              fontSize: 'clamp(1.6rem, 4vw, 2.4rem)',
              letterSpacing: '0.34em',
              paddingLeft: '0.34em',
              color: COLORS.cloudWhite,
              lineHeight: 1,
            }}
          >
            SENTRO
          </span>
        </div>

        {/* Terminal boot sequence */}
        <div
          ref={bootWrapRef}
          style={{
            position: 'relative', zIndex: 1,
            marginTop: '42px',
            minHeight: `${BOOT_LINES.length * 20}px`,
            display: 'flex', flexDirection: 'column', alignItems: 'flex-start', gap: '5px',
            fontFamily: FONTS.mono,
            fontSize: '12px',
            letterSpacing: '0.06em',
            color: 'rgba(0,229,255,0.75)',
            textShadow: '0 0 10px rgba(0,229,255,0.35)',
          }}
        >
          {BOOT_LINES.map((_, i) => (
            <div key={i} ref={(el) => (lineRefs.current[i] = el)} style={{ minHeight: '15px', whiteSpace: 'pre' }} />
          ))}
        </div>
      </div>

      {/* Skip */}
      <button
        onClick={handleSkip}
        style={{
          position: 'absolute', bottom: '42px', right: '46px',
          background: 'none',
          border: `1px solid rgba(0,229,255,0.16)`,
          borderRadius: '2px',
          color: 'rgba(0,229,255,0.4)',
          fontFamily: FONTS.mono,
          fontSize: '0.66rem', letterSpacing: '0.22em',
          padding: '7px 20px',
          zIndex: 25,
          textTransform: 'uppercase',
          transition: 'border-color 0.2s, color 0.2s',
        }}
        onMouseEnter={(e) => {
          e.currentTarget.style.borderColor = 'rgba(0,229,255,0.6)'
          e.currentTarget.style.color = 'rgba(0,229,255,0.92)'
        }}
        onMouseLeave={(e) => {
          e.currentTarget.style.borderColor = 'rgba(0,229,255,0.16)'
          e.currentTarget.style.color = 'rgba(0,229,255,0.4)'
        }}
      >
        Skip
      </button>
    </div>
  )
}
