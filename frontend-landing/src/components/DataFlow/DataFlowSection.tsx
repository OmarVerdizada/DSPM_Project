import { useEffect, useRef, useState } from 'react'
import { gsap } from 'gsap'
import { ScrollTrigger } from 'gsap/ScrollTrigger'
import { COLORS, FONTS, prefersReducedMotion } from '../../utils/constants'
import { useMousePositionRef } from '../../hooks/useMousePosition'
import { clamp, mapRange, lerp } from '../../utils/lerp'
import DataCenterScene from './DataCenterScene'
import ProgressIndicator from './ProgressIndicator'
import HeroText from '../Hero/HeroText'

gsap.registerPlugin(ScrollTrigger)

interface Phase { heading: string; subtext: string; gradient?: boolean }

const PHASES: Phase[] = [
  { heading: 'Discover', subtext: 'SENTRO scans SMB file servers, local datasets, and Windows endpoints to discover sensitive files, hidden data, and risky access.' },
  { heading: 'Classify', subtext: 'AI-powered classification identifies PII, PHI, financial data, and secrets along the route in real time.' },
  { heading: 'Monitor', subtext: 'Continuous monitoring tracks every packet of data as it flows toward the secured hub.' },
  { heading: 'Secure', subtext: 'Data arrives at the SENTRO database. Complete visibility. Zero blind spots.', gradient: true },
]

const PHASE_LABELS = PHASES.map((p) => p.heading)

function phaseIndexFor(p: number): number {
  if (p < 0.30) return 0
  if (p < 0.55) return 1
  if (p < 0.75) return 2
  return 3
}

export default function DataFlowSection() {
  const sectionRef = useRef<HTMLElement>(null)
  const hintRef = useRef<HTMLDivElement>(null)
  const progressRef = useRef(0)
  const mouseRef = useMousePositionRef()
  const [progress, setProgress] = useState(0)

  useEffect(() => {
    const section = sectionRef.current
    if (!section) return

    // Reduced motion: show the completed, secured end state — no pin/scrub.
    if (prefersReducedMotion()) {
      progressRef.current = 1
      setProgress(1)
      if (hintRef.current) hintRef.current.style.opacity = '0'
      return
    }

    const st = ScrollTrigger.create({
      trigger: section,
      start: 'top top',
      end: '+=360%',
      pin: true,
      scrub: 1,
      onUpdate: (self) => {
        const p = self.progress
        progressRef.current = p
        setProgress(p)
        if (hintRef.current) hintRef.current.style.opacity = String(1 - clamp(p / 0.06, 0, 1))
      },
    })

    return () => st.kill()
  }, [])

  const phaseIndex = phaseIndexFor(progress)
  const phase = PHASES[phaseIndex]

  // Hero text (front layer) rises + fades over the first 10% of scroll.
  const h = clamp(progress / 0.1, 0, 1)
  const heroExit = {
    transform: `translate3d(0, ${-60 * h}px, 0) scale(${1 + 0.15 * h})`,
    opacity: 1 - h,
    pointerEvents: (h > 0.9 ? 'none' : 'auto') as 'none' | 'auto',
  }

  const journeyUI = clamp(mapRange(progress, 0.10, 0.16, 0, 1), 0, 1) // fade UI in after hero
  const counterVal = Math.round(lerp(0, 10516, clamp(mapRange(progress, 0.85, 0.95, 0, 1), 0, 1)))
  const counterOp = clamp(mapRange(progress, 0.80, 0.86, 0, 1), 0, 1)

  // Arrival shock ring — expands out of the database hub as data arrives.
  const ringT = clamp(mapRange(progress, 0.88, 1.0, 0, 1), 0, 1)
  const showRing = ringT > 0.001 && ringT < 0.999

  return (
    <section
      ref={sectionRef}
      id="data-flow"
      aria-label="Data security journey"
      style={{ position: 'relative', height: '100vh', overflow: 'hidden', background: COLORS.navyDeep }}
    >
      {/* ── LAYER 0: Persistent 3D database environment ─────────────────────── */}
      <div aria-hidden="true" style={{ position: 'absolute', inset: 0, zIndex: 0 }}>
        <DataCenterScene progressRef={progressRef} mouseRef={mouseRef} />
      </div>

      {/* ── LAYER 1: Vignette — weight for the hero text ────────────────────── */}
      <div aria-hidden="true" style={{
        position: 'absolute', inset: 0, zIndex: 1, pointerEvents: 'none',
        background: 'radial-gradient(ellipse 55% 46% at 50% 48%, rgba(7,11,26,0.55) 0%, rgba(7,11,26,0.30) 44%, transparent 76%)',
        opacity: 1 - h * 0.7,
      }} />

      {/* ── LAYER 2: Hero text (front) — rises + fades on scroll ────────────── */}
      <div
        style={{
          position: 'absolute', inset: 0, zIndex: 6,
          display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
          textAlign: 'center', padding: '0 6vw',
          willChange: 'transform, opacity',
          ...heroExit,
        }}
      >
        <HeroText />
      </div>

      {/* ── Scroll hint ─────────────────────────────────────────────────────── */}
      <div ref={hintRef} aria-hidden="true" style={{
        position: 'absolute', bottom: '60px', left: '50%', transform: 'translateX(-50%)',
        display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '14px',
        zIndex: 6, pointerEvents: 'none',
      }}>
        <span style={{ fontFamily: FONTS.mono, fontSize: '12px', letterSpacing: '0.3em', textTransform: 'uppercase', color: COLORS.cloudMuted }}>
          Scroll to discover
        </span>
        <div style={{ position: 'relative', width: '1px', height: '40px', background: 'rgba(0,229,255,0.25)', overflow: 'hidden' }}>
          <span style={{
            position: 'absolute', top: 0, left: '50%', width: '4px', height: '4px', marginLeft: '-2px',
            borderRadius: '50%', background: COLORS.accentCyan, boxShadow: `0 0 6px ${COLORS.accentCyan}`,
            animation: 'hero-scroll-dot 2s ease-in-out infinite',
          }} />
        </div>
      </div>

      {/* ── LAYER 3: Vertical step indicator ────────────────────────────────── */}
      <div style={{
        position: 'absolute', left: 'clamp(20px, 3.5vw, 52px)', top: '50%',
        transform: 'translateY(-50%)', zIndex: 10, opacity: journeyUI,
      }}>
        <ProgressIndicator progress={clamp(mapRange(progress, 0.10, 1.0, 0, 0.999), 0, 0.999)} phases={PHASE_LABELS} />
      </div>

      {/* ── LAYER 3: Phase text — bottom-left ───────────────────────────────── */}
      <div style={{
        position: 'absolute', left: 'clamp(100px, 13vw, 220px)', bottom: 'clamp(60px, 8vh, 100px)',
        zIndex: 10, maxWidth: '360px', opacity: journeyUI, pointerEvents: 'none',
      }}>
        <div key={phaseIndex} style={{ animation: 'dfs-slide-in 0.38s ease forwards' }}>
          <div style={{ fontFamily: FONTS.mono, fontSize: '10px', letterSpacing: '0.2em', textTransform: 'uppercase', color: COLORS.accentCyan, opacity: 0.7, marginBottom: '12px' }}>
            {`PHASE ${String(phaseIndex + 1).padStart(2, '0')}`}
          </div>
          <h2 style={{
            fontFamily: FONTS.display, fontWeight: 700, fontSize: 'clamp(2rem, 3.8vw, 52px)', lineHeight: 1.05, marginBottom: '14px',
            ...(phase.gradient
              ? { background: `linear-gradient(135deg, ${COLORS.accentCyan}, ${COLORS.accentBlue})`, WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent', backgroundClip: 'text' }
              : { color: COLORS.cloudWhite }),
          }}>
            {phase.heading}
          </h2>
          <p style={{ fontFamily: FONTS.body, fontSize: '15px', lineHeight: 1.7, color: COLORS.cloudMuted, maxWidth: '300px' }}>
            {phase.subtext}
          </p>
        </div>
      </div>

      {/* ── LAYER 4: Arrival shock ring ─────────────────────────────────────── */}
      {showRing && (
        <div aria-hidden="true" style={{
          position: 'absolute', left: '48%', top: '46%',
          width: '68vw', height: '68vw', maxWidth: '900px', maxHeight: '900px',
          borderRadius: '50%', border: `2px solid ${COLORS.accentCyan}`,
          transform: `translate(-50%, -50%) scale(${ringT})`,
          opacity: (1 - ringT) * 0.6, zIndex: 5, pointerEvents: 'none',
          boxShadow: `0 0 24px rgba(0,229,255,0.4)`,
        }} />
      )}

      {/* ── LAYER 4: Arrival counter ────────────────────────────────────────── */}
      {counterOp > 0.01 && (
        <div style={{
          position: 'absolute', left: '50%', top: '20%', transform: 'translateX(-50%)',
          zIndex: 8, opacity: counterOp, pointerEvents: 'none',
          fontFamily: FONTS.mono, fontSize: '13px', letterSpacing: '0.06em',
          color: COLORS.accentCyan, background: 'rgba(15,21,53,0.92)',
          border: `1px solid ${COLORS.accentCyan}`, borderRadius: '6px', padding: '8px 18px',
          boxShadow: `0 0 18px rgba(0,229,255,0.35)`,
        }}>
          {counterVal.toLocaleString()} assets secured
        </div>
      )}

      <style>{`
        @keyframes dfs-slide-in {
          from { opacity: 0; transform: translateY(18px); }
          to   { opacity: 1; transform: translateY(0); }
        }
      `}</style>
    </section>
  )
}
