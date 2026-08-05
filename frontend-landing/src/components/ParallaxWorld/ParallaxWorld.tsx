import { useEffect, useRef, useState } from 'react'
import { gsap } from 'gsap'
import { ScrollTrigger } from 'gsap/ScrollTrigger'
import { COLORS, FONTS } from '../../utils/constants'
import WorldScene from './WorldScene'
import StepperPanel from './StepperPanel'

gsap.registerPlugin(ScrollTrigger)

// Progress windows for each step [start, end] in 0–1 scroll range
const STEP_RANGES: [number, number][] = [
  [0.10, 0.30],
  [0.30, 0.55],
  [0.55, 0.75],
  [0.75, 1.00],
]

const STEP_LABELS = ['Discover', 'Classify', 'Monitor', 'Secure']
const STEP_DESCS  = [
  'Auto-scanning every data source across cloud, on-prem, and SaaS.',
  'ML-powered tagging — PII, PHI, PCI, secrets, and custom types.',
  'Continuous radar watch. Real-time alerts on anomalies and risk spikes.',
  'Policies enforced, posture hardened, every asset accounted for.',
]

function resolveStep(p: number): { step: number; stepProgress: number } {
  if (p < STEP_RANGES[0][0]) return { step: 0, stepProgress: 0 }
  for (let i = 0; i < STEP_RANGES.length; i++) {
    const [s, e] = STEP_RANGES[i]
    if (p <= e) return { step: i, stepProgress: (p - s) / (e - s) }
  }
  return { step: 3, stepProgress: 1 }
}

export default function ParallaxWorld() {
  const outerRef = useRef<HTMLDivElement>(null)

  const [activeStep,    setActiveStep]    = useState(0)
  const [stepProgress,  setStepProgress]  = useState(0)
  const [rawProgress,   setRawProgress]   = useState(0)
  const [heroVisible,   setHeroVisible]   = useState(true)

  useEffect(() => {
    const outer = outerRef.current
    if (!outer) return

    const st = ScrollTrigger.create({
      trigger: outer,
      start: 'top top',
      end:   'bottom bottom',
      scrub: true,
      onUpdate(self) {
        const p = self.progress
        setRawProgress(p)
        setHeroVisible(p < 0.08)
        const { step, stepProgress: sp } = resolveStep(p)
        setActiveStep(step)
        setStepProgress(sp)
      },
    })

    return () => st.kill()
  }, [])

  const panelVisible = !heroVisible

  return (
    <section
      id="parallax-world"
      aria-label="SENTRO data security in action"
      ref={outerRef}
      style={{ height: '400vh', position: 'relative' }}
    >
      {/* ── Sticky viewport ─────────────────────────────────────────────── */}
      <div style={{
        position: 'sticky', top: 0, height: '100vh', overflow: 'hidden',
        background: COLORS.navyDeep,
      }}>

        {/* Isometric SVG world */}
        <WorldScene activeStep={activeStep} stepProgress={stepProgress} rawProgress={rawProgress} />

        {/* ── Hero overlay (0–10% scroll) ────────────────────────────── */}
        <div style={{
          position: 'absolute', inset: 0,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          pointerEvents: 'none', zIndex: 10,
          opacity: heroVisible ? 1 : 0,
          transform: heroVisible ? 'translateY(0)' : 'translateY(-24px)',
          transition: 'opacity 0.55s ease, transform 0.55s ease',
        }}>
          <h2 style={{
            fontFamily: FONTS.display,
            fontSize: 'clamp(2rem, 5.5vw, 68px)',
            fontWeight: 700,
            color: COLORS.cloudWhite,
            textAlign: 'center',
            lineHeight: 1.12,
            letterSpacing: '-0.02em',
            maxWidth: '780px',
            padding: '0 32px',
            opacity: 0.9,
            textShadow: `0 2px 50px rgba(0,229,255,0.12)`,
          }}>
            Your Data.<br />Fully Visible.<br />Fully Secured.
          </h2>
        </div>

        {/* ── Left stepper panel ────────────────────────────────────── */}
        <div style={{
          position: 'absolute', left: 'clamp(24px, 4vw, 60px)', top: '50%',
          transform: 'translateY(-50%)',
          zIndex: 20,
          opacity: panelVisible ? 1 : 0,
          transition: 'opacity 0.5s ease 0.1s',
          pointerEvents: 'none',
        }}>
          <StepperPanel activeStep={activeStep} stepProgress={stepProgress} />
        </div>

        {/* ── Step label — bottom-right ─────────────────────────────── */}
        <div style={{
          position: 'absolute', right: 'clamp(24px, 5vw, 72px)', bottom: '64px',
          zIndex: 20, textAlign: 'right', pointerEvents: 'none',
          opacity: panelVisible ? 1 : 0,
          transform: panelVisible ? 'translateY(0)' : 'translateY(12px)',
          transition: 'opacity 0.45s ease 0.1s, transform 0.45s ease 0.1s',
        }}>
          <div style={{
            fontFamily: FONTS.mono, fontSize: '10px',
            letterSpacing: '0.22em', textTransform: 'uppercase',
            color: COLORS.accentCyan, opacity: 0.65, marginBottom: '8px',
          }}>
            PHASE {String(activeStep + 1).padStart(2, '0')}
          </div>
          <div style={{
            fontFamily: FONTS.display,
            fontSize: 'clamp(1.3rem, 2.2vw, 28px)',
            fontWeight: 600, color: COLORS.cloudWhite, marginBottom: '8px',
          }}>
            {STEP_LABELS[activeStep]}
          </div>
          <div style={{
            fontFamily: FONTS.body, fontSize: '13px',
            color: COLORS.cloudMuted, maxWidth: '260px',
            lineHeight: 1.55,
          }}>
            {STEP_DESCS[activeStep]}
          </div>
        </div>

        {/* ── Top progress bar ─────────────────────────────────────── */}
        <div style={{
          position: 'absolute', top: 0, left: 0, right: 0,
          height: '2px', zIndex: 30, pointerEvents: 'none',
          background: `${COLORS.navyLight}60`,
        }}>
          <div style={{
            height: '100%',
            width: `${rawProgress * 100}%`,
            background: `linear-gradient(90deg, ${COLORS.accentCyan}, ${COLORS.accentPurple})`,
            transition: 'width 0.04s linear',
          }} />
        </div>

        {/* ── Scroll cue (visible before first step) ───────────────── */}
        <div style={{
          position: 'absolute', bottom: '32px', left: '50%',
          transform: 'translateX(-50%)',
          zIndex: 20, pointerEvents: 'none',
          opacity: heroVisible ? 1 : 0,
          transition: 'opacity 0.4s ease',
          display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '8px',
        }}>
          <div style={{
            fontFamily: FONTS.mono, fontSize: '10px',
            letterSpacing: '0.2em', color: COLORS.cloudMuted,
            textTransform: 'uppercase', opacity: 0.5,
          }}>Scroll to explore</div>
          <svg width="16" height="24" viewBox="0 0 16 24" fill="none">
            <rect x="1" y="1" width="14" height="22" rx="7"
              stroke={COLORS.cloudMuted} strokeWidth="1" opacity="0.35" />
            <circle cx="8" cy="6" r="2.5" fill={COLORS.accentCyan} opacity="0.7">
              <animateTransform attributeName="transform" type="translate"
                values="0 0; 0 10; 0 0" dur="1.8s" repeatCount="indefinite" />
            </circle>
          </svg>
        </div>
      </div>
    </section>
  )
}
