import { useEffect, useRef, useState } from 'react'
import { gsap } from 'gsap'
import { ScrollTrigger } from 'gsap/ScrollTrigger'
import { COLORS, FONTS } from '../../utils/constants'

gsap.registerPlugin(ScrollTrigger)

interface Step {
  number: string
  title: string
  body: string
  icon: React.ReactNode
}

function ConnectIcon() {
  return (
    <svg width="180" height="180" viewBox="0 0 180 180" fill="none" aria-hidden="true">
      <circle cx="90" cy="90" r="20" fill={`${COLORS.accentCyan}15`} stroke={COLORS.accentCyan} strokeWidth="1.5" />
      <circle cx="90" cy="90" r="6" fill={COLORS.accentCyan} opacity="0.8" />
      {[0, 1, 2, 3].map((i) => {
        const angle = (i * 90) * (Math.PI / 180)
        const x2 = 90 + Math.cos(angle) * 50
        const y2 = 90 + Math.sin(angle) * 50
        const px = 90 + Math.cos(angle) * 70
        const py = 90 + Math.sin(angle) * 70
        return (
          <g key={i}>
            <line x1="90" y1="90" x2={x2} y2={y2} stroke={COLORS.accentCyan} strokeWidth="1" opacity="0.4" strokeDasharray="3 2" />
            <rect x={px - 10} y={py - 10} width="20" height="20" rx="4"
              fill={`${COLORS.accentBlue}20`} stroke={COLORS.accentBlue} strokeWidth="1.5" />
            {/* server slats + status light */}
            <line x1={px - 5} y1={py - 3} x2={px + 5} y2={py - 3} stroke={COLORS.accentBlue} strokeWidth="1" opacity="0.7" />
            <line x1={px - 5} y1={py + 1} x2={px + 5} y2={py + 1} stroke={COLORS.accentBlue} strokeWidth="1" opacity="0.7" />
            <circle cx={px - 4} cy={py + 5.5} r="1.2" fill={COLORS.accentCyan} opacity="0.9" />
          </g>
        )
      })}
    </svg>
  )
}

function ScanIcon() {
  return (
    <svg width="180" height="180" viewBox="0 0 180 180" fill="none" aria-hidden="true">
      {[0, 1, 2, 3, 4].map((row) =>
        [0, 1, 2, 3, 4].map((col) => (
          <rect key={`${row}-${col}`}
            x={40 + col * 22} y={50 + row * 18}
            width="16" height="12" rx="2"
            fill="none" stroke={COLORS.navyLight} strokeWidth="1" />
        ))
      )}
      <line
        x1="40" y1="90" x2="140" y2="90"
        stroke={COLORS.accentCyan} strokeWidth="2" opacity="0.7"
        strokeDasharray="4 2"
        style={{ animation: 'radar-sweep 2s linear infinite' }}
      />
      <polygon points="40,85 48,90 40,95" fill={COLORS.accentCyan} opacity="0.6" />
    </svg>
  )
}

function AnalyzeIcon() {
  return (
    <svg width="180" height="180" viewBox="0 0 180 180" fill="none" aria-hidden="true">
      <path d="M50 50 L70 50 L80 90 L100 30 L120 90 L130 70 L150 70" stroke={COLORS.accentCyan} strokeWidth="1.5" fill="none" strokeLinecap="round" strokeLinejoin="round" opacity="0.6" />
      <path d="M80 90 L80 130 L100 130 L100 30" fill={`${COLORS.accentBlue}15`} stroke="none" />
      <line x1="50" y1="130" x2="150" y2="130" stroke={COLORS.navyLight} strokeWidth="1" />
      <circle cx="90" cy="90" r="35" fill="none" stroke={COLORS.accentPurple} strokeWidth="1" strokeDasharray="6 4" opacity="0.4" />
      <circle cx="90" cy="90" r="8" fill={`${COLORS.accentCyan}30`} stroke={COLORS.accentCyan} strokeWidth="1.5" />
    </svg>
  )
}

function ProtectIcon() {
  return (
    <svg width="180" height="180" viewBox="0 0 180 180" fill="none" aria-hidden="true">
      <path d="M90 30 L140 50 L140 100 C140 130 90 155 90 155 C90 155 40 130 40 100 L40 50 Z"
        fill={`${COLORS.accentCyan}10`} stroke={COLORS.accentCyan} strokeWidth="1.8" />
      <path d="M90 30 L140 50 L140 100 C140 130 90 155 90 155 C90 155 40 130 40 100 L40 50 Z"
        fill="none" stroke={COLORS.accentCyan} strokeWidth="1" opacity="0.3"
        transform="scale(1.12) translate(-10, -5)" />
      <path d="M70 92 L84 106 L112 78"
        stroke={COLORS.accentCyan} strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" />
      <circle cx="90" cy="92" r="35" fill="none" stroke={COLORS.accentCyan} strokeWidth="0.5" opacity="0.2"
        style={{ animation: 'pulse-glow 2.5s ease-in-out infinite' }} />
    </svg>
  )
}

const STEPS: Step[] = [
  {
    number: '01',
    title: 'Connect',
    body: 'Connect SMB servers, local datasets, and Windows endpoints through WinRM.',
    icon: <ConnectIcon />,
  },
  {
    number: '02',
    title: 'Scan',
    body: 'Discover files, hidden data, permissions, ownership, and source metadata.',
    icon: <ScanIcon />,
  },
  {
    number: '03',
    title: 'Analyze',
    body: 'Detect sensitive data, classify findings, and calculate contextual risk scores.',
    icon: <AnalyzeIcon />,
  },
  {
    number: '04',
    title: 'Protect',
    body: 'Prioritize risky files, guide remediation, and export audit-ready evidence.',
    icon: <ProtectIcon />,
  },
]

export default function HorizontalSteps() {
  const outerRef = useRef<HTMLDivElement>(null)
  const innerRef = useRef<HTMLDivElement>(null)
  const stepsRef = useRef<HTMLDivElement>(null)
  const [activeStep, setActiveStep] = useState(0)

  useEffect(() => {
    const outer = outerRef.current
    const inner = innerRef.current
    const steps = stepsRef.current
    if (!outer || !inner || !steps) return

    const getMaxX = () => steps.scrollWidth - window.innerWidth

    const st = ScrollTrigger.create({
      trigger: outer,
      start: 'top top',
      end: 'bottom bottom',
      scrub: 1,
      onUpdate: (self) => {
        const maxX = getMaxX()
        gsap.set(steps, { x: -self.progress * maxX })
        setActiveStep(Math.min(STEPS.length - 1, Math.floor(self.progress * STEPS.length)))
      },
    })

    return () => st.kill()
  }, [])

  return (
    <section
      id="how-it-works"
      aria-label="How SENTRO works"
      style={{
        background: COLORS.navyDeep,
      }}
    >
      {/* Section header (above the scroll area) */}
      <div
        style={{
          padding: '100px 8vw 0',
          textAlign: 'center',
          maxWidth: '800px',
          margin: '0 auto',
        }}
      >
        <div
          style={{
            fontFamily: FONTS.mono,
            fontSize: '12px',
            letterSpacing: '0.25em',
            textTransform: 'uppercase',
            color: COLORS.accentCyan,
            marginBottom: '12px',
          }}
        >
          HOW IT WORKS
        </div>
        <h2
          style={{
            fontFamily: FONTS.display,
            fontSize: 'clamp(1.8rem, 3.5vw, 44px)',
            fontWeight: 600,
            color: COLORS.cloudWhite,
            marginBottom: '8px',
          }}
        >
          From Connect to Secure in Minutes
        </h2>
      </div>

      {/* Horizontal scroll area */}
      <div
        ref={outerRef}
        style={{
          height: '400vh',
          position: 'relative',
        }}
      >
        <div
          ref={innerRef}
          style={{
            position: 'sticky',
            top: 0,
            height: '100vh',
            overflow: 'hidden',
            display: 'flex',
            alignItems: 'center',
          }}
        >
          {/* Step indicator dots */}
          <div
            style={{
              position: 'absolute',
              bottom: '40px',
              left: '50%',
              transform: 'translateX(-50%)',
              display: 'flex',
              gap: '10px',
              zIndex: 10,
            }}
          >
            {STEPS.map((_, i) => (
              <div
                key={i}
                style={{
                  width: i === activeStep ? '24px' : '8px',
                  height: '8px',
                  borderRadius: '4px',
                  background: i === activeStep ? COLORS.accentCyan : COLORS.navyLight,
                  transition: 'all 0.3s ease',
                  boxShadow: i === activeStep ? `0 0 8px ${COLORS.accentCyan}` : 'none',
                }}
              />
            ))}
          </div>

          {/* Steps strip */}
          <div
            ref={stepsRef}
            style={{
              display: 'flex',
              gap: '5vw',
              paddingLeft: '10vw',
              paddingRight: '10vw',
              willChange: 'transform',
            }}
          >
            {STEPS.map((step, i) => (
              <div
                key={step.number}
                style={{
                  width: '80vw',
                  maxWidth: '900px',
                  flexShrink: 0,
                  display: 'flex',
                  alignItems: 'center',
                  gap: '80px',
                  padding: '60px 60px',
                  background: `${COLORS.navyMid}60`,
                  border: `1px solid ${i === activeStep ? COLORS.accentCyan : COLORS.navyLight}`,
                  borderRadius: '20px',
                  backdropFilter: 'blur(8px)',
                  transition: 'border-color 0.4s ease',
                }}
                className="step-card"
              >
                {/* Left: number + text */}
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div
                    style={{
                      fontFamily: FONTS.mono,
                      fontSize: '80px',
                      fontWeight: 500,
                      color: COLORS.accentCyan,
                      opacity: 0.15,
                      lineHeight: 1,
                      marginBottom: '-20px',
                      userSelect: 'none',
                    }}
                  >
                    {step.number}
                  </div>
                  <h3
                    style={{
                      fontFamily: FONTS.display,
                      fontSize: 'clamp(1.5rem, 2.5vw, 32px)',
                      fontWeight: 600,
                      color: COLORS.cloudWhite,
                      marginBottom: '16px',
                    }}
                  >
                    {step.title}
                  </h3>
                  <p
                    style={{
                      fontFamily: FONTS.body,
                      fontSize: '16px',
                      lineHeight: 1.7,
                      color: COLORS.cloudMuted,
                      maxWidth: '380px',
                    }}
                  >
                    {step.body}
                  </p>
                </div>

                {/* Right: illustration */}
                <div style={{ flexShrink: 0 }}>{step.icon}</div>
              </div>
            ))}
          </div>
        </div>
      </div>

      <style>{`
        @media (max-width: 768px) {
          .step-card {
            flex-direction: column !important;
            gap: 32px !important;
            padding: 40px 32px !important;
            width: 90vw !important;
          }
        }
      `}</style>
    </section>
  )
}
