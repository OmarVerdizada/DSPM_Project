import { COLORS, FONTS } from '../../utils/constants'

interface StepMeta {
  number: string
  label:  string
  badge:  string
  color:  string
}

const STEPS: StepMeta[] = [
  { number: '01', label: 'Discover', badge: 'SCAN',     color: COLORS.accentCyan },
  { number: '02', label: 'Classify', badge: 'ML',       color: COLORS.accentPurple },
  { number: '03', label: 'Monitor',  badge: 'REALTIME', color: '#F59E0B' },
  { number: '04', label: 'Secure',   badge: 'PROTECT',  color: '#10B981' },
]

interface Props {
  activeStep:   number   // 0–3
  stepProgress: number   // 0–1 within the active step
}

export default function StepperPanel({ activeStep, stepProgress }: Props) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', position: 'relative' }}>
      {/* Vertical connector line */}
      <div aria-hidden="true" style={{
        position: 'absolute',
        left: '18px',
        top: '28px',
        bottom: '28px',
        width: '1px',
        background: `linear-gradient(to bottom,
          ${COLORS.accentCyan}30,
          ${COLORS.accentPurple}30,
          #F59E0B30,
          #10B98130)`,
      }} />

      {STEPS.map((step, i) => {
        const isActive = i === activeStep
        const isDone   = i < activeStep
        const c = step.color

        return (
          <div key={step.number} style={{
            display: 'flex',
            alignItems: 'flex-start',
            gap: '18px',
            padding: '14px 0',
            position: 'relative',
          }}>
            {/* Circle */}
            <div style={{
              width: '36px', height: '36px', borderRadius: '50%', flexShrink: 0,
              border: `1.5px solid ${isActive || isDone ? c : COLORS.navyLight}`,
              background: isActive ? `${c}18` : 'transparent',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              transition: 'all 0.4s ease',
              boxShadow: isActive ? `0 0 14px ${c}50` : 'none',
              zIndex: 1,
            }}>
              {isDone ? (
                <svg width="13" height="13" viewBox="0 0 13 13" fill="none">
                  <path d="M2.5 6.5l2.5 2.5 5-5"
                    stroke={c} strokeWidth="1.8"
                    strokeLinecap="round" strokeLinejoin="round" />
                </svg>
              ) : (
                <span style={{
                  fontFamily: FONTS.mono, fontSize: '10px', fontWeight: 600,
                  color: isActive ? c : COLORS.cloudMuted,
                  transition: 'color 0.4s ease',
                }}>{step.number}</span>
              )}
            </div>

            {/* Label + badge */}
            <div style={{ paddingTop: '5px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '9px', marginBottom: '5px' }}>
                <span style={{
                  fontFamily: FONTS.display, fontSize: '14px',
                  fontWeight: isActive ? 600 : 400,
                  color: COLORS.cloudWhite,
                  opacity: isActive ? 1 : isDone ? 0.55 : 0.3,
                  transition: 'all 0.4s ease',
                }}>{step.label}</span>

                <span style={{
                  fontFamily: FONTS.mono, fontSize: '9px', letterSpacing: '0.1em',
                  color: isActive ? c : COLORS.cloudMuted,
                  background: isActive ? `${c}15` : 'transparent',
                  border: `1px solid ${isActive ? c : COLORS.navyLight}`,
                  borderRadius: '100px', padding: '2px 7px',
                  opacity: isActive ? 1 : 0.3,
                  transition: 'all 0.4s ease',
                }}>{step.badge}</span>
              </div>

              {isActive && (
                <div style={{
                  width: '72px', height: '2px',
                  background: `${c}25`, borderRadius: '2px', overflow: 'hidden',
                }}>
                  <div style={{
                    height: '100%',
                    width: `${stepProgress * 100}%`,
                    background: c, borderRadius: '2px',
                    transition: 'width 0.05s linear',
                  }} />
                </div>
              )}
            </div>
          </div>
        )
      })}
    </div>
  )
}
