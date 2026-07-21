import { COLORS, FONTS } from '../../utils/constants'

interface ProgressIndicatorProps {
  progress: number
  phases: string[]
}

export default function ProgressIndicator({ progress, phases }: ProgressIndicatorProps) {
  const count = phases.length
  const activeIndex = Math.min(count - 1, Math.floor(progress * count))
  const lineHeight = progress * 100

  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        gap: 0,
        position: 'relative',
        padding: '8px 0',
      }}
      role="progressbar"
      aria-valuenow={Math.round(progress * 100)}
      aria-valuemin={0}
      aria-valuemax={100}
      aria-label={`Section progress: ${phases[activeIndex]}`}
    >
      {phases.map((phase, i) => {
        const isActive = i === activeIndex
        const isPast = i < activeIndex

        return (
          <div
            key={phase}
            style={{
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
            }}
          >
            {/* Dot */}
            <div
              style={{
                width: isActive ? '10px' : '7px',
                height: isActive ? '10px' : '7px',
                borderRadius: '50%',
                background: isActive || isPast ? COLORS.accentCyan : COLORS.navyMid,
                border: `1.5px solid ${isActive ? COLORS.accentCyan : isPast ? COLORS.accentCyan : COLORS.cloudMuted}`,
                boxShadow: isActive
                  ? `0 0 8px ${COLORS.accentCyan}, 0 0 16px rgba(0,229,255,0.3)`
                  : 'none',
                transform: `scale(${isActive ? 1.3 : 1})`,
                transition: 'all 0.3s ease',
                zIndex: 2,
                position: 'relative',
              }}
            />

            {/* Connecting line (below dot, except last) */}
            {i < count - 1 && (
              <div
                style={{
                  width: '1.5px',
                  height: '48px',
                  background: COLORS.navyLight,
                  position: 'relative',
                  overflow: 'hidden',
                }}
              >
                <div
                  style={{
                    position: 'absolute',
                    top: 0,
                    left: 0,
                    right: 0,
                    background: COLORS.accentCyan,
                    height: `${lineHeight}%`,
                    transition: 'height 0.1s ease',
                  }}
                />
              </div>
            )}
          </div>
        )
      })}

      {/* Phase labels */}
      <div
        style={{
          position: 'absolute',
          left: '20px',
          top: 0,
          display: 'flex',
          flexDirection: 'column',
          gap: '40px',
        }}
      >
        {phases.map((phase, i) => (
          <span
            key={phase}
            style={{
              fontFamily: FONTS.mono,
              fontSize: '10px',
              letterSpacing: '0.1em',
              textTransform: 'uppercase',
              color: i === activeIndex ? COLORS.accentCyan : COLORS.cloudMuted,
              opacity: i === activeIndex ? 1 : 0.5,
              transition: 'all 0.3s ease',
              whiteSpace: 'nowrap',
              marginTop: i === 0 ? '-3px' : 0,
            }}
          >
            {phase}
          </span>
        ))}
      </div>
    </div>
  )
}
