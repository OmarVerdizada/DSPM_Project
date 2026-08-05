import { useId } from 'react'

interface SentroLogoProps {
  size?: number
  className?: string
  glowBlur?: number
  lightColor?: string
  withGlow?: boolean
  /** 'light' darkens the three inner blades so they stay visible on light backgrounds. */
  variant?: 'dark' | 'light'
}

// The official SENTRO mark (from "SENTRO Mark.html"): a blue-gradient ring,
// three rotor blades, and a gradient core with a specular highlight.
export default function SentroLogo({
  size = 64,
  className = '',
  glowBlur = 1.6,
  lightColor = '#eaf3ff',
  withGlow = true,
  variant = 'dark',
}: SentroLogoProps) {
  const uid = useId().replace(/:/g, '')
  const BLADE = 'M58 16 A36 36 0 0 1 85 60 A30 30 0 0 0 58 23 Z'
  const onLight = variant === 'light'

  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 100 100"
      xmlns="http://www.w3.org/2000/svg"
      className={className}
      style={withGlow ? { filter: `drop-shadow(0 0 12px rgba(74,124,255,${onLight ? 0.22 : 0.45}))` } : undefined}
      aria-label="SENTRO logo"
    >
      <defs>
        <linearGradient id={`mblue-${uid}`} x1="0" y1="0" x2="1" y2="1">
          <stop offset="0%" stopColor="#bcd4ff" />
          <stop offset="42%" stopColor="#5b8cff" />
          <stop offset="78%" stopColor="#2f5ad6" />
          <stop offset="100%" stopColor="#1d3a96" />
        </linearGradient>
        <linearGradient id={`blade-${uid}`} x1="0" y1="0" x2="1" y2="1">
          {onLight ? (
            <>
              {/* Deep indigo blades so the mark stays legible on light backgrounds */}
              <stop offset="0%" stopColor="#2D4CC8" />
              <stop offset="55%" stopColor="#2440A6" />
              <stop offset="100%" stopColor="#1E3A8A" />
            </>
          ) : (
            <>
              <stop offset="0%" stopColor={lightColor} />
              <stop offset="100%" stopColor="#9fc2ff" />
            </>
          )}
        </linearGradient>
        <filter id={`glow-${uid}`} x="-70%" y="-70%" width="240%" height="240%">
          <feGaussianBlur stdDeviation={glowBlur} result="b" />
          <feMerge>
            <feMergeNode in="b" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
      </defs>

      {/* Outer ring — dark track with a gradient stroke on top */}
      <circle cx="50" cy="50" r="45" fill="none" stroke="#1a2c5a" strokeWidth="6" />
      <circle cx="50" cy="50" r="45" fill="none" stroke={`url(#mblue-${uid})`} strokeWidth="3" />

      {/* Three rotor blades */}
      <g fill={`url(#blade-${uid})`} filter={`url(#glow-${uid})`}>
        <path className="sentro-logo-arc" d={BLADE} />
        <path className="sentro-logo-arc" d={BLADE} transform="rotate(120 50 50)" />
        <path className="sentro-logo-arc" d={BLADE} transform="rotate(240 50 50)" />
      </g>

      {/* Core with specular highlight */}
      <circle cx="50" cy="50" r="10" fill={`url(#mblue-${uid})`} />
      <circle cx="47" cy="47" r="3" fill="#e7f0ff" />
    </svg>
  )
}
