import { COLORS } from '../../utils/constants'

type DataObjectType = 'document' | 'lock' | 'database' | 'cloud' | 'chart' | 'warning'

interface DataObjectProps {
  type: DataObjectType
  x: number
  y: number
  progress: number
  label?: string
  glowColor?: string
  opacity?: number
}

function DocumentIcon({ color }: { color: string }) {
  return (
    <g>
      <rect x="-10" y="-12" width="20" height="24" rx="2" fill={`${color}20`} stroke={color} strokeWidth="1.5" />
      <line x1="-6" y1="-4" x2="6" y2="-4" stroke={color} strokeWidth="1.2" strokeLinecap="round" />
      <line x1="-6" y1="0" x2="6" y2="0" stroke={color} strokeWidth="1.2" strokeLinecap="round" />
      <line x1="-6" y1="4" x2="2" y2="4" stroke={color} strokeWidth="1.2" strokeLinecap="round" />
    </g>
  )
}

function LockIcon({ color }: { color: string }) {
  return (
    <g>
      <rect x="-9" y="-2" width="18" height="14" rx="2" fill={`${color}20`} stroke={color} strokeWidth="1.5" />
      <path d="M-5 -2 v-4 a5 5 0 0 1 10 0 v4" fill="none" stroke={color} strokeWidth="1.5" />
      <circle cx="0" cy="6" r="2" fill={color} />
    </g>
  )
}

function DatabaseIcon({ color }: { color: string }) {
  return (
    <g>
      <ellipse cx="0" cy="-8" rx="10" ry="4" fill={`${color}20`} stroke={color} strokeWidth="1.5" />
      <path d="M-10 -8 v16" stroke={color} strokeWidth="1.5" />
      <path d="M10 -8 v16" stroke={color} strokeWidth="1.5" />
      <ellipse cx="0" cy="8" rx="10" ry="4" fill={`${color}20`} stroke={color} strokeWidth="1.5" />
      <ellipse cx="0" cy="0" rx="10" ry="4" fill="none" stroke={color} strokeWidth="1" strokeDasharray="2 2" />
    </g>
  )
}

function CloudIcon({ color }: { color: string }) {
  return (
    <g>
      <path
        d="M-12 4 C-12 -2 -8 -6 -3 -6 C-1 -10 4 -12 8 -8 C12 -8 14 -4 12 0 C14 0 14 6 10 6 L-10 6 C-14 6 -14 0 -12 4Z"
        fill={`${color}20`}
        stroke={color}
        strokeWidth="1.5"
      />
    </g>
  )
}

function ChartIcon({ color }: { color: string }) {
  return (
    <g>
      <line x1="-10" y1="8" x2="10" y2="8" stroke={color} strokeWidth="1.5" />
      <rect x="-8" y="-2" width="4" height="10" rx="1" fill={`${color}40`} stroke={color} strokeWidth="1" />
      <rect x="-2" y="-8" width="4" height="16" rx="1" fill={`${color}40`} stroke={color} strokeWidth="1" />
      <rect x="4" y="0" width="4" height="8" rx="1" fill={`${color}40`} stroke={color} strokeWidth="1" />
    </g>
  )
}

function WarningIcon({ color }: { color: string }) {
  return (
    <g>
      <path
        d="M0 -12 L11 8 L-11 8 Z"
        fill={`${color}25`}
        stroke={color}
        strokeWidth="1.5"
        strokeLinejoin="round"
      />
      <line x1="0" y1="-4" x2="0" y2="2" stroke={color} strokeWidth="1.8" strokeLinecap="round" />
      <circle cx="0" cy="5" r="1.2" fill={color} />
    </g>
  )
}

const ICON_MAP: Record<DataObjectType, React.ComponentType<{ color: string }>> = {
  document: DocumentIcon,
  lock: LockIcon,
  database: DatabaseIcon,
  cloud: CloudIcon,
  chart: ChartIcon,
  warning: WarningIcon,
}

export default function DataObject({
  type,
  x,
  y,
  progress,
  label,
  glowColor,
  opacity = 1,
}: DataObjectProps) {
  const color = type === 'warning'
    ? '#F59E0B'
    : (glowColor ?? COLORS.accentCyan)
  const IconComponent = ICON_MAP[type]
  const filterId = `glow-${type}-${Math.round(x)}-${Math.round(y)}`

  return (
    <g transform={`translate(${x}, ${y})`} opacity={opacity} style={{ willChange: 'transform' }}>
      <defs>
        <filter id={filterId} x="-50%" y="-50%" width="200%" height="200%">
          <feGaussianBlur stdDeviation={progress > 0.2 ? 3 : 1} result="blur" />
          <feComposite in="SourceGraphic" in2="blur" operator="over" />
        </filter>
      </defs>

      <g filter={`url(#${filterId})`} transform="scale(1)">
        <IconComponent color={color} />
      </g>

      {/* Glow halo at higher progress */}
      {progress > 0.2 && (
        <circle
          r="18"
          fill="none"
          stroke={color}
          strokeWidth="1"
          opacity={Math.min(1, (progress - 0.2) * 2) * 0.3}
        />
      )}

      {/* Classification label */}
      {label && progress > 0.2 && progress < 0.8 && (
        <g transform="translate(16, -12)">
          <rect
            x="0"
            y="-8"
            width={label.length * 6.5}
            height="14"
            rx="3"
            fill={COLORS.navyMid}
            stroke={color}
            strokeWidth="0.8"
            opacity={Math.min(1, (progress - 0.2) * 5)}
          />
          <text
            x={label.length * 3.25}
            y="1"
            textAnchor="middle"
            fontSize="7"
            fill={color}
            fontFamily="'JetBrains Mono', monospace"
            opacity={Math.min(1, (progress - 0.2) * 5)}
          >
            {label}
          </text>
        </g>
      )}
    </g>
  )
}
