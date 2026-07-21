import { COLORS } from '../../utils/constants'
import { lerp, mapRange, clamp } from '../../utils/lerp'

// ─── Cubic bezier utilities ─────────────────────────────────────────────────

function bPoint(
  t: number,
  x0: number, y0: number, x1: number, y1: number,
  x2: number, y2: number, x3: number, y3: number,
): [number, number] {
  const u = 1 - t
  return [
    u * u * u * x0 + 3 * u * u * t * x1 + 3 * u * t * t * x2 + t * t * t * x3,
    u * u * u * y0 + 3 * u * u * t * y1 + 3 * u * t * t * y2 + t * t * t * y3,
  ]
}

function bLen(
  x0: number, y0: number, x1: number, y1: number,
  x2: number, y2: number, x3: number, y3: number,
): number {
  let len = 0, px = x0, py = y0
  for (let i = 1; i <= 48; i++) {
    const [qx, qy] = bPoint(i / 48, x0, y0, x1, y1, x2, y2, x3, y3)
    len += Math.sqrt((qx - px) ** 2 + (qy - py) ** 2)
    px = qx; py = qy
  }
  return len
}

// ─── The journey path — ONE continuous curve, source (left) → hub (right) ────

const P = { x0: 175, y0: 258, x1: 370, y1: 95, x2: 640, y2: 110, x3: 812, y3: 296 }
const PATH_D = `M${P.x0},${P.y0} C${P.x1},${P.y1} ${P.x2},${P.y2} ${P.x3},${P.y3}`
const PATH_LEN = bLen(P.x0, P.y0, P.x1, P.y1, P.x2, P.y2, P.x3, P.y3)
const head = (t: number) => bPoint(clamp(t, 0, 1), P.x0, P.y0, P.x1, P.y1, P.x2, P.y2, P.x3, P.y3)

const HUB = { x: 820, y: 296 }

// How much of the path is drawn at a given scroll progress (staged by phase).
function journeyDraw(p: number): number {
  if (p < 0.10) return 0
  if (p < 0.30) return mapRange(p, 0.10, 0.30, 0, 0.30)   // Discover → 30%
  if (p < 0.55) return mapRange(p, 0.30, 0.55, 0.30, 0.60) // Classify → 60%
  if (p < 0.75) return mapRange(p, 0.55, 0.75, 0.60, 0.85) // Monitor → 85%
  if (p < 0.95) return mapRange(p, 0.75, 0.95, 0.85, 1.0)  // Secure → 100%
  return 1
}

// Classification route-markers (Phase 2).
const MARKERS = [
  { text: 'PII', frac: 0.40, color: COLORS.accentCyan, appear: 0.38, fade: 0.52 },
  { text: 'PHI', frac: 0.50, color: COLORS.accentPurple, appear: 0.46, fade: 0.60 },
  { text: 'Encrypted', frac: 0.58, color: COLORS.accentCyan, appear: 0.52, fade: 0.66 },
]

// ─── Isometric building ─────────────────────────────────────────────────────

function IsometricBuilding({
  x, y, width, height, depth, color1, color2,
}: {
  x: number; y: number; width: number; height: number; depth: number
  color1: string; color2: string
}) {
  const pts = {
    top:    [x,         y - height],
    right:  [x + width, y - height + depth],
    bottom: [x + width, y + depth],
    left:   [x,         y],
  }
  return (
    <g>
      <polygon
        points={`${pts.left[0]},${pts.left[1]} ${pts.bottom[0]},${pts.bottom[1]} ${pts.bottom[0]},${pts.bottom[1] - height} ${pts.left[0]},${pts.left[1] - height}`}
        fill={color1} stroke={COLORS.navyLight} strokeWidth="1"
      />
      <polygon
        points={`${pts.top[0]},${pts.top[1]} ${pts.right[0]},${pts.right[1] - height + depth} ${pts.right[0]},${pts.right[1] - height} ${pts.top[0]},${pts.top[1] - depth}`}
        fill={color2} stroke={COLORS.navyLight} strokeWidth="1"
      />
      <polygon
        points={`${pts.right[0]},${pts.right[1] - height} ${pts.right[0]},${pts.right[1]} ${pts.bottom[0]},${pts.bottom[1]} ${pts.bottom[0]},${pts.bottom[1] - height}`}
        fill={COLORS.navyLight} stroke={COLORS.navyLight} strokeWidth="1"
      />
    </g>
  )
}

// ─── Source cluster (left) — where data lives ───────────────────────────────

function SourceCluster({ progress }: { progress: number }) {
  // The origin pulses gently as the journey begins.
  const originT = clamp(mapRange(progress, 0.08, 0.24, 0, 1), 0, 1)
  const originGlow = Math.sin(progress * Math.PI * 6) * 0.5 + 0.5

  return (
    <g>
      {/* Server building */}
      <IsometricBuilding x={120} y={300} width={70} height={130} depth={22}
        color1={COLORS.navyMid} color2="#0E1B3A" />
      {[0, 1, 2, 3].map((i) => (
        <rect key={i} x={122} y={182 + i * 15} width={64} height={10}
          rx="1" fill="none" stroke={COLORS.navyLight} strokeWidth="0.8" />
      ))}

      {/* Cloud storage box */}
      <IsometricBuilding x={70} y={452} width={54} height={64} depth={16}
        color1={COLORS.navyMid} color2="#112040" />
      <rect x={72} y={386} width={50} height={9} rx="4"
        fill="none" stroke={COLORS.navyLight} strokeWidth="1" />

      {/* Database cylinders */}
      <g transform="translate(25, 65)">
        <ellipse cx={180} cy={430} rx={34} ry={12} fill={COLORS.navyMid} stroke={COLORS.navyLight} strokeWidth="1" />
        <rect x={146} y={410} width={68} height={20} fill={COLORS.navyMid} />
        <ellipse cx={180} cy={410} rx={34} ry={12} fill="#112040" stroke={COLORS.navyLight} strokeWidth="1" />
        <ellipse cx={180} cy={452} rx={34} ry={12} fill={COLORS.navyMid} stroke={COLORS.navyLight} strokeWidth="1" />
        <rect x={146} y={432} width={68} height={20} fill={COLORS.navyMid} />
        <ellipse cx={180} cy={432} rx={34} ry={12} fill="#112040" stroke={COLORS.navyLight} strokeWidth="1" />
      </g>

      {/* Endpoint terminal */}
      <g transform="translate(238, 250)">
        <rect x={0} y={0} width={44} height={30} rx={2} fill={COLORS.navyMid} stroke={COLORS.navyLight} strokeWidth="1" />
        <rect x={4} y={4} width={36} height={22} rx={1} fill="#0E1B3A" />
        <rect x={16} y={30} width={12} height={8} fill={COLORS.navyMid} />
        <rect x={8} y={38} width={28} height={3} rx={1} fill={COLORS.navyLight} />
      </g>

      {/* Origin emission glow at the path start */}
      <circle cx={P.x0} cy={P.y0} r={12 + originGlow * 6}
        fill={COLORS.accentCyan} opacity={originT * (0.10 + originGlow * 0.12)} filter="url(#dl-glow)" />
      <circle cx={P.x0} cy={P.y0} r={4}
        fill={COLORS.accentCyan} opacity={originT * 0.9} />
    </g>
  )
}

// ─── SENTRO hub (right) — the destination ───────────────────────────────────

function Hub({ progress }: { progress: number }) {
  const cx = HUB.x
  const cy = HUB.y
  const size = 62

  const climaxT = clamp(mapRange(progress, 0.75, 1.0, 0, 1), 0, 1)
  const ringT = clamp(mapRange(progress, 0.88, 1.0, 0, 1), 0, 1)
  const settle = clamp(mapRange(progress, 0.95, 1.0, 0, 1), 0, 1)
  const idleGlow = Math.sin(progress * Math.PI * 5) * 0.5 + 0.5

  const hexPts = Array.from({ length: 6 }, (_, i) => {
    const a = (i * 60 - 30) * (Math.PI / 180)
    return `${cx + size * Math.cos(a)},${cy + size * Math.sin(a)}`
  }).join(' ')

  // Expanding shock ring when the journey completes.
  const shockR = ringT * 560
  const shockOp = (1 - ringT) * 0.6

  const coreR = 20 + climaxT * 10 + idleGlow * 2
  const counterVal = Math.round(lerp(0, 10516, clamp(mapRange(progress, 0.85, 0.95, 0, 1), 0, 1)))
  const showCounter = progress > 0.80

  return (
    <g>
      {/* Expanding completion shock ring */}
      {shockOp > 0.01 && (
        <circle cx={cx} cy={cy} r={shockR}
          fill="none" stroke={COLORS.accentCyan}
          strokeWidth={Math.max(0.2, 2.4 * (1 - ringT))} opacity={shockOp} />
      )}

      {/* Ambient halo */}
      <circle cx={cx} cy={cy} r={92 + climaxT * 26}
        fill={COLORS.accentCyan} opacity={0.03 + climaxT * 0.06} filter="url(#dl-glow)" />

      {/* Shield ring */}
      <ellipse cx={cx} cy={cy - 6}
        rx={92 + climaxT * 14} ry={78 + climaxT * 10}
        fill="none" stroke={COLORS.accentCyan} strokeWidth="1"
        strokeDasharray="4 4"
        opacity={0.25 + climaxT * 0.45 + idleGlow * 0.05} />

      {/* Hex platform */}
      <polygon points={hexPts}
        fill={`${COLORS.accentCyan}14`}
        stroke={COLORS.accentCyan}
        strokeWidth={1.5 + climaxT * 1.6} filter="url(#dl-glow)" />

      {/* Glowing core */}
      <circle cx={cx} cy={cy} r={coreR}
        fill={COLORS.accentCyan} opacity={0.14 + climaxT * 0.22} filter="url(#dl-glow)" />
      <circle cx={cx} cy={cy} r={coreR * 0.5}
        fill="#eaffff" opacity={0.5 + climaxT * 0.4} />

      {/* Wordmark */}
      <text x={cx} y={cy + 44} textAnchor="middle"
        fontSize={11} fontFamily="'JetBrains Mono', monospace"
        fill={COLORS.accentCyan} letterSpacing="3" opacity={0.7 + climaxT * 0.3}>
        SENTRO
      </text>

      {/* Asset counter */}
      {showCounter && (
        <g opacity={clamp(mapRange(progress, 0.80, 0.87, 0, 1), 0, 1)}>
          <rect x={cx - 92} y={cy - 132} width={184} height={30} rx={4}
            fill={COLORS.navyMid} stroke={COLORS.accentCyan} strokeWidth="1" opacity={0.95} />
          <text x={cx} y={cy - 111} textAnchor="middle"
            fontSize="11" fontFamily="'JetBrains Mono', monospace" fill={COLORS.accentCyan}>
            {counterVal.toLocaleString()} assets secured
          </text>
        </g>
      )}

      {/* Steady arrival flash fades in as everything settles */}
      {settle > 0 && (
        <circle cx={cx} cy={cy} r={coreR + 6}
          fill="none" stroke="#eaffff" strokeWidth="1.5" opacity={settle * 0.5} />
      )}
    </g>
  )
}

// ─── Main ───────────────────────────────────────────────────────────────────

interface DataLandscapeProps { progress: number }

export default function DataLandscape({ progress }: DataLandscapeProps) {
  const drawP = journeyDraw(progress)
  const lineOffset = PATH_LEN * (1 - drawP)

  // Line brightens as it draws, then relaxes to a permanent low-opacity route.
  const lineOp = lerp(0.9, 0.42, clamp(mapRange(progress, 0.95, 1.0, 0, 1), 0, 1))

  // Leading comet head — visible while the path is still drawing.
  const [hx, hy] = head(drawP)
  const showHead = progress >= 0.10 && progress < 0.955
  const headPulse = Math.sin(progress * Math.PI * 8) * 0.5 + 0.5

  // Flowing data packets (Phase 3+), rushing into the hub at the very end.
  const showDots = progress >= 0.53
  const rush = clamp(mapRange(progress, 0.88, 1.0, 0, 1), 0, 1)
  const dotOp = clamp(mapRange(progress, 0.53, 0.58, 0, 0.9), 0, 0.9) * (1 - rush * 0.25)

  return (
    <svg
      viewBox="0 0 1000 600"
      preserveAspectRatio="xMidYMid slice"
      style={{ width: '100%', height: '100%', display: 'block' }}
      aria-hidden="true"
    >
      <defs>
        <pattern id="dl-grid" x="0" y="0" width="42" height="42" patternUnits="userSpaceOnUse">
          <path d="M 42 0 L 0 0 0 42" fill="none" stroke={COLORS.accentCyan} strokeWidth="0.5" opacity="0.07" />
        </pattern>
        <filter id="dl-glow" x="-80%" y="-80%" width="260%" height="260%">
          <feGaussianBlur stdDeviation="4" result="b" />
          <feMerge>
            <feMergeNode in="b" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
        <filter id="dl-glow-wide" x="-120%" y="-120%" width="340%" height="340%">
          <feGaussianBlur stdDeviation="7" result="b" />
          <feMerge>
            <feMergeNode in="b" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
      </defs>

      {/* Ground grid */}
      <rect width="1000" height="600" fill="url(#dl-grid)" />

      {/* Source cluster (left) */}
      <SourceCluster progress={progress} />

      {/* The journey path */}
      {drawP > 0 && (
        <path
          d={PATH_D}
          fill="none"
          stroke={COLORS.accentCyan}
          strokeWidth="2"
          strokeLinecap="round"
          strokeDasharray={PATH_LEN}
          strokeDashoffset={lineOffset}
          opacity={lineOp}
          filter="url(#dl-glow-wide)"
        />
      )}

      {/* Flowing data packets along the drawn portion */}
      {showDots && dotOp > 0.01 && [0, 1, 2, 3, 4].map((i) => {
        const phase = i / 5
        const t = (progress * 3 + phase) % 1
        let frac = t * drawP
        frac = lerp(frac, 1, rush)               // rush into hub at completion
        const [dx, dy] = head(frac)
        return (
          <circle key={`dot-${i}`} cx={dx} cy={dy} r={2.6}
            fill={COLORS.accentCyan} opacity={dotOp} filter="url(#dl-glow)" />
        )
      })}

      {/* Classification route-markers */}
      {MARKERS.map((m) => {
        if (drawP < m.frac) return null
        const op = clamp(
          Math.min(
            mapRange(progress, m.appear, m.appear + 0.04, 0, 1),
            mapRange(progress, m.fade - 0.04, m.fade, 1, 0),
          ), 0, 1,
        )
        if (op < 0.01) return null
        const [mx, my] = head(m.frac)
        const chipW = m.text.length * 6.2 + 12
        return (
          <g key={`mk-${m.text}`} opacity={op}>
            <line x1={mx} y1={my} x2={mx} y2={my - 16} stroke={m.color} strokeWidth="0.8" opacity="0.6" />
            <rect x={mx - chipW / 2} y={my - 32} width={chipW} height={15} rx={7.5}
              fill={COLORS.navyMid} stroke={m.color} strokeWidth="0.9" />
            <text x={mx} y={my - 21.5} textAnchor="middle"
              fontSize="7.5" fontFamily="'JetBrains Mono', monospace" fill={m.color}>
              {m.text}
            </text>
          </g>
        )
      })}

      {/* SENTRO hub (right) */}
      <Hub progress={progress} />

      {/* Leading comet head — drawn last so it sits above the path */}
      {showHead && (
        <g>
          <circle cx={hx} cy={hy} r={9 + headPulse * 3}
            fill={COLORS.accentCyan} opacity={0.35} filter="url(#dl-glow-wide)" />
          <circle cx={hx} cy={hy} r={3.4} fill="#eaffff" opacity="0.95" filter="url(#dl-glow)" />
        </g>
      )}
    </svg>
  )
}
