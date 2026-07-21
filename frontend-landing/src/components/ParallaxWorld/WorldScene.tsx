import { memo } from 'react'
import { COLORS } from '../../utils/constants'

// ─── Isometric projection (cabinet-style) ──────────────────────────────────
const CX = 700, CY = 340, TW = 32, TH = 16, ZS = 36

function proj(x: number, y: number, z: number) {
  return { x: CX + (x - y) * TW, y: CY + (x + y) * TH - z * ZS }
}

function ptStr(pts: { x: number; y: number }[]): string {
  return pts.map(p => `${p.x.toFixed(1)},${p.y.toFixed(1)}`).join(' ')
}

function isoBox(gx: number, gy: number, w: number, d: number, h: number) {
  const A  = proj(gx,   gy,   h), B  = proj(gx+w, gy,   h)
  const C  = proj(gx+w, gy+d, h), D  = proj(gx,   gy+d, h)
  const A0 = proj(gx,   gy,   0), B0 = proj(gx+w, gy,   0)
  const C0 = proj(gx+w, gy+d, 0)
  return {
    top:   ptStr([A, B, C, D]),
    front: ptStr([A, B, B0, A0]),
    right: ptStr([B, C, C0, B0]),
  }
}

// ─── Building primitive ────────────────────────────────────────────────────
function IsoBuilding({ gx, gy, w, d, h, top, front, side, opacity = 1 }: {
  gx: number; gy: number; w: number; d: number; h: number
  top: string; front: string; side: string; opacity?: number
}) {
  const f = isoBox(gx, gy, w, d, h)
  return (
    <g opacity={opacity}>
      <polygon points={f.right} fill={side}  />
      <polygon points={f.front} fill={front} />
      <polygon points={f.top}   fill={top}   />
    </g>
  )
}

// Ground tile
function IsoTile({ gx, gy, color }: { gx: number; gy: number; color: string }) {
  const { top } = isoBox(gx, gy, 1, 1, 0)
  return <polygon points={top} fill={color} stroke="#070B1A" strokeWidth="0.4" />
}

// ─── Pre-computed hub centre ───────────────────────────────────────────────
const HUB = proj(4.5, 4.5, 1.5)

// ─── Static world — memoised so it never re-renders on scroll ─────────────
const StaticWorld = memo(function StaticWorld() {
  return (
    <g>
      {/* Ground grid 10×10 */}
      {Array.from({ length: 10 }, (_, row) =>
        Array.from({ length: 10 }, (_, col) => (
          <IsoTile key={`${row}-${col}`} gx={col} gy={row}
            color={(row + col) % 2 === 0 ? '#080D20' : '#0A1028'} />
        ))
      )}

      {/* ── Cloud storage cluster — upper-left ── */}
      <IsoBuilding gx={0}   gy={0}   w={2.4} d={2}   h={2}
        top="#101830" front="#0C1228" side="#0E1530" />
      <IsoBuilding gx={0.3} gy={0.3} w={1.8} d={1.4} h={3.8}
        top="#141E40" front="#101838" side="#12183C" />
      {/* Antenna */}
      <IsoBuilding gx={0.9} gy={0.9} w={0.25} d={0.25} h={5.4}
        top={`${COLORS.accentCyan}90`} front={`${COLORS.accentCyan}45`} side={`${COLORS.accentCyan}60`} />

      {/* ── Server rack cluster — upper-right ── */}
      <IsoBuilding gx={7}   gy={0}   w={2.2} d={2.4} h={2.5}
        top="#101830" front="#0C1228" side="#0E1530" />
      <IsoBuilding gx={7.2} gy={0.2} w={1.8} d={2}   h={4.5}
        top="#161E48" front="#121840" side="#141A42" />
      <IsoBuilding gx={7.7} gy={0.9} w={0.3} d={0.3} h={6}
        top={`${COLORS.accentBlue}90`} front={`${COLORS.accentBlue}45`} side={`${COLORS.accentBlue}60`} />

      {/* ── API tower — left ── */}
      <IsoBuilding gx={0}   gy={6.5} w={2}   d={2}   h={3}
        top="#101830" front="#0C1228" side="#0E1530" />
      <IsoBuilding gx={0.3} gy={6.8} w={1.4} d={1.4} h={5.5}
        top="#181E50" front="#141A45" side="#161C48" />
      <IsoBuilding gx={0.8} gy={7.3} w={0.25} d={0.25} h={7.5}
        top={`${COLORS.accentPurple}90`} front={`${COLORS.accentPurple}45`} side={`${COLORS.accentPurple}60`} />

      {/* ── Database cluster — right ── */}
      <IsoBuilding gx={7.5} gy={6.5} w={2}   d={2}   h={1.8}
        top="#101830" front="#0C1228" side="#0E1530" />
      <IsoBuilding gx={7.5} gy={6.5} w={2}   d={2}   h={3.2}
        top="#161E48" front="#121840" side="#141A42" />
      <IsoBuilding gx={7.5} gy={6.5} w={2}   d={2}   h={4.4}
        top="#1C2458" front="#18204E" side="#1A2252" />

      {/* ── Small data nodes ── */}
      <IsoBuilding gx={3}   gy={1}   w={1}   d={0.8} h={1.2}
        top="#121A3A" front="#0E1630" side="#101838" />
      <IsoBuilding gx={6.5} gy={2}   w={0.8} d={1}   h={1.8}
        top="#121A3A" front="#0E1630" side="#101838" />
      <IsoBuilding gx={1.5} gy={4.5} w={0.7} d={0.7} h={1}
        top="#121A3A" front="#0E1630" side="#101838" />
      <IsoBuilding gx={8}   gy={4.5} w={0.7} d={0.7} h={1.4}
        top="#121A3A" front="#0E1630" side="#101838" />
      <IsoBuilding gx={3.5} gy={8}   w={1}   d={0.8} h={1}
        top="#121A3A" front="#0E1630" side="#101838" />
      <IsoBuilding gx={6}   gy={8.5} w={0.8} d={0.8} h={1.2}
        top="#121A3A" front="#0E1630" side="#101838" />

      {/* ── Central hub platform ── */}
      <IsoBuilding gx={3.5} gy={3.5} w={2.2} d={2.2} h={0.4}
        top="#1C2458" front="#161E4E" side="#181E50" />
      <IsoBuilding gx={3.8} gy={3.8} w={1.6} d={1.6} h={0.9}
        top="#202C62" front="#1A245A" side="#1C2860" />
      {/* Hub core */}
      <IsoBuilding gx={4.2} gy={4.2} w={0.8} d={0.8} h={1.5}
        top={`${COLORS.accentCyan}DD`} front={`${COLORS.accentCyan}70`} side={`${COLORS.accentCyan}90`} />
    </g>
  )
})

// ─── Step 0 — Discover ─────────────────────────────────────────────────────
function DiscoverAnimation({ progress }: { progress: number }) {
  // Beam sweeps across the grid footprint ~x 370→1000 in SVG space
  const beamX = 370 + progress * 680

  const cloudTop  = proj(1.2,  1.2, 5.4)
  const serverTop = proj(8,    1,   6)
  const apiTop    = proj(1,    7.5, 7.5)
  const dbTop     = proj(8.5,  7.5, 4.4)

  const sources = [cloudTop, serverTop, apiTop, dbTop]
  const thresholds = [0.2, 0.45, 0.65, 0.80]

  return (
    <g>
      {/* Scan beam */}
      <rect x={beamX - 30} y={0} width={60} height={800} fill={COLORS.accentCyan} opacity="0.025" />
      <rect x={beamX - 10} y={0} width={20} height={800} fill={COLORS.accentCyan} opacity="0.05" />
      <line x1={beamX} y1={0} x2={beamX} y2={800}
        stroke={COLORS.accentCyan} strokeWidth="1.5" opacity="0.65" />

      {/* Node lights appear as beam passes */}
      {sources.map((pt, i) => {
        const lit = progress > thresholds[i]
        const op = lit ? Math.min(1, (progress - thresholds[i]) / 0.15) : 0
        return (
          <g key={i} opacity={op}>
            <circle cx={pt.x} cy={pt.y} r={10} fill="none"
              stroke={COLORS.accentCyan} strokeWidth="1.2" opacity="0.7" />
            <circle cx={pt.x} cy={pt.y} r={3.5} fill={COLORS.accentCyan} opacity="0.9" />
            {/* Pulse ring */}
            <circle cx={pt.x} cy={pt.y} r={10 + progress * 20}
              fill="none" stroke={COLORS.accentCyan} strokeWidth="0.8"
              opacity={0.25 * (1 - (progress - thresholds[i]))} />
          </g>
        )
      })}

      {/* Floating data particles */}
      {Array.from({ length: 6 }, (_, i) => {
        const baseX = 420 + i * 90
        const baseY = 560 - progress * 160 - i * 18
        return (
          <circle key={i} cx={baseX} cy={baseY} r={1.8}
            fill={COLORS.accentCyan}
            opacity={Math.max(0, 0.5 - i * 0.05) * Math.min(1, progress * 4)} />
        )
      })}
    </g>
  )
}

// Flow line from source to hub drawn by pathLength="1" trick
function FlowLine({ from, color, progress, label }: {
  from: { x: number; y: number }
  color: string
  progress: number
  label?: string
}) {
  if (progress <= 0) return null
  const p = Math.min(1, progress)
  const cpX = (from.x + HUB.x) / 2
  const cpY = Math.min(from.y, HUB.y) - 60
  const d = `M ${from.x.toFixed(1)} ${from.y.toFixed(1)} Q ${cpX.toFixed(1)} ${cpY.toFixed(1)} ${HUB.x.toFixed(1)} ${HUB.y.toFixed(1)}`

  // Dot travels along a rough linear interpolation of the bezier
  const t = p
  const dotX = (1-t)*(1-t)*from.x + 2*(1-t)*t*cpX + t*t*HUB.x
  const dotY = (1-t)*(1-t)*from.y + 2*(1-t)*t*cpY + t*t*HUB.y

  return (
    <g>
      <path d={d} fill="none" stroke={color} strokeWidth="1.4"
        strokeLinecap="round" pathLength="1"
        strokeDasharray="1" strokeDashoffset={`${1 - p}`}
        opacity="0.75" />
      {p > 0 && p < 0.98 && (
        <circle cx={dotX} cy={dotY} r={3} fill={color} opacity="0.9" />
      )}
      {label && p > 0.08 && (
        <text x={from.x + 10} y={from.y - 6}
          fontFamily="'JetBrains Mono', monospace" fontSize="9" fill={color}
          opacity={Math.min(1, p * 5)}>{label}</text>
      )}
    </g>
  )
}

// ─── Step 1 — Classify ─────────────────────────────────────────────────────
function ClassifyAnimation({ progress }: { progress: number }) {
  const cloudTop  = proj(1.2, 1.2, 5.4)
  const serverTop = proj(8,   1,   6)
  const apiTop    = proj(1,   7.5, 7.5)
  const dbTop     = proj(8.5, 7.5, 4.4)

  const lines = [
    { from: cloudTop,  color: COLORS.accentCyan,   progress: Math.min(1, progress / 0.6),        label: 'PII' },
    { from: serverTop, color: COLORS.accentPurple, progress: Math.min(1, Math.max(0, (progress - 0.15) / 0.6)), label: 'PHI' },
    { from: apiTop,    color: '#F59E0B',            progress: Math.min(1, Math.max(0, (progress - 0.30) / 0.6)), label: 'API-KEY' },
    { from: dbTop,     color: '#10B981',            progress: Math.min(1, Math.max(0, (progress - 0.45) / 0.6)), label: 'PCI' },
  ]

  return (
    <g>
      {/* Keep node lights visible from Discover */}
      {[cloudTop, serverTop, apiTop, dbTop].map((pt, i) => (
        <g key={i} opacity="0.5">
          <circle cx={pt.x} cy={pt.y} r={6} fill={COLORS.accentCyan} opacity="0.7" />
        </g>
      ))}

      {lines.map((l, i) => (
        <FlowLine key={i} from={l.from} color={l.color} progress={l.progress} label={l.label} />
      ))}

      {/* Hub glow growing */}
      <circle cx={HUB.x} cy={HUB.y} r={16 + progress * 24}
        fill="none" stroke={COLORS.accentCyan} strokeWidth="1"
        opacity={0.12 + progress * 0.2} />
    </g>
  )
}

// ─── Step 2 — Monitor ──────────────────────────────────────────────────────
function MonitorAnimation({ progress }: { progress: number }) {
  const cloudTop = proj(1.2, 1.2, 5.4)
  const dbTop    = proj(8.5, 7.5, 4.4)

  const alertFlash = Math.abs(Math.sin(progress * 14))

  return (
    <g>
      {/* Radar rings */}
      {[0, 0.33, 0.66].map((offset, i) => {
        const p = ((progress * 1.2 + offset) % 1)
        return (
          <ellipse key={i} cx={HUB.x} cy={HUB.y}
            rx={16 + p * 200} ry={(16 + p * 200) * 0.35}
            fill="none" stroke={COLORS.accentCyan} strokeWidth="1.2"
            opacity={0.55 * (1 - p)} />
        )
      })}

      {/* Alert on cloud node */}
      {progress > 0.2 && (
        <g opacity={Math.min(1, (progress - 0.2) * 5)}>
          <circle cx={cloudTop.x} cy={cloudTop.y} r={6}
            fill="#F59E0B" opacity={0.7 + alertFlash * 0.3} />
          <text x={cloudTop.x + 10} y={cloudTop.y + 4}
            fontFamily="'JetBrains Mono', monospace" fontSize="9" fill="#F59E0B"
            opacity="0.9">ANOMALY</text>
        </g>
      )}

      {/* Alert on db node */}
      {progress > 0.5 && (
        <g opacity={Math.min(1, (progress - 0.5) * 5)}>
          <circle cx={dbTop.x} cy={dbTop.y} r={6}
            fill={COLORS.alertRed ?? '#EF4444'} opacity={0.7 + alertFlash * 0.3} />
          <text x={dbTop.x - 44} y={dbTop.y + 4}
            fontFamily="'JetBrains Mono', monospace" fontSize="9" fill="#EF4444"
            opacity="0.9">HIGH RISK</text>
        </g>
      )}

      {/* Dot field */}
      {Array.from({ length: 5 }, (_, row) =>
        Array.from({ length: 8 }, (_, col) => {
          const dx = (HUB.x - 200) + col * 56
          const dy = (HUB.y - 90)  + row * 46
          const dist = Math.hypot(dx - HUB.x, dy - HUB.y)
          return (
            <circle key={`${row}-${col}`} cx={dx} cy={dy} r={1.4}
              fill={COLORS.accentCyan}
              opacity={(0.05 + 0.1 * Math.sin(progress * 7 + dist * 0.025))
                * Math.min(1, progress * 4)} />
          )
        })
      )}
    </g>
  )
}

// ─── Step 3 — Secure ───────────────────────────────────────────────────────
function SecureAnimation({ progress }: { progress: number }) {
  const count = Math.round(Math.min(1, progress * 1.4) * 12847)
  const domeP = Math.min(1, progress * 1.8)
  const domeR = domeP * 170

  const sources = [
    proj(1.2, 1.2, 3),
    proj(8,   1,   4),
    proj(1,   7.5, 5),
    proj(8.5, 7.5, 2.5),
  ]

  return (
    <g>
      {/* Convergence lines collapse to hub */}
      {sources.map((src, i) => {
        const t = Math.min(1, progress * 1.6)
        const ex = src.x + (HUB.x - src.x) * t
        const ey = src.y + (HUB.y - src.y) * t
        return (
          <line key={i} x1={src.x} y1={src.y} x2={ex} y2={ey}
            stroke={COLORS.accentCyan} strokeWidth="1"
            opacity={0.4 * (1 - t)} />
        )
      })}

      {/* Shield dome ellipses */}
      <ellipse cx={HUB.x} cy={HUB.y} rx={domeR} ry={domeR * 0.38}
        fill="none" stroke="#10B981" strokeWidth="1.5"
        opacity={domeP * 0.6} />
      <ellipse cx={HUB.x} cy={HUB.y} rx={domeR * 0.78} ry={domeR * 0.3}
        fill="none" stroke="#10B981" strokeWidth="0.8"
        opacity={domeP * 0.3} />
      <ellipse cx={HUB.x} cy={HUB.y} rx={domeR} ry={domeR * 0.38}
        fill="#10B981" opacity={domeP * 0.04} />

      {/* Hub pulse */}
      <circle cx={HUB.x} cy={HUB.y} r={10 + progress * 18}
        fill="#10B981" opacity={0.08 + progress * 0.12} />
      <circle cx={HUB.x} cy={HUB.y} r={7}
        fill="#10B981" opacity={0.55 * progress} />

      {/* Check mark on hub */}
      {progress > 0.4 && (
        <g opacity={Math.min(1, (progress - 0.4) * 4)}>
          <path d={`M ${HUB.x - 5} ${HUB.y} l 3 3 6 -6`}
            stroke="#10B981" strokeWidth="1.8"
            strokeLinecap="round" strokeLinejoin="round" fill="none" />
        </g>
      )}

      {/* Asset counter */}
      {progress > 0.25 && (
        <text x={HUB.x} y={HUB.y - domeR - 18}
          fontFamily="'JetBrains Mono', monospace" fontSize="13" fontWeight="700"
          fill="#10B981" textAnchor="middle"
          opacity={Math.min(1, (progress - 0.25) * 4)}>
          {count.toLocaleString()} assets secured
        </text>
      )}
    </g>
  )
}

// ─── Main component ────────────────────────────────────────────────────────
interface Props {
  activeStep:   number
  stepProgress: number
  rawProgress:  number
}

export default function WorldScene({ activeStep, stepProgress }: Props) {
  return (
    <div style={{ position: 'absolute', inset: 0 }}>
      <svg
        viewBox="0 0 1400 800"
        preserveAspectRatio="xMidYMid slice"
        style={{ width: '100%', height: '100%' }}
        aria-hidden="true"
      >
        <defs>
          <radialGradient id="pw-hub-glow" cx="50%" cy="60%" r="35%">
            <stop offset="0%"   stopColor={COLORS.accentCyan} stopOpacity="0.05" />
            <stop offset="100%" stopColor={COLORS.navyDeep}   stopOpacity="0"    />
          </radialGradient>
        </defs>

        {/* Sky / bg */}
        <rect width="1400" height="800" fill={COLORS.navyDeep} />
        <rect width="1400" height="800" fill="url(#pw-hub-glow)" />

        {/* Static geometry */}
        <StaticWorld />

        {/* Persistent hub indicator */}
        <circle cx={HUB.x} cy={HUB.y} r={4.5} fill={COLORS.accentCyan} opacity="0.9" />
        <circle cx={HUB.x} cy={HUB.y} r={11}  fill="none"
          stroke={COLORS.accentCyan} strokeWidth="1" opacity="0.35" />

        {/* Step animations */}
        {activeStep === 0 && <DiscoverAnimation  progress={stepProgress} />}
        {activeStep === 1 && <ClassifyAnimation  progress={stepProgress} />}
        {activeStep === 2 && <MonitorAnimation   progress={stepProgress} />}
        {activeStep === 3 && <SecureAnimation    progress={stepProgress} />}
      </svg>

      {/* Depth vignette */}
      <div aria-hidden="true" style={{
        position: 'absolute', inset: 0, pointerEvents: 'none',
        background: `radial-gradient(ellipse 80% 70% at 50% 55%,
          transparent 25%, ${COLORS.navyDeep}BB 100%)`,
      }} />
    </div>
  )
}
