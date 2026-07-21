import { useRef, useMemo, Suspense } from 'react'
import { Canvas, useFrame, useThree } from '@react-three/fiber'
import { Edges, Line, Html } from '@react-three/drei'
import { EffectComposer, Bloom } from '@react-three/postprocessing'
import * as THREE from 'three'
import { lerp, clamp, mapRange } from '../../utils/lerp'
import { FONTS } from '../../utils/constants'

const CYAN = '#00E5FF'
const TEAL = '#2FF5E0'
const NAVY_BODY = '#141a3d'

// ─── Scroll phase helpers ─────────────────────────────────────────────────────
// Phase 1 (0.10–0.30) endpoints power on + lines draw, staggered.
// Phase 2 (0.30–0.55) packets start, labels appear, dashboards fade in + draw.
// Phase 3 (0.55–0.75) continuous flow, live charts, scan ring.
// Phase 4 (0.75–1.00) rush, flare, shield expansion, settle.

/** Endpoint i powers on at 0.10 + i*0.045, glow builds over 0.05. */
const activation = (p: number, i: number) =>
  clamp(mapRange(p, 0.10 + i * 0.045, 0.15 + i * 0.045, 0, 1), 0, 1)

/** Line i draws itself right after its endpoint wakes. */
const lineDraw = (p: number, i: number) =>
  clamp(mapRange(p, 0.135 + i * 0.045, 0.21 + i * 0.045, 0, 1), 0, 1)

/** Packet flow speed — one calm, constant tempo across all phases. */
const PACKET_SPEED = 0.13

/** Dashboard charts draw during Classify. */
const chartDraw = (p: number) => clamp(mapRange(p, 0.34, 0.55, 0, 1), 0, 1)

/** "Live" chart oscillation amount — Monitor onward. */
const liveAmount = (p: number) => clamp(mapRange(p, 0.55, 0.62, 0, 1), 0, 1)

/** Secure-phase flare on the core. */
const flareAmount = (p: number) => clamp(mapRange(p, 0.80, 1.0, 0, 1), 0, 1)

// ─── Endpoint definitions — 4 corners of the isometric scene ─────────────────
interface EndpointDef {
  pos: [number, number]        // x, z on the grid
  label: string
  color: string
}
const ENDPOINTS: EndpointDef[] = [
  { pos: [-5.5, -4.1], label: 'PII',       color: '#00E5FF' },
  { pos: [ 4.4, -3.6], label: 'PHI',       color: '#7B5BF2' },
  { pos: [-4.9,  2.1], label: 'Secrets',   color: '#F59E0B' },
  { pos: [ 4.7,  2.4], label: 'Financial', color: '#10B981' },
]

// Each endpoint connects to the edge of the central platform.
const PLATFORM_R = 2.55
const endpointCurve = (def: EndpointDef): THREE.CubicBezierCurve3 => {
  const [x, z] = def.pos
  const dir = new THREE.Vector3(x, 0, z).normalize()
  const end = dir.clone().multiplyScalar(PLATFORM_R * 0.92)
  // Gentle sideways bow so lines read as routed paths, not spokes.
  const side = new THREE.Vector3(-dir.z, 0, dir.x).multiplyScalar(x * z > 0 ? 0.9 : -0.9)
  // Slightly lifted mid-arc so the pipes read above the grid floor.
  return new THREE.CubicBezierCurve3(
    new THREE.Vector3(x, 0.08, z),
    new THREE.Vector3(x * 0.62 + side.x, 0.45, z * 0.62 + side.z),
    new THREE.Vector3(end.x * 1.6 + side.x * 0.4, 0.45, end.z * 1.6 + side.z * 0.4),
    new THREE.Vector3(end.x, 0.12, end.z),
  )
}

// ─── Central server towers (on the platform) ─────────────────────────────────
interface TowerDef { pos: [number, number]; h: number; seg: number; primary?: boolean }
const TOWERS: TowerDef[] = [
  { pos: [ 0.0,  0.0], h: 3.0, seg: 5, primary: true },
  { pos: [ 1.3,  0.55], h: 2.2, seg: 4 },
  { pos: [-1.2,  0.5], h: 2.5, seg: 4 },
  { pos: [ 0.45, -1.15], h: 1.8, seg: 3 },
]
const PLATFORM_H = 0.22

function DatabaseTower({ def, phase, capRefs, index }: {
  def: TowerDef; phase: number
  capRefs: React.MutableRefObject<THREE.MeshStandardMaterial[]>
  index: number
}) {
  const capRef = useRef<THREE.MeshStandardMaterial | null>(null)
  const [cx, cz] = def.pos
  const W = def.primary ? 1.05 : 0.9
  const gap = 0.09
  const segH = (def.h - gap * (def.seg - 1)) / def.seg

  useFrame((state) => {
    if (!capRef.current) return
    const t = state.clock.elapsedTime
    capRef.current.emissiveIntensity = 1.6 + Math.sin(t * 2.0 + phase) * 0.6
  })

  return (
    <group position={[cx, PLATFORM_H, cz]}>
      {Array.from({ length: def.seg }, (_, i) => {
        const y = i * (segH + gap) + segH / 2
        return (
          <mesh key={i} position={[0, y, 0]} castShadow>
            <boxGeometry args={[W, segH, W]} />
            <meshStandardMaterial
              color={NAVY_BODY}
              emissive="#1a1245"
              emissiveIntensity={0.5}
              metalness={0.5}
              roughness={0.35}
            />
            <Edges color={CYAN} />
          </mesh>
        )
      })}
      {/* Glowing energy cap */}
      <mesh position={[0, def.h + 0.06, 0]}>
        <boxGeometry args={[W * 0.92, 0.14, W * 0.92]} />
        <meshStandardMaterial
          ref={(m: THREE.MeshStandardMaterial | null) => {
            capRef.current = m
            if (m) capRefs.current[index] = m
          }}
          color={TEAL} emissive={TEAL} emissiveIntensity={1.8} toneMapped={false}
        />
      </mesh>
    </group>
  )
}

// ─── Central platform / dais with glowing light pool ─────────────────────────
function Platform({ progressRef }: { progressRef: React.RefObject<number> }) {
  const poolRef = useRef<THREE.MeshBasicMaterial>(null)
  const rimRef = useRef<THREE.MeshBasicMaterial>(null)

  useFrame((state) => {
    const p = progressRef.current ?? 0
    const t = state.clock.elapsedTime
    const flare = flareAmount(p)
    if (poolRef.current) poolRef.current.opacity = 0.07 + Math.sin(t * 1.4) * 0.02 + flare * 0.10
    if (rimRef.current) rimRef.current.opacity = 0.4 + Math.sin(t * 1.4) * 0.08 + flare * 0.5
  })

  return (
    <group>
      {/* Dais body */}
      <mesh position={[0, PLATFORM_H / 2, 0]}>
        <cylinderGeometry args={[PLATFORM_R, PLATFORM_R + 0.15, PLATFORM_H, 48]} />
        <meshStandardMaterial color={NAVY_BODY} emissive="#0b1030" emissiveIntensity={0.6} metalness={0.55} roughness={0.35} />
      </mesh>
      {/* Glowing pool of light on the dais surface */}
      <mesh position={[0, PLATFORM_H + 0.005, 0]} rotation={[-Math.PI / 2, 0, 0]}>
        <circleGeometry args={[PLATFORM_R * 0.97, 48]} />
        <meshBasicMaterial ref={poolRef} color={CYAN} transparent opacity={0.07}
          blending={THREE.AdditiveBlending} depthWrite={false} toneMapped={false} />
      </mesh>
      {/* Bright rim ring */}
      <mesh position={[0, PLATFORM_H + 0.01, 0]} rotation={[-Math.PI / 2, 0, 0]}>
        <ringGeometry args={[PLATFORM_R * 0.94, PLATFORM_R, 64]} />
        <meshBasicMaterial ref={rimRef} color={TEAL} transparent opacity={0.4}
          blending={THREE.AdditiveBlending} depthWrite={false} toneMapped={false} />
      </mesh>
    </group>
  )
}

// ─── Holographic dashboard panels ─────────────────────────────────────────────
function panelFrame(w: number, h: number): [number, number, number][] {
  const x = w / 2, y = h / 2
  return [[-x, -y, 0], [x, -y, 0], [x, y, 0], [-x, y, 0], [-x, -y, 0]]
}

function PanelShell({ w, h, opacityRef, children }: {
  w: number; h: number
  opacityRef: React.MutableRefObject<number>
  children: React.ReactNode
}) {
  const bgRef = useRef<THREE.MeshBasicMaterial>(null)
  const frameRef = useRef<any>(null)

  useFrame(() => {
    const o = opacityRef.current
    if (bgRef.current) bgRef.current.opacity = 0.10 * o
    if (frameRef.current?.material) frameRef.current.material.opacity = 0.65 * o
  })

  return (
    <group>
      <mesh>
        <planeGeometry args={[w, h]} />
        <meshBasicMaterial ref={bgRef} color="#0a1440" transparent opacity={0}
          side={THREE.DoubleSide} depthWrite={false} />
      </mesh>
      <Line ref={frameRef} points={panelFrame(w, h)} color={CYAN} lineWidth={1.2}
        transparent opacity={0} toneMapped={false} />
      {children}
    </group>
  )
}

/** Area/line chart — draws left to right, pulses when live. */
function AreaChartPanel({ progressRef }: { progressRef: React.RefObject<number> }) {
  const N = 24
  const W = 1.7, H = 1.0
  const opacityRef = useRef(0)
  const lineRef = useRef<any>(null)
  const groupRef = useRef<THREE.Group>(null)

  // Smooth rising pseudo-random profile.
  const heights = useMemo(() => {
    const hs: number[] = []
    for (let i = 0; i < N; i++) {
      const t = i / (N - 1)
      hs.push(0.12 + t * 0.55 + Math.sin(i * 1.7) * 0.09 + Math.sin(i * 0.6) * 0.06)
    }
    return hs
  }, [])

  useFrame((state) => {
    const p = progressRef.current ?? 0
    const t = state.clock.elapsedTime
    opacityRef.current = clamp(mapRange(p, 0.32, 0.42, 0, 1), 0, 1)
    if (groupRef.current) {
      groupRef.current.visible = opacityRef.current > 0.01
      groupRef.current.position.y = 3.55 + Math.sin(t * 0.7) * 0.06
    }
    if (!lineRef.current) return

    const draw = chartDraw(p)
    const live = liveAmount(p)
    const n = Math.max(2, Math.round(N * draw))
    const pts: number[] = []
    for (let i = 0; i < n; i++) {
      const x = -W / 2 + 0.08 + (i / (N - 1)) * (W - 0.16)
      const osc = live * Math.sin(t * 2.2 + i * 0.8) * 0.035
      pts.push(x, -H / 2 + 0.12 + (heights[i] + osc) * (H - 0.28), 0.01)
    }
    lineRef.current.geometry.setPositions(pts)
    lineRef.current.material.opacity = 0.9 * opacityRef.current
  })

  return (
    <group ref={groupRef} position={[-2.5, 3.55, 0.7]} rotation={[0, 0.62, 0]} visible={false}>
      <PanelShell w={W} h={H} opacityRef={opacityRef}>
        <Line ref={lineRef} points={[[-W / 2 + 0.08, -H / 2 + 0.2, 0.01], [-W / 2 + 0.12, -H / 2 + 0.2, 0.01]]}
          color={TEAL} lineWidth={2.2} transparent opacity={0} toneMapped={false} />
      </PanelShell>
    </group>
  )
}

/** Circular gauge — arc fills clockwise, live percentage readout. */
function GaugePanel({ progressRef }: { progressRef: React.RefObject<number> }) {
  const W = 1.15, H = 1.15
  const R = 0.36
  const SEGS = 48
  const opacityRef = useRef(0)
  const arcRef = useRef<any>(null)
  const trackRef = useRef<any>(null)
  const groupRef = useRef<THREE.Group>(null)
  const textRef = useRef<HTMLDivElement>(null)

  const trackPts = useMemo<[number, number, number][]>(() => {
    const pts: [number, number, number][] = []
    for (let i = 0; i <= SEGS; i++) {
      const a = Math.PI / 2 - (i / SEGS) * Math.PI * 2
      pts.push([Math.cos(a) * R, Math.sin(a) * R, 0.01])
    }
    return pts
  }, [])

  useFrame((state) => {
    const p = progressRef.current ?? 0
    const t = state.clock.elapsedTime
    opacityRef.current = clamp(mapRange(p, 0.34, 0.44, 0, 1), 0, 1)
    if (groupRef.current) {
      groupRef.current.visible = opacityRef.current > 0.01
      groupRef.current.position.y = 3.95 + Math.sin(t * 0.8 + 1.7) * 0.06
    }
    if (!arcRef.current) return

    const live = liveAmount(p)
    const fill = chartDraw(p) * (0.82 + live * Math.sin(t * 1.6) * 0.04)
    const n = Math.max(2, Math.round(SEGS * clamp(fill, 0, 1)))
    const pts: number[] = []
    for (let i = 0; i < n; i++) {
      const a = Math.PI / 2 - (i / SEGS) * Math.PI * 2
      pts.push(Math.cos(a) * R, Math.sin(a) * R, 0.012)
    }
    arcRef.current.geometry.setPositions(pts)
    arcRef.current.material.opacity = 0.95 * opacityRef.current
    if (trackRef.current?.material) trackRef.current.material.opacity = 0.18 * opacityRef.current

    if (textRef.current) {
      textRef.current.style.opacity = String(opacityRef.current)
      textRef.current.textContent = `${Math.round(fill * 100)}%`
    }
  })

  return (
    <group ref={groupRef} position={[2.6, 3.95, -0.1]} rotation={[0, -0.55, 0]} visible={false}>
      <PanelShell w={W} h={H} opacityRef={opacityRef}>
        <Line ref={trackRef} points={trackPts} color={CYAN} lineWidth={1.4}
          transparent opacity={0} toneMapped={false} />
        <Line ref={arcRef} points={[trackPts[0], trackPts[1]]} color={TEAL} lineWidth={3}
          transparent opacity={0} toneMapped={false} />
        <Html center transform distanceFactor={6} position={[0, 0, 0.02]} style={{ pointerEvents: 'none' }}>
          <div ref={textRef} style={{
            fontFamily: FONTS.mono, fontSize: '14px', color: CYAN,
            textShadow: `0 0 8px ${CYAN}`, opacity: 0, whiteSpace: 'nowrap',
          }}>0%</div>
        </Html>
      </PanelShell>
    </group>
  )
}

/** Bar chart — bars grow in, oscillate gently when live. */
function BarChartPanel({ progressRef }: { progressRef: React.RefObject<number> }) {
  const W = 1.4, H = 0.9
  const BARS = 6
  const opacityRef = useRef(0)
  const groupRef = useRef<THREE.Group>(null)
  const barRefs = useRef<(THREE.Mesh | null)[]>([])
  const matRefs = useRef<(THREE.MeshBasicMaterial | null)[]>([])
  const baseH = useMemo(() => [0.42, 0.68, 0.5, 0.85, 0.62, 0.74], [])

  useFrame((state) => {
    const p = progressRef.current ?? 0
    const t = state.clock.elapsedTime
    opacityRef.current = clamp(mapRange(p, 0.36, 0.46, 0, 1), 0, 1)
    if (groupRef.current) {
      groupRef.current.visible = opacityRef.current > 0.01
      groupRef.current.position.y = 2.85 + Math.sin(t * 0.75 + 3.1) * 0.05
    }
    const draw = chartDraw(p)
    const live = liveAmount(p)
    for (let i = 0; i < BARS; i++) {
      const mesh = barRefs.current[i]
      const mat = matRefs.current[i]
      if (!mesh || !mat) continue
      const grow = clamp(mapRange(draw, i / BARS, (i + 1) / BARS + 0.2, 0, 1), 0, 1)
      const osc = 1 + live * Math.sin(t * 2.6 + i * 1.1) * 0.08
      const bh = Math.max(0.001, baseH[i] * grow * osc * (H - 0.24))
      mesh.scale.y = bh
      mesh.position.y = -H / 2 + 0.12 + bh / 2
      mat.opacity = 0.85 * opacityRef.current
    }
  })

  const barW = (W - 0.3) / BARS
  return (
    <group ref={groupRef} position={[1.15, 2.85, 1.9]} rotation={[0, -0.35, 0]} visible={false}>
      <PanelShell w={W} h={H} opacityRef={opacityRef}>
        {Array.from({ length: BARS }, (_, i) => (
          <mesh
            key={i}
            ref={(el) => (barRefs.current[i] = el)}
            position={[-W / 2 + 0.2 + i * barW, -H / 2 + 0.12, 0.01]}
          >
            <boxGeometry args={[barW * 0.55, 1, 0.02]} />
            <meshBasicMaterial
              ref={(m: THREE.MeshBasicMaterial | null) => (matRefs.current[i] = m)}
              color={i % 2 === 0 ? CYAN : TEAL} transparent opacity={0}
              depthWrite={false} toneMapped={false}
            />
          </mesh>
        ))}
      </PanelShell>
    </group>
  )
}

// ─── Endpoint server node — one glowing rack on a small base ─────────────────
function EndpointNode({ def, index, progressRef }: {
  def: EndpointDef; index: number
  progressRef: React.RefObject<number>
}) {
  const [x, z] = def.pos
  const bodyRef = useRef<THREE.MeshStandardMaterial>(null)
  const lightRef = useRef<THREE.MeshStandardMaterial>(null)
  const slotRefs = useRef<(THREE.MeshBasicMaterial | null)[]>([])
  const labelRef = useRef<HTMLDivElement>(null)

  useFrame((state) => {
    const p = progressRef.current ?? 0
    const t = state.clock.elapsedTime
    const act = activation(p, index)
    const flare = flareAmount(p)

    if (bodyRef.current) bodyRef.current.emissiveIntensity = 0.25 + act * 0.55
    if (lightRef.current) {
      lightRef.current.emissiveIntensity = 0.15 + act * (2.0 + Math.sin(t * 2.4 + index * 1.7) * 0.7) + flare * 1.4
    }
    slotRefs.current.forEach((m, i) => {
      if (m) m.opacity = act * (0.35 + 0.3 * Math.abs(Math.sin(t * 1.8 + i * 2.1 + index)))
    })

    // Classify-phase label pill above the rack.
    if (labelRef.current) {
      const op = clamp(mapRange(p, 0.32 + index * 0.05, 0.36 + index * 0.05, 0, 1), 0, 1)
      labelRef.current.style.opacity = String(op)
    }
  })

  // Face the rack roughly toward the center.
  const rotY = Math.atan2(-x, -z)

  return (
    <group position={[x, 0, z]} rotation={[0, rotY, 0]}>
      {/* Raised base */}
      <mesh position={[0, 0.07, 0]}>
        <boxGeometry args={[1.1, 0.14, 1.1]} />
        <meshStandardMaterial color={NAVY_BODY} emissive="#0b1030" emissiveIntensity={0.5} metalness={0.5} roughness={0.4} />
        <Edges color={CYAN} />
      </mesh>
      {/* Rack body */}
      <mesh position={[0, 0.14 + 0.62, 0]}>
        <boxGeometry args={[0.72, 1.24, 0.72]} />
        <meshStandardMaterial ref={bodyRef} color={NAVY_BODY} emissive="#131a4a"
          emissiveIntensity={0.25} metalness={0.55} roughness={0.35} />
        <Edges color={CYAN} />
      </mesh>
      {/* Slot strips on the front face */}
      {[0.42, 0.66, 0.9].map((y, i) => (
        <mesh key={i} position={[0, 0.14 + y, 0.365]}>
          <planeGeometry args={[0.5, 0.05]} />
          <meshBasicMaterial
            ref={(m: THREE.MeshBasicMaterial | null) => (slotRefs.current[i] = m)}
            color={CYAN} transparent opacity={0} depthWrite={false} toneMapped={false}
          />
        </mesh>
      ))}
      {/* Indicator light — endpoint's data-type color */}
      <mesh position={[0, 0.14 + 1.12, 0.365]}>
        <sphereGeometry args={[0.055, 10, 10]} />
        <meshStandardMaterial ref={lightRef} color={def.color} emissive={def.color}
          emissiveIntensity={0.15} toneMapped={false} />
      </mesh>
      {/* Data-type pill label (Classify phase onward) */}
      <Html center position={[0, 2.15, 0]} style={{ pointerEvents: 'none' }} zIndexRange={[4, 0]}>
        <div ref={labelRef} style={{
          fontFamily: FONTS.mono, fontSize: '11px', letterSpacing: '0.08em',
          color: def.color, background: 'rgba(15,21,53,0.9)',
          border: `1px solid ${def.color}`, borderRadius: '999px', padding: '4px 12px',
          boxShadow: `0 0 12px ${def.color}55`, opacity: 0, whiteSpace: 'nowrap',
          transition: 'opacity 0.2s linear',
        }}>
          {def.label}
        </div>
      </Html>
    </group>
  )
}

// ─── Data line + packets from one endpoint into the core ─────────────────────
function DataLine({ def, index, progressRef }: {
  def: EndpointDef; index: number
  progressRef: React.RefObject<number>
}) {
  const glowRef = useRef<any>(null)
  const coreRef = useRef<any>(null)
  const packetRefs = useRef<(THREE.Mesh | null)[]>([])
  const PACKETS = 4

  const { curve, pts, flat } = useMemo(() => {
    const curve = endpointCurve(def)
    const pts = curve.getPoints(90)
    return { curve, pts, flat: pts.flatMap((v) => [v.x, v.y, v.z]) }
  }, [def])

  useFrame((state) => {
    const p = progressRef.current ?? 0
    const t = state.clock.elapsedTime
    const draw = lineDraw(p, index)
    const visible = draw > 0.004

    if (glowRef.current && coreRef.current) {
      glowRef.current.visible = visible
      coreRef.current.visible = visible
      if (visible) {
        const n = Math.max(2, Math.floor(pts.length * draw))
        const sub = flat.slice(0, n * 3)
        glowRef.current.geometry.setPositions(sub)
        coreRef.current.geometry.setPositions(sub)
      }
    }

    // Packets: flow endpoint → core once the line is fully drawn (Classify onward).
    const flowing = p >= 0.30 && draw > 0.999
    // More packets as the phases progress: 2 → 4.
    const active = p >= 0.55 ? PACKETS : 2
    for (let i = 0; i < PACKETS; i++) {
      const m = packetRefs.current[i]
      if (!m) continue
      const show = flowing && i < active
      m.visible = show
      if (!show) continue
      const f = (t * PACKET_SPEED + i / PACKETS + index * 0.23) % 1
      const v = curve.getPointAt(f)
      m.position.set(v.x, v.y + 0.05, v.z)
      const s = 1 + 0.3 * Math.sin(f * Math.PI) // slight swell mid-path
      m.scale.setScalar(s)
    }
  })

  return (
    <>
      <Line ref={glowRef} points={[pts[0], pts[1]]} color={CYAN}
        lineWidth={7} transparent opacity={0.32} toneMapped={false} visible={false} />
      <Line ref={coreRef} points={[pts[0], pts[1]]} color="#d6faff"
        lineWidth={2.4} transparent opacity={1} toneMapped={false} visible={false} />
      {Array.from({ length: PACKETS }, (_, i) => (
        <mesh key={i} ref={(el) => (packetRefs.current[i] = el)} visible={false}>
          <boxGeometry args={[0.11, 0.11, 0.11]} />
          <meshStandardMaterial color={CYAN} emissive={CYAN} emissiveIntensity={2.4} toneMapped={false} />
        </mesh>
      ))}
    </>
  )
}

// ─── Scan ring — periodic sweep around the platform (Monitor phase) ──────────
function ScanRing({ progressRef }: { progressRef: React.RefObject<number> }) {
  const meshRef = useRef<THREE.Mesh>(null)
  const matRef = useRef<THREE.MeshBasicMaterial>(null)

  useFrame((state) => {
    const p = progressRef.current ?? 0
    const mesh = meshRef.current
    const mat = matRef.current
    if (!mesh || !mat) return
    const gate = clamp(mapRange(p, 0.55, 0.60, 0, 1), 0, 1) * clamp(mapRange(p, 0.78, 0.74, 0, 1), 0, 1)
    if (gate < 0.01) { mesh.visible = false; return }
    mesh.visible = true
    const cycle = (state.clock.elapsedTime % 3.2) / 3.2
    const r = 2.8 + cycle * 5.6
    mesh.scale.setScalar(r)
    mat.opacity = (1 - cycle) * 0.30 * gate
  })

  return (
    <mesh ref={meshRef} position={[0, 0.02, 0]} rotation={[-Math.PI / 2, 0, 0]} visible={false}>
      <ringGeometry args={[0.96, 1, 64]} />
      <meshBasicMaterial ref={matRef} color={CYAN} transparent opacity={0}
        blending={THREE.AdditiveBlending} depthWrite={false} toneMapped={false} />
    </mesh>
  )
}

// ─── Shield — expanding ring of light + faint dome (Secure phase) ────────────
function Shield({ progressRef }: { progressRef: React.RefObject<number> }) {
  const ringRef = useRef<THREE.Mesh>(null)
  const ringMatRef = useRef<THREE.MeshBasicMaterial>(null)
  const domeMatRef = useRef<THREE.MeshBasicMaterial>(null)

  useFrame((state) => {
    const p = progressRef.current ?? 0
    const t = state.clock.elapsedTime

    // One big ring of light expanding across the whole scene.
    const rt = clamp(mapRange(p, 0.76, 0.92, 0, 1), 0, 1)
    if (ringRef.current && ringMatRef.current) {
      const show = rt > 0.001 && rt < 0.999
      ringRef.current.visible = show
      if (show) {
        ringRef.current.scale.setScalar(2.6 + rt * 12)
        ringMatRef.current.opacity = (1 - rt) * 0.45
      }
    }

    // Faint protective dome settles over the core.
    if (domeMatRef.current) {
      const d = clamp(mapRange(p, 0.82, 0.96, 0, 1), 0, 1)
      domeMatRef.current.opacity = d * (0.045 + Math.sin(t * 1.1) * 0.012)
    }
  })

  return (
    <>
      <mesh ref={ringRef} position={[0, 0.025, 0]} rotation={[-Math.PI / 2, 0, 0]} visible={false}>
        <ringGeometry args={[0.965, 1, 64]} />
        <meshBasicMaterial ref={ringMatRef} color={TEAL} transparent opacity={0}
          blending={THREE.AdditiveBlending} depthWrite={false} toneMapped={false} />
      </mesh>
      <mesh position={[0, 0.02, 0]}>
        <sphereGeometry args={[5.4, 40, 24, 0, Math.PI * 2, 0, Math.PI / 2]} />
        <meshBasicMaterial ref={domeMatRef} color={CYAN} transparent opacity={0}
          blending={THREE.AdditiveBlending} depthWrite={false} side={THREE.BackSide} toneMapped={false} />
      </mesh>
    </>
  )
}

// ─── Vertical light streams rising from tower tops ───────────────────────────
function LightStreams({ progressRef }: { progressRef: React.RefObject<number> }) {
  const COUNT = TOWERS.length * 7
  const geoRef = useRef<THREE.BufferGeometry>(null)
  const matRef = useRef<THREE.PointsMaterial>(null)

  const { positions, base, speed } = useMemo(() => {
    const positions = new Float32Array(COUNT * 3)
    const base = new Float32Array(COUNT * 3)
    const speed = new Float32Array(COUNT)
    let k = 0
    TOWERS.forEach((tw) => {
      for (let j = 0; j < 7; j++) {
        const x = tw.pos[0] + (Math.random() - 0.5) * 0.5
        const z = tw.pos[1] + (Math.random() - 0.5) * 0.5
        const topY = PLATFORM_H + tw.h
        const y = topY + Math.random() * 2.2
        base[k * 3] = x; base[k * 3 + 1] = topY; base[k * 3 + 2] = z
        positions[k * 3] = x; positions[k * 3 + 1] = y; positions[k * 3 + 2] = z
        speed[k] = 0.5 + Math.random() * 0.7
        k++
      }
    })
    return { positions, base, speed }
  }, [COUNT])

  useFrame((_, delta) => {
    if (!geoRef.current) return
    const p = progressRef.current ?? 0
    const boost = 1 + flareAmount(p) * 1.6 // streams intensify in Secure
    const arr = geoRef.current.attributes.position.array as Float32Array
    for (let i = 0; i < COUNT; i++) {
      arr[i * 3 + 1] += speed[i] * boost * delta
      if (arr[i * 3 + 1] > base[i * 3 + 1] + 2.4) arr[i * 3 + 1] = base[i * 3 + 1]
    }
    geoRef.current.attributes.position.needsUpdate = true
    if (matRef.current) matRef.current.opacity = 0.85 + flareAmount(p) * 0.15
  })

  return (
    <points>
      <bufferGeometry ref={geoRef}>
        <bufferAttribute attach="attributes-position" array={positions} count={COUNT} itemSize={3} />
      </bufferGeometry>
      <pointsMaterial ref={matRef} color={CYAN} size={0.09} transparent opacity={0.85} sizeAttenuation
        blending={THREE.AdditiveBlending} depthWrite={false} toneMapped={false} />
    </points>
  )
}

// ─── Secure-phase core flare — overrides tower-cap idle pulse ────────────────
function CoreFlare({ progressRef, capRefs }: {
  progressRef: React.RefObject<number>
  capRefs: React.MutableRefObject<THREE.MeshStandardMaterial[]>
}) {
  useFrame(() => {
    const p = progressRef.current ?? 0
    const flare = flareAmount(p)
    if (flare > 0.001) {
      capRefs.current.forEach((mat) => {
        if (mat) mat.emissiveIntensity = 1.8 + flare * 3.6
      })
    }
  })
  return null
}

// ─── Persistent grid ground plane ────────────────────────────────────────────
function GridFloor() {
  const ref = useRef<THREE.GridHelper>(null)
  const t = useRef(0)
  const inited = useRef(false)
  useFrame((_, delta) => {
    const g = ref.current
    if (!g) return
    const mat = g.material as THREE.Material & { opacity: number }
    if (!inited.current) { mat.transparent = true; inited.current = true }
    t.current += delta
    mat.opacity = 0.32 + Math.sin(t.current * (Math.PI * 2 / 4)) * 0.08
  })
  return <gridHelper ref={ref} args={[26, 26, CYAN, CYAN]} position={[0, 0, 0]} />
}

// ─── Camera — grounded, tiny transition then steady ──────────────────────────
function CameraRig({ progressRef, mouseRef }: {
  progressRef: React.RefObject<number>
  mouseRef: React.RefObject<{ x: number; y: number }>
}) {
  const { camera } = useThree()
  const mx = useRef(0)
  const my = useRef(0)
  useFrame(() => {
    const p = progressRef.current ?? 0
    const t = clamp(p / 0.1, 0, 1)          // small entry transition over first 10%
    const dist = 1 + 0.08 * t               // pull back ~8%
    const tmx = (mouseRef.current?.x ?? 0) / (window.innerWidth || 1) - 0.5
    const tmy = (mouseRef.current?.y ?? 0) / (window.innerHeight || 1) - 0.5
    mx.current = lerp(mx.current, tmx, 0.04)
    my.current = lerp(my.current, tmy, 0.04)
    camera.position.set(
      4.8 * dist + mx.current * 0.6,
      4.7 - 0.23 * t - my.current * 0.4,   // lower ~5%
      9.2 * dist,
    )
    camera.lookAt(0, 0.9, 0)
  })
  return null
}

// ─── Scene content ───────────────────────────────────────────────────────────
function SceneContent({ progressRef, mouseRef, capRefs }: {
  progressRef: React.RefObject<number>
  mouseRef: React.RefObject<{ x: number; y: number }>
  capRefs: React.MutableRefObject<THREE.MeshStandardMaterial[]>
}) {
  const groupRef = useRef<THREE.Group>(null)
  useFrame((state) => {
    if (groupRef.current) groupRef.current.position.y = Math.sin(state.clock.elapsedTime * 0.6) * 0.05
  })

  return (
    <>
      <CameraRig progressRef={progressRef} mouseRef={mouseRef} />

      <ambientLight color="#0F1535" intensity={0.9} />
      <directionalLight color="#ffffff" intensity={0.7} position={[5, 9, 5]} />
      <pointLight color={CYAN} intensity={3} position={[-3, 4, 3]} distance={16} decay={2} />
      <pointLight color="#7B5BF2" intensity={1.4} position={[4, 2, -3]} distance={14} decay={2} />

      <GridFloor />

      {/* The SENTRO core — dais, towers, holo dashboards, light streams */}
      <group ref={groupRef}>
        <Platform progressRef={progressRef} />
        {TOWERS.map((def, i) => (
          <DatabaseTower key={i} def={def} phase={i * 1.3} capRefs={capRefs} index={i} />
        ))}
        <LightStreams progressRef={progressRef} />
        <AreaChartPanel progressRef={progressRef} />
        <GaugePanel progressRef={progressRef} />
        <BarChartPanel progressRef={progressRef} />
      </group>

      {/* Perimeter endpoints + data lines into the core */}
      {ENDPOINTS.map((def, i) => (
        <EndpointNode key={def.label} def={def} index={i} progressRef={progressRef} />
      ))}
      {ENDPOINTS.map((def, i) => (
        <DataLine key={def.label} def={def} index={i} progressRef={progressRef} />
      ))}

      <ScanRing progressRef={progressRef} />
      <Shield progressRef={progressRef} />
      <CoreFlare progressRef={progressRef} capRefs={capRefs} />

      {/* Subtle bloom — makes every emissive element glow softly */}
      <EffectComposer>
        <Bloom intensity={0.6} luminanceThreshold={0.2} luminanceSmoothing={0.55} mipmapBlur />
      </EffectComposer>
    </>
  )
}

// ─── Cap-material registry so the flare can drive all tower tops ─────────────
function useCapRegistry() {
  const capRefs = useRef<THREE.MeshStandardMaterial[]>([])
  return capRefs
}

interface DataCenterSceneProps {
  progressRef: React.RefObject<number>
  mouseRef: React.RefObject<{ x: number; y: number }>
}

export default function DataCenterScene({ progressRef, mouseRef }: DataCenterSceneProps) {
  const capRefs = useCapRegistry()
  return (
    <Canvas
      camera={{ position: [4.8, 4.7, 9.2], fov: 45, near: 0.1, far: 100 }}
      gl={{ antialias: true, alpha: true }}
      dpr={[1, 1.5]}
      style={{ background: 'transparent' }}
    >
      <color attach="background" args={['#070B1A']} />
      <Suspense fallback={null}>
        <SceneContent progressRef={progressRef} mouseRef={mouseRef} capRefs={capRefs} />
      </Suspense>
    </Canvas>
  )
}
