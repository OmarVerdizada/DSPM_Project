import { useRef, useMemo, Suspense } from 'react'
import { Canvas, useFrame, useThree } from '@react-three/fiber'
import { Edges, Line, Sparkles, Environment } from '@react-three/drei'
import * as THREE from 'three'
import { lerp, clamp } from '../../utils/lerp'

interface CameraRigProps {
  mouseRef: React.RefObject<{ x: number; y: number }>
}

interface GridFloorProps {
  progressRef: React.RefObject<number>
}

// Cyan grid ground plane. Brighter in the hero rest state with a slow 4s glow pulse;
// as the hero scrolls away (progress 0→1) it relaxes back to a quiet resting intensity.
function GridFloor({ progressRef }: GridFloorProps) {
  const ref = useRef<THREE.GridHelper>(null)
  const t = useRef(0)
  const inited = useRef(false)

  useFrame((_, delta) => {
    const grid = ref.current
    if (!grid) return
    const mat = grid.material as THREE.Material & { opacity: number }
    if (!inited.current) {
      mat.transparent = true
      inited.current = true
    }
    t.current += delta
    const pulse = 0.4 + Math.sin(t.current * ((Math.PI * 2) / 4)) * 0.12
    const p = clamp(progressRef.current ?? 0, 0, 1)
    mat.opacity = lerp(pulse, 0.15, p)
  })

  return <gridHelper ref={ref} args={[20, 20, '#00E5FF', '#00E5FF']} position={[0, -2.5, 0]} />
}

function CameraRig({ mouseRef }: CameraRigProps) {
  const { camera } = useThree()
  const azimuthRef = useRef(0)
  const elevationRef = useRef(0)

  useFrame(() => {
    const mx = mouseRef.current?.x ?? 0
    const my = mouseRef.current?.y ?? 0
    const targetAzimuth = (mx / (window.innerWidth || 1) - 0.5) * (Math.PI / 36)
    const targetElevation = (my / (window.innerHeight || 1) - 0.5) * (Math.PI / 48)
    azimuthRef.current = lerp(azimuthRef.current, targetAzimuth, 0.03)
    elevationRef.current = lerp(elevationRef.current, targetElevation, 0.03)
    camera.position.x = Math.sin(azimuthRef.current) * 8
    camera.position.y = 1.5 - elevationRef.current * 2
    camera.position.z = Math.cos(azimuthRef.current) * 8
    camera.lookAt(0, 0, 0)
  })
  return null
}

function ServerMonolith() {
  const meshRef = useRef<THREE.Mesh>(null)
  const t = useRef(0)

  useFrame((_, delta) => {
    if (!meshRef.current) return
    t.current += delta
    meshRef.current.rotation.y += delta * 0.08
    meshRef.current.position.y = Math.sin(t.current * 0.8) * 0.15
  })

  return (
    <mesh ref={meshRef} castShadow>
      <boxGeometry args={[1.2, 2.4, 0.8]} />
      <meshStandardMaterial
        color="#0F1535"
        transparent
        opacity={0.85}
        emissive="#1A2250"
        emissiveIntensity={0.4}
        metalness={0.6}
        roughness={0.2}
      />
      <Edges color="#00E5FF" />
    </mesh>
  )
}

interface DataNodeProps {
  type: 'box' | 'sphere' | 'octahedron'
  radius: number
  speed: number
  offset: number
  inclination: number
  scale: number
  color: string
}

function DataNode({ type, radius, speed, offset, inclination, scale, color }: DataNodeProps) {
  const meshRef = useRef<THREE.Mesh>(null)
  const matRef = useRef<THREE.MeshStandardMaterial>(null)
  const pulseTimer = useRef(Math.random() * 4)
  const t = useRef(offset)

  useFrame((_, delta) => {
    if (!meshRef.current || !matRef.current) return
    t.current += delta * speed

    const x = Math.cos(t.current) * radius
    const z = Math.sin(t.current) * radius
    const y = Math.sin(t.current + inclination) * radius * 0.3 + Math.cos(inclination) * 0.5

    meshRef.current.position.set(x, y, z)
    meshRef.current.rotation.x += delta * 0.5
    meshRef.current.rotation.z += delta * 0.3

    pulseTimer.current -= delta
    if (pulseTimer.current <= 0) {
      matRef.current.emissiveIntensity = 2.5
      pulseTimer.current = 2 + Math.random() * 3
    } else {
      matRef.current.emissiveIntensity = lerp(matRef.current.emissiveIntensity, 0.6, delta * 3)
    }
  })

  return (
    <mesh ref={meshRef} scale={scale}>
      {type === 'box' && <boxGeometry args={[1, 1, 1]} />}
      {type === 'sphere' && <sphereGeometry args={[0.6, 8, 8]} />}
      {type === 'octahedron' && <octahedronGeometry args={[0.7]} />}
      <meshStandardMaterial
        ref={matRef}
        color={color}
        emissive={color}
        emissiveIntensity={0.6}
        transparent
        opacity={0.75}
        metalness={0.4}
        roughness={0.3}
      />
    </mesh>
  )
}

function ConnectionLines() {
  const nodePositions = useMemo<[number, number, number][]>(
    () => [
      [3, 0.5, 0],
      [-3, -0.3, 1],
      [2, 1.5, -2],
      [-2, -1, -2],
      [1, 2, 2],
      [-1, 1.5, 3],
    ],
    []
  )

  return (
    <>
      {nodePositions.map((pos, i) => (
        <Line
          key={i}
          points={[[0, 0, 0], pos]}
          color="#00E5FF"
          lineWidth={0.8}
          transparent
          opacity={0.2}
          dashed
          dashSize={0.3}
          gapSize={0.2}
        />
      ))}
    </>
  )
}

function AmbientParticles() {
  const positions = useMemo(() => {
    const arr = new Float32Array(80 * 3)
    for (let i = 0; i < 80; i++) {
      const theta = Math.random() * Math.PI * 2
      const phi = Math.acos(2 * Math.random() - 1)
      const r = 4 + Math.random() * 4
      arr[i * 3] = r * Math.sin(phi) * Math.cos(theta)
      arr[i * 3 + 1] = r * Math.sin(phi) * Math.sin(theta)
      arr[i * 3 + 2] = r * Math.cos(phi)
    }
    return arr
  }, [])

  const velocities = useMemo(() => {
    return Array.from({ length: 80 }, () => ({
      vx: (Math.random() - 0.5) * 0.002,
      vy: (Math.random() - 0.5) * 0.002,
      vz: (Math.random() - 0.5) * 0.002,
    }))
  }, [])

  const geoRef = useRef<THREE.BufferGeometry>(null)

  useFrame(() => {
    if (!geoRef.current) return
    const pos = geoRef.current.attributes.position as THREE.BufferAttribute
    const arr = pos.array as Float32Array
    for (let i = 0; i < 80; i++) {
      arr[i * 3] += velocities[i].vx
      arr[i * 3 + 1] += velocities[i].vy
      arr[i * 3 + 2] += velocities[i].vz
      const dist = Math.sqrt(arr[i * 3] ** 2 + arr[i * 3 + 1] ** 2 + arr[i * 3 + 2] ** 2)
      if (dist > 8 || dist < 3) {
        velocities[i].vx *= -1
        velocities[i].vy *= -1
        velocities[i].vz *= -1
      }
    }
    pos.needsUpdate = true
  })

  return (
    <points>
      <bufferGeometry ref={geoRef}>
        <bufferAttribute
          attach="attributes-position"
          array={positions}
          count={80}
          itemSize={3}
        />
      </bufferGeometry>
      <pointsMaterial
        color="#00E5FF"
        size={0.05}
        transparent
        opacity={0.4}
        sizeAttenuation
        blending={THREE.AdditiveBlending}
        depthWrite={false}
      />
    </points>
  )
}

const NODE_CONFIG: DataNodeProps[] = [
  { type: 'box', radius: 2.5, speed: 0.4, offset: 0, inclination: 0.2, scale: 0.22, color: '#00E5FF' },
  { type: 'sphere', radius: 3.2, speed: 0.3, offset: 1.0, inclination: 0.8, scale: 0.2, color: '#3B6BF5' },
  { type: 'octahedron', radius: 2.8, speed: 0.5, offset: 2.1, inclination: -0.5, scale: 0.25, color: '#7B5BF2' },
  { type: 'box', radius: 3.8, speed: 0.25, offset: 3.5, inclination: 1.1, scale: 0.18, color: '#00E5FF' },
  { type: 'sphere', radius: 2.3, speed: 0.6, offset: 0.7, inclination: -0.9, scale: 0.15, color: '#00E5FF' },
  { type: 'octahedron', radius: 4.2, speed: 0.2, offset: 1.8, inclination: 0.4, scale: 0.22, color: '#7B5BF2' },
  { type: 'box', radius: 3.0, speed: 0.45, offset: 4.5, inclination: 1.5, scale: 0.2, color: '#3B6BF5' },
  { type: 'sphere', radius: 4.5, speed: 0.15, offset: 2.9, inclination: -1.2, scale: 0.18, color: '#00E5FF' },
  { type: 'octahedron', radius: 2.0, speed: 0.7, offset: 3.8, inclination: 0.7, scale: 0.15, color: '#7B5BF2' },
  { type: 'box', radius: 3.5, speed: 0.35, offset: 5.2, inclination: -0.3, scale: 0.2, color: '#00E5FF' },
  { type: 'sphere', radius: 4.8, speed: 0.18, offset: 1.4, inclination: 1.3, scale: 0.16, color: '#3B6BF5' },
  { type: 'octahedron', radius: 3.3, speed: 0.55, offset: 6.1, inclination: -1.0, scale: 0.24, color: '#7B5BF2' },
]

interface HeroSceneContentProps {
  mouseRef: React.RefObject<{ x: number; y: number }>
  progressRef: React.RefObject<number>
}

function HeroSceneContent({ mouseRef, progressRef }: HeroSceneContentProps) {
  return (
    <>
      <CameraRig mouseRef={mouseRef} />

      <ambientLight color="#0F1535" intensity={0.8} />
      <directionalLight color="#ffffff" intensity={0.8} position={[5, 8, 5]} />
      <pointLight color="#00E5FF" intensity={3} position={[-3, 3, -3]} distance={12} decay={2} />
      <pointLight color="#7B5BF2" intensity={1.5} position={[4, -2, 4]} distance={10} decay={2} />

      <Environment preset="night" />

      <ServerMonolith />

      {NODE_CONFIG.map((config, i) => (
        <DataNode key={i} {...config} />
      ))}

      <ConnectionLines />
      <AmbientParticles />

      <Sparkles
        count={40}
        size={0.6}
        speed={0.08}
        color="#00E5FF"
        scale={14}
        opacity={0.3}
      />

      <GridFloor progressRef={progressRef} />
    </>
  )
}

interface HeroSceneProps {
  mouseRef: React.RefObject<{ x: number; y: number }>
  progressRef: React.RefObject<number>
}

export default function HeroScene({ mouseRef, progressRef }: HeroSceneProps) {
  return (
    <Canvas
      camera={{ position: [0, 1.5, 8], fov: 50, near: 0.1, far: 100 }}
      gl={{ antialias: true, alpha: true }}
      dpr={[1, 1.5]}
      style={{ background: 'transparent' }}
    >
      <Suspense fallback={null}>
        <HeroSceneContent mouseRef={mouseRef} progressRef={progressRef} />
      </Suspense>
    </Canvas>
  )
}
