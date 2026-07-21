import { useRef, useMemo, type MutableRefObject } from 'react'
import { useFrame, useThree } from '@react-three/fiber'
import * as THREE from 'three'

// ─────────────────────────────────────────────────────────────────────────────
// "System boot" scene behind the intro overlay.
//
// The grid, camera and colors replicate the hero DataCenterScene's initial
// state (gridHelper 26×26 cyan, camera [4.8, 4.7, 9.2] → lookAt(0, 0.9, 0))
// so when the overlay fades the intro grid seamlessly becomes the scene grid.
// ─────────────────────────────────────────────────────────────────────────────

export interface BootState {
  /** 0→1: grid draws itself in from the center outward */
  grid: number
  /** 0→1: energy ring expanding across the grid (fired when the logo lands) */
  ring: number
  /** 0→1: ambient particle visibility */
  particles: number
}

interface Props {
  bootState: MutableRefObject<BootState>
}

const CYAN = '#00E5FF'
const GRID_EXTENT = 13 // half-size of the 26×26 grid

// ─── Grid that reveals radially from the center ──────────────────────────────
function RevealGrid({ bootState }: Props) {
  const matRef = useRef<THREE.ShaderMaterial>(null)

  const geo = useMemo(() => {
    const verts: number[] = []
    for (let i = -GRID_EXTENT; i <= GRID_EXTENT; i++) {
      verts.push(-GRID_EXTENT, 0, i, GRID_EXTENT, 0, i) // lines along X
      verts.push(i, 0, -GRID_EXTENT, i, 0, GRID_EXTENT) // lines along Z
    }
    const g = new THREE.BufferGeometry()
    g.setAttribute('position', new THREE.Float32BufferAttribute(verts, 3))
    return g
  }, [])

  const uniforms = useMemo(
    () => ({
      uReveal: { value: 0 },
      uColor: { value: new THREE.Color(CYAN) },
    }),
    [],
  )

  useFrame(() => {
    if (!matRef.current) return
    // Reveal radius sweeps 0 → past the far corner (~18.4).
    matRef.current.uniforms.uReveal.value = bootState.current.grid * (GRID_EXTENT * Math.SQRT2 + 1.5)
  })

  return (
    <lineSegments geometry={geo}>
      <shaderMaterial
        ref={matRef}
        transparent
        depthWrite={false}
        uniforms={uniforms}
        vertexShader={/* glsl */ `
          varying vec2 vXZ;
          void main() {
            vXZ = position.xz;
            gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
          }
        `}
        fragmentShader={/* glsl */ `
          uniform float uReveal;
          uniform vec3 uColor;
          varying vec2 vXZ;
          void main() {
            float d = length(vXZ);
            // Illuminated once the reveal front passes; bright leading edge.
            float lit  = smoothstep(uReveal, uReveal - 1.6, d);
            float edge = smoothstep(uReveal - 1.6, uReveal - 0.2, d) * smoothstep(uReveal + 0.2, uReveal - 0.2, d);
            float alpha = lit * 0.32 + edge * 0.5;
            if (alpha < 0.003) discard;
            gl_FragColor = vec4(uColor, alpha);
          }
        `}
      />
    </lineSegments>
  )
}

// ─── Energy ring pulsing outward when the logo lands ─────────────────────────
function PulseRing({ bootState }: Props) {
  const meshRef = useRef<THREE.Mesh>(null)
  const matRef = useRef<THREE.MeshBasicMaterial>(null)

  useFrame(() => {
    const t = bootState.current.ring
    const mesh = meshRef.current
    const mat = matRef.current
    if (!mesh || !mat) return
    const show = t > 0.001 && t < 0.999
    mesh.visible = show
    if (show) {
      mesh.scale.setScalar(0.4 + t * 12)
      mat.opacity = (1 - t) * 0.5
    }
  })

  return (
    <mesh ref={meshRef} position={[0, 0.02, 0]} rotation={[-Math.PI / 2, 0, 0]} visible={false}>
      <ringGeometry args={[0.94, 1, 64]} />
      <meshBasicMaterial ref={matRef} color={CYAN} transparent opacity={0}
        blending={THREE.AdditiveBlending} depthWrite={false} toneMapped={false} />
    </mesh>
  )
}

// ─── Faint ambient particles drifting upward ─────────────────────────────────
function AmbientDots({ bootState }: Props) {
  const matRef = useRef<THREE.PointsMaterial>(null)
  const geoRef = useRef<THREE.BufferGeometry>(null)
  const COUNT = 160

  const positions = useMemo(() => {
    const pos = new Float32Array(COUNT * 3)
    for (let i = 0; i < COUNT; i++) {
      pos[i * 3] = (Math.random() - 0.5) * 22
      pos[i * 3 + 1] = Math.random() * 7
      pos[i * 3 + 2] = (Math.random() - 0.5) * 22
    }
    return pos
  }, [])

  useFrame((_, delta) => {
    if (matRef.current) matRef.current.opacity = bootState.current.particles * 0.35
    const geo = geoRef.current
    if (!geo) return
    const arr = geo.attributes.position.array as Float32Array
    for (let i = 0; i < COUNT; i++) {
      arr[i * 3 + 1] += delta * 0.25
      if (arr[i * 3 + 1] > 7) arr[i * 3 + 1] = 0
    }
    geo.attributes.position.needsUpdate = true
  })

  return (
    <points>
      <bufferGeometry ref={geoRef}>
        <bufferAttribute attach="attributes-position" array={positions} count={COUNT} itemSize={3} />
      </bufferGeometry>
      <pointsMaterial ref={matRef} color={CYAN} size={0.05} sizeAttenuation transparent opacity={0}
        blending={THREE.AdditiveBlending} depthWrite={false} />
    </points>
  )
}

// ─── Static camera matching the hero scene's initial framing ─────────────────
function CameraRig() {
  const { camera } = useThree()
  useFrame(() => {
    camera.position.set(4.8, 4.7, 9.2)
    camera.lookAt(0, 0.9, 0)
  })
  return null
}

// ─────────────────────────────────────────────────────────────────────────────
export default function IntroScene({ bootState }: Props) {
  return (
    <>
      <CameraRig />
      <RevealGrid bootState={bootState} />
      <PulseRing bootState={bootState} />
      <AmbientDots bootState={bootState} />
    </>
  )
}
