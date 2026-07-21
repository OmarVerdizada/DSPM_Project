import { useEffect, useRef } from 'react'
import { gsap } from 'gsap'
import { COLORS, FONTS, prefersReducedMotion } from '../../utils/constants'

interface Particle {
  x: number
  y: number
  vx: number
  vy: number
  targetX: number
  targetY: number
  color: string
  size: number
  opacity: number
  delay: number
}

interface AnimState {
  phase: number
  orbOpacity: number
  orbRadius: number
  orbGlow: number
  particleProgress: number
  convergeProgress: number
}

function generateLetterPositions(
  canvasWidth: number,
  canvasHeight: number
): Array<{ x: number; y: number }> {
  const positions: Array<{ x: number; y: number }> = []
  const letters = ['S', 'E', 'N', 'T', 'R', 'O']
  const totalWidth = 360
  const startX = (canvasWidth - totalWidth) / 2
  const y = canvasHeight / 2

  letters.forEach((_, i) => {
    const cx = startX + i * 60 + 30
    for (let j = 0; j < 8; j++) {
      positions.push({
        x: cx + (Math.random() - 0.5) * 40,
        y: y + (Math.random() - 0.5) * 50,
      })
    }
  })
  return positions
}

interface Props {
  onComplete: () => void
}

export default function OpeningAnimation({ onComplete }: Props) {
  const containerRef = useRef<HTMLDivElement>(null)
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const textRef = useRef<HTMLDivElement>(null)
  const taglineRef = useRef<HTMLParagraphElement>(null)
  const scanLineRef = useRef<HTMLDivElement>(null)
  const particlesRef = useRef<Particle[]>([])
  const animStateRef = useRef<AnimState>({
    phase: 0,
    orbOpacity: 0,
    orbRadius: 4,
    orbGlow: 0,
    particleProgress: 0,
    convergeProgress: 0,
  })
  const rafRef = useRef<number>(0)

  useEffect(() => {
    const reduced = prefersReducedMotion()
    const container = containerRef.current
    const canvas = canvasRef.current
    const textEl = textRef.current
    const taglineEl = taglineRef.current
    const scanLine = scanLineRef.current
    if (!container || !canvas || !textEl || !taglineEl || !scanLine) return

    const ctx = canvas.getContext('2d')
    if (!ctx) return

    const resize = () => {
      canvas.width = window.innerWidth
      canvas.height = window.innerHeight
    }
    resize()
    window.addEventListener('resize', resize)

    if (reduced) {
      gsap.set(textEl, { opacity: 1 })
      gsap.to(container, {
        opacity: 0,
        duration: 0.6,
        delay: 1,
        onComplete,
      })
      return () => {
        window.removeEventListener('resize', resize)
      }
    }

    // Initialize particles
    const cx = canvas.width / 2
    const cy = canvas.height / 2
    const COUNT = 50
    const letterTargets = generateLetterPositions(canvas.width, canvas.height)

    particlesRef.current = Array.from({ length: COUNT }, (_, i) => {
      const angle = (i / COUNT) * Math.PI * 2
      const speed = 3 + Math.random() * 4
      return {
        x: cx,
        y: cy,
        vx: Math.cos(angle) * speed,
        vy: Math.sin(angle) * speed,
        targetX: letterTargets[i % letterTargets.length].x,
        targetY: letterTargets[i % letterTargets.length].y,
        color: Math.random() > 0.5 ? COLORS.accentCyan : COLORS.accentPurple,
        size: 2 + Math.random() * 2,
        opacity: 1,
        delay: Math.random() * 0.3,
      }
    })

    // Draw loop
    const draw = () => {
      if (!ctx || !canvas) return
      ctx.clearRect(0, 0, canvas.width, canvas.height)

      const s = animStateRef.current
      const { phase } = s

      // Draw orb
      if (phase >= 0 && s.orbOpacity > 0) {
        const orbX = canvas.width / 2
        const orbY = canvas.height / 2
        const glow = ctx.createRadialGradient(orbX, orbY, 0, orbX, orbY, s.orbRadius * 8)
        glow.addColorStop(0, `rgba(0, 229, 255, ${s.orbOpacity * 0.6})`)
        glow.addColorStop(1, `rgba(0, 229, 255, 0)`)
        ctx.fillStyle = glow
        ctx.beginPath()
        ctx.arc(orbX, orbY, s.orbRadius * 8, 0, Math.PI * 2)
        ctx.fill()

        ctx.fillStyle = `rgba(0, 229, 255, ${s.orbOpacity})`
        ctx.beginPath()
        ctx.arc(orbX, orbY, s.orbRadius, 0, Math.PI * 2)
        ctx.fill()
      }

      // Draw particles
      if (phase >= 1) {
        const pp = s.particleProgress
        const cp = s.convergeProgress
        particlesRef.current.forEach((p) => {
          const posX = phase < 2
            ? canvas.width / 2 + p.vx * pp * 80
            : p.x + (p.targetX - p.x) * cp
          const posY = phase < 2
            ? canvas.height / 2 + p.vy * pp * 80
            : p.y + (p.targetY - p.y) * cp

          // Trail
          ctx.fillStyle = p.color.replace(')', ', 0.15)').replace('rgb', 'rgba').replace('#00E5FF', 'rgba(0,229,255,0.15)').replace('#7B5BF2', 'rgba(123,91,242,0.15)')
          ctx.beginPath()
          ctx.arc(
            posX - p.vx * 3,
            posY - p.vy * 3,
            p.size * 0.6,
            0,
            Math.PI * 2
          )
          ctx.fill()

          // Core particle
          const hexToRgba = (hex: string, alpha: number) => {
            const r = parseInt(hex.slice(1, 3), 16)
            const g = parseInt(hex.slice(3, 5), 16)
            const b = parseInt(hex.slice(5, 7), 16)
            return `rgba(${r},${g},${b},${alpha})`
          }
          ctx.fillStyle = hexToRgba(p.color, p.opacity)
          ctx.beginPath()
          ctx.arc(posX, posY, p.size, 0, Math.PI * 2)
          ctx.fill()
        })
      }

      rafRef.current = requestAnimationFrame(draw)
    }
    rafRef.current = requestAnimationFrame(draw)

    // GSAP Timeline
    const tl = gsap.timeline()
    const s = animStateRef.current

    // Phase 0: orb fades in (0-1s)
    tl.to(s, {
      orbOpacity: 1,
      orbRadius: 4,
      orbGlow: 1,
      duration: 0.8,
      ease: 'power2.out',
      onStart: () => { s.phase = 0 },
    })

    // Phase 1: explode particles (1-2s)
    tl.to(s, {
      particleProgress: 1,
      orbOpacity: 0,
      duration: 0.8,
      ease: 'power3.out',
      onStart: () => { s.phase = 1 },
    }, '+=0.2')

    // Phase 2: converge to letters (2-3s)
    tl.to(s, {
      convergeProgress: 1,
      duration: 0.9,
      ease: 'power2.inOut',
      onStart: () => {
        s.phase = 2
        particlesRef.current.forEach((p) => {
          p.x = canvas.width / 2 + p.vx * 80
          p.y = canvas.height / 2 + p.vy * 80
        })
      },
    }, '+=0.1')

    // Phase 3: text materializes
    tl.fromTo(
      textEl,
      { opacity: 0, y: 10 },
      { opacity: 1, y: 0, duration: 0.4, ease: 'power2.out' },
      '-=0.3'
    )

    // Phase 3.5: scan line + tagline + fade out
    tl.fromTo(
      scanLine,
      { scaleX: 0 },
      { scaleX: 1, duration: 0.5, ease: 'power2.out' },
      '+=0.15'
    )
    tl.fromTo(
      taglineEl,
      { opacity: 0, y: 20 },
      { opacity: 1, y: 0, duration: 0.45, ease: 'power2.out' },
      '-=0.3'
    )
    tl.to(
      container,
      {
        opacity: 0,
        duration: 0.6,
        ease: 'power2.inOut',
        delay: 0.4,
        onComplete,
      }
    )

    return () => {
      tl.kill()
      cancelAnimationFrame(rafRef.current)
      window.removeEventListener('resize', resize)
    }
  }, [onComplete])

  return (
    <div
      ref={containerRef}
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: 9999,
        background: COLORS.navyDeep,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        flexDirection: 'column',
      }}
    >
      <canvas
        ref={canvasRef}
        aria-hidden="true"
        style={{ position: 'absolute', inset: 0 }}
      />

      {/* SENTRO text — fades in as particles converge */}
      <div
        ref={textRef}
        style={{
          position: 'relative',
          zIndex: 10,
          textAlign: 'center',
          opacity: 0,
          pointerEvents: 'none',
        }}
      >
        <div
          style={{
            fontFamily: FONTS.display,
            fontWeight: 700,
            fontSize: 'clamp(3rem, 6vw, 5rem)',
            letterSpacing: '0.1em',
            color: COLORS.accentCyan,
            textShadow: `0 0 30px ${COLORS.accentCyan}, 0 0 60px rgba(0,229,255,0.3)`,
          }}
        >
          SENTRO
        </div>

        {/* Scan line */}
        <div
          ref={scanLineRef}
          style={{
            height: '1px',
            background: `linear-gradient(90deg, transparent, ${COLORS.accentCyan}, transparent)`,
            transform: 'scaleX(0)',
            transformOrigin: 'center',
            margin: '12px 0',
          }}
        />

        {/* Tagline */}
        <p
          ref={taglineRef}
          style={{
            fontFamily: FONTS.mono,
            fontSize: '0.8rem',
            letterSpacing: '0.25em',
            color: COLORS.cloudMuted,
            textTransform: 'uppercase',
            opacity: 0,
          }}
        >
          Data Security Posture Management
        </p>
      </div>
    </div>
  )
}
