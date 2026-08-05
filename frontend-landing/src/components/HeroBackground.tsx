import { useEffect, useRef } from 'react'

// ── Types ─────────────────────────────────────────────────────────────────
type Pt = [number, number]

interface IsoObj {
  fx: number; fy: number           // fractional viewport position (0–1)
  u:  number; d: number            // iso half-width, depth (set on resize)
  phase: number; amp: number       // float animation
  spd:   number
  kind: 'tower' | 'flat' | 'node'
  cx: number; cy: number           // computed screen coords
}

// ── Pure drawing helpers (take ctx as arg → no closure null issue) ────────

function quad(
  ctx: CanvasRenderingContext2D,
  pts: Pt[],
  fill: string,
  stroke: string,
  lw: number,
) {
  ctx.beginPath()
  ctx.moveTo(pts[0][0], pts[0][1])
  for (let i = 1; i < pts.length; i++) ctx.lineTo(pts[i][0], pts[i][1])
  ctx.closePath()
  ctx.fillStyle   = fill;   ctx.fill()
  ctx.strokeStyle = stroke; ctx.lineWidth = lw; ctx.stroke()
}

/**
 * Isometric box with top vertex at (cx, cy).
 *
 * Rhombus (top face):  t=(cx,cy)  r=(cx+u, cy+u·0.5)  b=(cx, cy+u)  l=(cx-u, cy+u·0.5)
 * Right depth face:    b → r → rb → bb
 * Left depth face:     l → b → bb → lb
 */
function isoBox(
  ctx:       CanvasRenderingContext2D,
  cx:        number,
  cy:        number,
  u:         number,
  d:         number,
  edgeA:     number,   // edge (cyan) alpha
  fillA:     number,   // fill base alpha multiplier
  shelves:   number,   // horizontal dividers on depth faces
) {
  const t:  Pt = [cx,     cy]
  const r:  Pt = [cx + u, cy + u * 0.5]
  const b:  Pt = [cx,     cy + u]
  const l:  Pt = [cx - u, cy + u * 0.5]
  const rb: Pt = [cx + u, cy + u * 0.5 + d]
  const bb: Pt = [cx,     cy + u + d]
  const lb: Pt = [cx - u, cy + u * 0.5 + d]

  const e = `rgba(56,189,248,${edgeA})`

  // Draw back-to-front: right face, left face, top face
  quad(ctx, [b, r, rb, bb], `rgba(10,35,110,${fillA * 0.55})`, e, 0.6)
  quad(ctx, [l, b, bb, lb], `rgba(4, 13, 50, ${fillA * 0.72})`, e, 0.6)
  quad(ctx, [t, r, b,  l],  `rgba(18,58,180,${fillA * 0.28})`, e, 0.6)

  // Shelf / disk-platter lines on both depth faces
  if (shelves > 0) {
    ctx.strokeStyle = `rgba(56,189,248,${edgeA * 0.50})`
    ctx.lineWidth = 0.45
    for (let i = 1; i <= shelves; i++) {
      const s = i / (shelves + 1)
      // right face shelf
      ctx.beginPath()
      ctx.moveTo(b[0] + (bb[0] - b[0]) * s, b[1] + (bb[1] - b[1]) * s)
      ctx.lineTo(r[0] + (rb[0] - r[0]) * s, r[1] + (rb[1] - r[1]) * s)
      ctx.stroke()
      // left face shelf
      ctx.beginPath()
      ctx.moveTo(b[0] + (bb[0] - b[0]) * s, b[1] + (bb[1] - b[1]) * s)
      ctx.lineTo(l[0] + (lb[0] - l[0]) * s, l[1] + (lb[1] - l[1]) * s)
      ctx.stroke()
    }
  }
}

/**
 * Grid lines on the top rhombus face — gives a "data tile / file system" look.
 *
 * Row lines run parallel to t→r.  Column lines run parallel to t→l.
 * At parameter s ∈ (0,1):
 *   row endpoints:    lerp(t,l,s)  →  lerp(r,b,s)
 *   column endpoints: lerp(t,r,s)  →  lerp(l,b,s)
 */
function topGrid(
  ctx:   CanvasRenderingContext2D,
  cx:    number,
  cy:    number,
  u:     number,
  rows:  number,
  cols:  number,
  alpha: number,
) {
  ctx.strokeStyle = `rgba(56,189,248,${alpha})`
  ctx.lineWidth   = 0.35
  for (let i = 1; i < rows; i++) {
    const s = i / rows
    ctx.beginPath()
    ctx.moveTo(cx - u * s,       cy + u * 0.5 * s)
    ctx.lineTo(cx + u - u * s,   cy + u * 0.5 + u * 0.5 * s)
    ctx.stroke()
  }
  for (let i = 1; i < cols; i++) {
    const s = i / cols
    ctx.beginPath()
    ctx.moveTo(cx + u * s,       cy + u * 0.5 * s)
    ctx.lineTo(cx - u + u * s,   cy + u * 0.5 + u * 0.5 * s)
    ctx.stroke()
  }
}

// ── Component ─────────────────────────────────────────────────────────────
export default function HeroBackground() {
  const canvasRef = useRef<HTMLCanvasElement>(null)

  useEffect(() => {
    const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches
    const maybe   = canvasRef.current
    if (!maybe) return
    const canvas: HTMLCanvasElement          = maybe
    const rawCtx                             = canvas.getContext('2d')
    if (!rawCtx) return
    const ctx: CanvasRenderingContext2D      = rawCtx

    let W = 0, H = 0, raf = 0, tick = 0

    // ── Scene layout ─────────────────────────────────────────────────────
    // Objects are kept away from the hero text zone (centre 50% × top 70%).
    // They live in the lower band and side columns.
    const SCENE: IsoObj[] = [
      // Left column
      { fx: 0.05,  fy: 0.46, u: 0, d: 0, phase: 0.0, amp: 10, spd: 0.0070, kind: 'tower', cx: 0, cy: 0 },
      { fx: 0.17,  fy: 0.68, u: 0, d: 0, phase: 1.5, amp:  7, spd: 0.0055, kind: 'flat',  cx: 0, cy: 0 },
      { fx: 0.08,  fy: 0.83, u: 0, d: 0, phase: 2.9, amp:  5, spd: 0.0090, kind: 'node',  cx: 0, cy: 0 },
      // Bottom centre (below text)
      { fx: 0.37,  fy: 0.82, u: 0, d: 0, phase: 0.6, amp:  8, spd: 0.0075, kind: 'flat',  cx: 0, cy: 0 },
      { fx: 0.56,  fy: 0.87, u: 0, d: 0, phase: 3.3, amp:  5, spd: 0.0100, kind: 'node',  cx: 0, cy: 0 },
      // Right column
      { fx: 0.79,  fy: 0.47, u: 0, d: 0, phase: 1.8, amp:  9, spd: 0.0070, kind: 'tower', cx: 0, cy: 0 },
      { fx: 0.88,  fy: 0.68, u: 0, d: 0, phase: 0.4, amp:  7, spd: 0.0080, kind: 'flat',  cx: 0, cy: 0 },
      { fx: 0.93,  fy: 0.56, u: 0, d: 0, phase: 2.2, amp:  4, spd: 0.0110, kind: 'node',  cx: 0, cy: 0 },
    ]

    // Scan sweeps sequentially across objects
    let scanIdx = 0
    let scanT   = -0.2   // progress from -0.2 → 1.2

    function layout() {
      // Scale object sizes relative to 1440px baseline; cap at 1× on large screens
      const s = Math.min(W / 1440, 1)
      SCENE.forEach(o => {
        o.cx = o.fx * W
        o.cy = o.fy * H
        if      (o.kind === 'tower') { o.u = 42 * s; o.d = 80 * s }
        else if (o.kind === 'flat')  { o.u = 60 * s; o.d = 14 * s }
        else                         { o.u = 25 * s; o.d = 25 * s }
      })
    }

    function resize() {
      W = canvas.offsetWidth  || window.innerWidth
      H = canvas.offsetHeight || window.innerHeight
      canvas.width  = W
      canvas.height = H
      layout()
    }

    // ── Per-object draw ───────────────────────────────────────────────────
    function drawObject(o: IsoObj, floatY: number, scanning: boolean, sp: number) {
      const cy = o.cy + floatY

      // Soft ambient glow pooling beneath the object
      const glowCx = o.cx
      const glowCy = cy + o.u + o.d * 0.55
      const glow   = ctx.createRadialGradient(glowCx, glowCy, 0, glowCx, glowCy, o.u * 2)
      glow.addColorStop(0, 'rgba(37,99,235,0.09)')
      glow.addColorStop(1, 'rgba(37,99,235,0)')
      ctx.fillStyle = glow
      ctx.beginPath()
      ctx.ellipse(glowCx, glowCy, o.u * 2, o.u * 0.6, 0, 0, Math.PI * 2)
      ctx.fill()

      // The isometric box
      const shelves = o.kind === 'tower' ? 3 : 0
      isoBox(ctx, o.cx, cy, o.u, o.d, 0.20, 1.0, shelves)

      // Flat tiles: data-grid on top face
      if (o.kind === 'flat') {
        topGrid(ctx, o.cx, cy, o.u, 3, 4, 0.08)
      }

      // Nodes: tiny glowing data dots on top face
      if (o.kind === 'node') {
        ctx.fillStyle = 'rgba(56,189,248,0.55)'
        const dots: Pt[] = [
          [o.cx - o.u * 0.22, cy + o.u * 0.28],
          [o.cx,               cy + o.u * 0.58],
          [o.cx + o.u * 0.22, cy + o.u * 0.28],
        ]
        dots.forEach(([dx, dy]) => {
          ctx.beginPath(); ctx.arc(dx, dy, 1.6, 0, Math.PI * 2); ctx.fill()
        })
      }

      // Scan sweep — a slim glowing line that slides top-to-bottom across the object
      if (scanning && !reduced) {
        const clamped = Math.max(0, Math.min(1, sp))
        // Width of the scan line mirrors the rhombus: widest at mid-point
        const hw    = o.u * Math.max(0.1, 1 - Math.abs(clamped - 0.5) * 1.6)
        const lineY = cy + o.u * clamped
        const sg    = ctx.createLinearGradient(o.cx - hw, 0, o.cx + hw, 0)
        sg.addColorStop(0,   'rgba(56,189,248,0)')
        sg.addColorStop(0.2, 'rgba(56,189,248,0.55)')
        sg.addColorStop(0.8, 'rgba(56,189,248,0.55)')
        sg.addColorStop(1,   'rgba(56,189,248,0)')
        ctx.fillStyle = sg
        ctx.fillRect(o.cx - hw, lineY - 1, hw * 2, 2)
      }
    }

    // ── Main render loop ──────────────────────────────────────────────────
    function frame() {
      ctx.clearRect(0, 0, W, H)
      tick++

      // Advance scan
      if (!reduced) {
        scanT += 0.005
        if (scanT > 1.2) {
          scanT   = -0.2
          scanIdx = (scanIdx + 1) % SCENE.length
        }
      }

      // Dashed connection lines between nearby objects
      ctx.save()
      ctx.setLineDash([2, 9])
      ctx.lineWidth = 0.5
      for (let i = 0; i < SCENE.length; i++) {
        for (let j = i + 1; j < SCENE.length; j++) {
          const a = SCENE[i], b = SCENE[j]
          const dist = Math.hypot(a.cx - b.cx, a.cy - b.cy)
          if (dist < W * 0.40) {
            const alpha = (1 - dist / (W * 0.40)) * 0.045
            ctx.strokeStyle = `rgba(37,99,235,${alpha})`
            ctx.beginPath()
            // Connect from the bottom-ish centre of each object
            ctx.moveTo(a.cx, a.cy + a.u * 0.8)
            ctx.lineTo(b.cx, b.cy + b.u * 0.8)
            ctx.stroke()
          }
        }
      }
      ctx.restore()

      // Draw objects back-to-front (lower cy = further back in iso space)
      ;[...SCENE]
        .sort((a, b) => a.cy - b.cy)
        .forEach(o => {
          const fy      = reduced ? 0 : Math.sin(tick * o.spd + o.phase) * o.amp
          const active  = SCENE[scanIdx] === o
          drawObject(o, fy, active, scanT)
        })

      raf = requestAnimationFrame(frame)
    }

    const ro = new ResizeObserver(resize)
    ro.observe(canvas)
    resize()
    raf = requestAnimationFrame(frame)

    return () => {
      cancelAnimationFrame(raf)
      ro.disconnect()
    }
  }, [])

  return (
    <canvas
      ref={canvasRef}
      aria-hidden="true"
      style={{
        position: 'absolute',
        inset: 0,
        width: '100%',
        height: '100%',
        pointerEvents: 'none',
        opacity: 0.82,
        zIndex: 0,
      }}
    />
  )
}
