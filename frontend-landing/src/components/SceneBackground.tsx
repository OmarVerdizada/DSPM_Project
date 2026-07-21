import { useEffect, useRef } from 'react'

// ── Types ──────────────────────────────────────────────────────────────────
type Kind = 'db' | 'store' | 'endpoint'

interface Node {
  fx: number; fy: number   // fractional anchor (0–1)
  cx: number; cy: number   // screen coords, updated on resize
  r: number                // base radius px (at 1440px wide)
  depth: number            // 0=far, 1=near — drives parallax weight
  phase: number            // breathing animation offset
  kind: Kind
  links: number[]          // connected node indices (built on resize)
  pulseR: number           // expanding ring radius
  pulseA: number           // ring alpha (0 = no ring)
}

interface Packet {
  a: number; b: number     // from/to node indices
  t: number                // 0 → 1 travel progress
  spd: number              // speed per frame
}

// ── Node definitions ───────────────────────────────────────────────────────
// Format: [fx, fy, r, depth, kind, phase]
// Primary db/store nodes stay outside the hero text zone (see textFade()).
// Tiny endpoint nodes are scattered everywhere but rendered near-invisible
// inside the text zone via textFade().
const NODE_DEFS: [number, number, number, number, Kind, number][] = [
  // Left column — safe zone (fx < 0.18)
  [0.03, 0.15, 5.5, 0.10, 'db',       0.00],
  [0.07, 0.40, 4.5, 0.30, 'db',       1.80],
  [0.04, 0.66, 5.0, 0.60, 'db',       3.20],
  [0.11, 0.84, 3.5, 0.80, 'store',    0.70],
  [0.15, 0.25, 2.5, 0.20, 'endpoint', 2.10],
  [0.17, 0.55, 2.0, 0.50, 'endpoint', 4.40],
  [0.13, 0.76, 2.0, 0.70, 'endpoint', 1.30],

  // Right column — safe zone (fx > 0.82)
  [0.97, 0.20, 5.5, 0.10, 'db',       1.50],
  [0.92, 0.46, 4.5, 0.30, 'db',       3.00],
  [0.96, 0.72, 5.0, 0.60, 'db',       0.40],
  [0.87, 0.88, 3.5, 0.80, 'store',    2.60],
  [0.83, 0.13, 2.5, 0.20, 'endpoint', 1.10],
  [0.80, 0.37, 2.0, 0.40, 'endpoint', 3.50],
  [0.84, 0.62, 2.0, 0.60, 'endpoint', 0.30],

  // Bottom band — safe zone (fy > 0.72)
  [0.27, 0.77, 4.5, 0.80, 'db',       2.20],
  [0.40, 0.84, 3.0, 0.90, 'store',    0.60],
  [0.50, 0.80, 5.5, 0.70, 'db',       1.40],
  [0.62, 0.85, 3.0, 0.90, 'store',    3.80],
  [0.74, 0.75, 4.5, 0.80, 'db',       0.90],

  // Top strip — safe zone (fy < 0.08)
  [0.30, 0.03, 2.5, 0.00, 'endpoint', 4.00],
  [0.50, 0.05, 3.0, 0.00, 'store',    1.70],
  [0.70, 0.02, 2.5, 0.00, 'endpoint', 2.90],

  // Interior — tiny nodes, rendered at ~18% opacity in text zone
  [0.34, 0.22, 1.5, 0.20, 'endpoint', 1.30],
  [0.46, 0.14, 1.5, 0.10, 'endpoint', 3.10],
  [0.57, 0.18, 1.5, 0.10, 'endpoint', 0.20],
  [0.68, 0.31, 1.5, 0.30, 'endpoint', 2.70],
  [0.37, 0.46, 1.5, 0.40, 'endpoint', 4.50],
  [0.63, 0.50, 1.5, 0.40, 'endpoint', 1.60],
  [0.50, 0.58, 1.5, 0.50, 'endpoint', 3.40],
  [0.29, 0.63, 1.5, 0.60, 'endpoint', 0.50],
  [0.71, 0.61, 1.5, 0.50, 'endpoint', 2.00],
  [0.43, 0.34, 1.2, 0.30, 'endpoint', 3.80],
  [0.58, 0.38, 1.2, 0.30, 'endpoint', 0.80],
]

// ── Helpers ────────────────────────────────────────────────────────────────

/** Opacity multiplier for elements in the hero text reading zone. */
function textFade(fx: number, fy: number): number {
  const inX = fx > 0.18 && fx < 0.82
  const inY = fy > 0.06 && fy < 0.70
  return inX && inY ? 0.18 : 1.0
}

/** Lerp between a and b by t */
function lerp(a: number, b: number, t: number) { return a + (b - a) * t }

// ── Component ──────────────────────────────────────────────────────────────
export default function SceneBackground() {
  const canvasRef = useRef<HTMLCanvasElement>(null)

  useEffect(() => {
    const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches
    const rawCanvas = canvasRef.current
    if (!rawCanvas) return
    const canvas: HTMLCanvasElement = rawCanvas
    const rawCtx = rawCanvas.getContext('2d')
    if (!rawCtx) return
    const ctx: CanvasRenderingContext2D = rawCtx

    let W = 0, H = 0, raf = 0, tick = 0, scrollY = 0
    let pulseClock = 0

    // ── Build scene ─────────────────────────────────────────────────────────
    const nodes: Node[] = NODE_DEFS.map(([fx, fy, r, depth, kind, phase]) => ({
      fx, fy, r, depth, kind, phase,
      cx: 0, cy: 0, links: [], pulseR: 0, pulseA: 0,
    }))
    // Pre-sort far→near; depth never changes so this is stable
    const drawOrder = [...nodes].sort((a, b) => a.depth - b.depth)

    // Packets — pre-allocated, filled after links are built
    const MAX_PACKETS = 18
    const packets: Packet[] = []

    function buildLinks() {
      // Reset links
      nodes.forEach(n => { n.links = [] })

      // Connect in screen space within a fraction of viewport width
      const maxDist = W * 0.30
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const dx = nodes[i].cx - nodes[j].cx
          const dy = nodes[i].cy - nodes[j].cy
          if (dx * dx + dy * dy < maxDist * maxDist) {
            nodes[i].links.push(j)
            nodes[j].links.push(i)
          }
        }
      }
    }

    function buildPackets() {
      packets.length = 0
      // Gather unique directed edges
      const edges: [number, number][] = []
      nodes.forEach((n, i) => {
        n.links.forEach(j => { if (i < j) edges.push([i, j]) })
      })
      if (edges.length === 0) return

      const count = Math.min(MAX_PACKETS, edges.length)
      const shuffled = [...edges].sort(() => Math.random() - 0.5)
      for (let k = 0; k < count; k++) {
        const [a, b] = shuffled[k % shuffled.length]
        packets.push({
          a, b,
          t: Math.random(),
          spd: 0.0018 + Math.random() * 0.0022,
        })
      }
    }

    // ── Resize ──────────────────────────────────────────────────────────────
    function resize() {
      W = canvas.offsetWidth  || window.innerWidth
      H = canvas.offsetHeight || window.innerHeight
      canvas.width  = W
      canvas.height = H

      const scale = W / 1440
      nodes.forEach((n, i) => {
        n.cx = n.fx * W
        n.cy = n.fy * H
        n.r  = NODE_DEFS[i][2] * Math.min(scale, 1.2)
      })

      buildLinks()
      buildPackets()
    }

    // ── Per-node parallax Y offset ───────────────────────────────────────────
    // Nodes at depth=0 (far) move little; depth=1 (near) move more.
    function parallaxY(n: Node): number {
      if (reduced) return 0
      const sy = Math.min(scrollY, 1000)
      return sy * lerp(0.006, 0.028, n.depth)
    }

    // ── Draw: subtle background grid ─────────────────────────────────────────
    function drawGrid() {
      const step = 64
      ctx.strokeStyle = 'rgba(37,99,235,0.032)'
      ctx.lineWidth   = 0.5
      ctx.setLineDash([])
      for (let x = 0; x <= W; x += step) {
        ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, H); ctx.stroke()
      }
      for (let y = 0; y <= H; y += step) {
        ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(W, y); ctx.stroke()
      }
    }

    // ── Draw: connection lines ────────────────────────────────────────────────
    function drawLinks() {
      ctx.setLineDash([])
      for (let i = 0; i < nodes.length; i++) {
        const a = nodes[i]
        const ay = a.cy + parallaxY(a)

        for (const j of a.links) {
          if (j <= i) continue
          const b = nodes[j]
          const by = b.cy + parallaxY(b)

          // Fade lines that cross the text zone
          const fadeA = textFade(a.fx, a.fy)
          const fadeB = textFade(b.fx, b.fy)
          const fade  = (fadeA + fadeB) * 0.5
          if (fade < 0.01) continue

          // Distance-based alpha (closer nodes = slightly brighter line)
          const dist  = Math.hypot(a.cx - b.cx, a.cy - b.cy)
          const t     = 1 - dist / (W * 0.30)
          const alpha = lerp(0.06, 0.16, t) * fade

          const lg = ctx.createLinearGradient(a.cx, ay, b.cx, by)
          lg.addColorStop(0,   `rgba(37,99,235,${alpha})`)
          lg.addColorStop(0.5, `rgba(56,189,248,${alpha * 1.5})`)
          lg.addColorStop(1,   `rgba(37,99,235,${alpha})`)
          ctx.strokeStyle = lg
          ctx.lineWidth   = 0.55
          ctx.beginPath(); ctx.moveTo(a.cx, ay); ctx.lineTo(b.cx, by); ctx.stroke()
        }
      }
    }

    // ── Draw: nodes ───────────────────────────────────────────────────────────
    function drawNode(n: Node) {
      const py = parallaxY(n)
      const x  = n.cx
      const y  = n.cy + py

      const breathe = reduced ? 1.0 : 1.0 + 0.12 * Math.sin(tick * 0.018 + n.phase)
      const rr      = n.r * breathe
      const fade    = textFade(n.fx, n.fy)
      if (fade < 0.01) return

      // Layer 1 — wide ambient bloom (db nodes only, for weight)
      if (n.kind === 'db') {
        const bloom = rr * 9
        const g0 = ctx.createRadialGradient(x, y, 0, x, y, bloom)
        g0.addColorStop(0, `rgba(37,99,235,${0.15 * fade})`)
        g0.addColorStop(1, `rgba(37,99,235,0)`)
        ctx.fillStyle = g0
        ctx.beginPath(); ctx.arc(x, y, bloom, 0, Math.PI * 2); ctx.fill()
      }

      // Layer 2 — mid glow (all nodes)
      const midR = rr * (n.kind === 'db' ? 5 : n.kind === 'store' ? 4 : 3)
      const g1 = ctx.createRadialGradient(x, y, 0, x, y, midR)
      g1.addColorStop(0, `rgba(56,189,248,${0.28 * fade})`)
      g1.addColorStop(1, `rgba(56,189,248,0)`)
      ctx.fillStyle = g1
      ctx.beginPath(); ctx.arc(x, y, midR, 0, Math.PI * 2); ctx.fill()

      // Layer 3 — core dot
      if (n.kind === 'db') {
        // Outer ring
        ctx.strokeStyle = `rgba(56,189,248,${0.75 * fade})`
        ctx.lineWidth   = 1.2
        ctx.beginPath(); ctx.arc(x, y, rr, 0, Math.PI * 2); ctx.stroke()
        // Inner bright centre
        ctx.fillStyle = `rgba(215,240,255,${0.92 * fade})`
        ctx.beginPath(); ctx.arc(x, y, rr * 0.42, 0, Math.PI * 2); ctx.fill()
      } else if (n.kind === 'store') {
        ctx.fillStyle = `rgba(56,189,248,${0.65 * fade})`
        ctx.beginPath(); ctx.arc(x, y, rr, 0, Math.PI * 2); ctx.fill()
        ctx.fillStyle = `rgba(200,235,255,${0.85 * fade})`
        ctx.beginPath(); ctx.arc(x, y, rr * 0.38, 0, Math.PI * 2); ctx.fill()
      } else {
        ctx.fillStyle = `rgba(56,189,248,${0.50 * fade})`
        ctx.beginPath(); ctx.arc(x, y, rr, 0, Math.PI * 2); ctx.fill()
      }
    }

    // ── Draw: packets ─────────────────────────────────────────────────────────
    function drawPackets() {
      if (reduced) return
      packets.forEach(p => {
        const na = nodes[p.a], nb = nodes[p.b]
        const ay = na.cy + parallaxY(na)
        const by = nb.cy + parallaxY(nb)

        const x = lerp(na.cx, nb.cx, p.t)
        const y = lerp(ay,    by,    p.t)

        // Fade based on both endpoints' text-zone factor
        const fade = Math.max(0.22, (textFade(na.fx, na.fy) + textFade(nb.fx, nb.fy)) * 0.5)

        // Halo
        const g = ctx.createRadialGradient(x, y, 0, x, y, 7)
        g.addColorStop(0, `rgba(56,189,248,${0.72 * fade})`)
        g.addColorStop(1, `rgba(56,189,248,0)`)
        ctx.fillStyle = g
        ctx.beginPath(); ctx.arc(x, y, 7, 0, Math.PI * 2); ctx.fill()

        // Core
        ctx.fillStyle = `rgba(210,245,255,${0.95 * fade})`
        ctx.beginPath(); ctx.arc(x, y, 1.6, 0, Math.PI * 2); ctx.fill()

        // Advance — bounce back on db nodes, wrap on others
        p.t += p.spd
        if (p.t >= 1.0) {
          // Swap direction occasionally to make it feel organic
          if (Math.random() < 0.4) { const tmp = p.a; p.a = p.b; p.b = tmp }
          p.t = 0
        }
      })
    }

    // ── Draw: pulse rings (radar pings from db nodes) ─────────────────────────
    function updatePulses() {
      if (reduced) return

      pulseClock++
      // Fire a ring every ~110 ticks (~1.8 s at 60 fps) from a random db node
      if (pulseClock % 110 === 0) {
        const dbs = nodes.filter(n => n.kind === 'db' && n.pulseA <= 0)
        if (dbs.length > 0) {
          const n   = dbs[Math.floor(Math.random() * dbs.length)]
          n.pulseR  = n.r * 1.2
          n.pulseA  = 0.62
        }
      }

      nodes.forEach(n => {
        if (n.pulseA <= 0) return
        const py = parallaxY(n)
        const fade = textFade(n.fx, n.fy)

        ctx.strokeStyle = `rgba(56,189,248,${n.pulseA * fade})`
        ctx.lineWidth   = 0.9
        ctx.beginPath()
        ctx.arc(n.cx, n.cy + py, n.pulseR, 0, Math.PI * 2)
        ctx.stroke()

        n.pulseR += 1.3
        n.pulseA -= 0.0085
        if (n.pulseA < 0) { n.pulseA = 0; n.pulseR = 0 }
      })
    }

    // ── Render loop ────────────────────────────────────────────────────────────
    function frame() {
      ctx.fillStyle = '#060914'
      ctx.fillRect(0, 0, W, H)
      tick++

      drawGrid()
      drawLinks()
      drawPackets()
      updatePulses()

      // Nodes — far to near (pre-sorted, no per-frame allocation)
      drawOrder.forEach(drawNode)

      raf = requestAnimationFrame(frame)
    }

    // ── Bootstrap ──────────────────────────────────────────────────────────────
    const onScroll = () => { scrollY = window.scrollY }
    window.addEventListener('scroll', onScroll, { passive: true })

    const ro = new ResizeObserver(resize)
    ro.observe(canvas)
    resize()
    raf = requestAnimationFrame(frame)

    return () => {
      cancelAnimationFrame(raf)
      ro.disconnect()
      window.removeEventListener('scroll', onScroll)
    }
  }, [])

  return (
    <canvas
      ref={canvasRef}
      aria-hidden="true"
      style={{
        position:      'fixed',
        inset:         0,
        width:         '100%',
        height:        '100%',
        pointerEvents: 'none',
        zIndex:        0,
      }}
    />
  )
}
