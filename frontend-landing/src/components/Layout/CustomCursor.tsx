import { useEffect, useRef } from 'react'
import { lerp } from '../../utils/lerp'
import { COLORS, BREAKPOINTS } from '../../utils/constants'

export default function CustomCursor() {
  const ringRef = useRef<HTMLDivElement>(null)
  const dotRef = useRef<HTMLDivElement>(null)
  const posRef = useRef({ x: 0, y: 0 })
  const ringPosRef = useRef({ x: 0, y: 0 })
  const isHoveringRef = useRef(false)
  const isClickingRef = useRef(false)

  useEffect(() => {
    if (window.innerWidth < BREAKPOINTS.mobile) return

    const ring = ringRef.current
    const dot = dotRef.current
    if (!ring || !dot) return

    let rafId: number

    const onMove = (e: MouseEvent) => {
      posRef.current = { x: e.clientX, y: e.clientY }
    }

    const onEnterInteractive = () => { isHoveringRef.current = true }
    const onLeaveInteractive = () => { isHoveringRef.current = false }

    const onMouseDown = () => {
      isClickingRef.current = true
      if (ring) ring.style.transform = `translate(-50%, -50%) scale(0.8)`
    }
    const onMouseUp = () => {
      isClickingRef.current = false
      if (ring) ring.style.transform = `translate(-50%, -50%) scale(1)`
    }

    const updateInteractiveTargets = () => {
      document.querySelectorAll('a, button, [data-cursor-hover]').forEach((el) => {
        el.addEventListener('mouseenter', onEnterInteractive)
        el.addEventListener('mouseleave', onLeaveInteractive)
      })
    }
    updateInteractiveTargets()

    const observer = new MutationObserver(updateInteractiveTargets)
    observer.observe(document.body, { childList: true, subtree: true })

    window.addEventListener('mousemove', onMove, { passive: true })
    window.addEventListener('mousedown', onMouseDown)
    window.addEventListener('mouseup', onMouseUp)

    const animate = () => {
      const { x, y } = posRef.current
      ringPosRef.current.x = lerp(ringPosRef.current.x, x, 0.15)
      ringPosRef.current.y = lerp(ringPosRef.current.y, y, 0.15)

      if (dot) {
        dot.style.left = `${x}px`
        dot.style.top = `${y}px`
      }

      if (ring) {
        ring.style.left = `${ringPosRef.current.x}px`
        ring.style.top = `${ringPosRef.current.y}px`

        if (isHoveringRef.current) {
          ring.style.width = '40px'
          ring.style.height = '40px'
          ring.style.borderColor = COLORS.accentPurple
          ring.style.opacity = '0.8'
        } else {
          ring.style.width = '16px'
          ring.style.height = '16px'
          ring.style.borderColor = COLORS.accentCyan
          ring.style.opacity = '0.5'
        }
      }

      rafId = requestAnimationFrame(animate)
    }
    rafId = requestAnimationFrame(animate)

    return () => {
      cancelAnimationFrame(rafId)
      window.removeEventListener('mousemove', onMove)
      window.removeEventListener('mousedown', onMouseDown)
      window.removeEventListener('mouseup', onMouseUp)
      observer.disconnect()
      document.querySelectorAll('a, button, [data-cursor-hover]').forEach((el) => {
        el.removeEventListener('mouseenter', onEnterInteractive)
        el.removeEventListener('mouseleave', onLeaveInteractive)
      })
    }
  }, [])

  return (
    <>
      <div
        ref={ringRef}
        aria-hidden="true"
        style={{
          position: 'fixed',
          width: '16px',
          height: '16px',
          border: `1.5px solid ${COLORS.accentCyan}`,
          borderRadius: '50%',
          pointerEvents: 'none',
          zIndex: 99999,
          transform: 'translate(-50%, -50%)',
          transition: 'width 0.2s ease, height 0.2s ease, border-color 0.2s ease, opacity 0.2s ease',
          opacity: 0.5,
          willChange: 'left, top',
          mixBlendMode: 'normal',
        }}
      />
      <div
        ref={dotRef}
        aria-hidden="true"
        style={{
          position: 'fixed',
          width: '3px',
          height: '3px',
          background: COLORS.cloudWhite,
          borderRadius: '50%',
          pointerEvents: 'none',
          zIndex: 100000,
          transform: 'translate(-50%, -50%)',
          willChange: 'left, top',
        }}
      />
    </>
  )
}
