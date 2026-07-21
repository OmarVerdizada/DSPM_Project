import { useState, useEffect, useRef, useCallback } from 'react'

interface MousePosition {
  x: number
  y: number
}

export function useMousePosition(): MousePosition {
  const [position, setPosition] = useState<MousePosition>({ x: 0, y: 0 })
  const rawRef = useRef<MousePosition>({ x: 0, y: 0 })
  const rafRef = useRef<number>(0)
  const scheduledRef = useRef(false)

  const flush = useCallback(() => {
    setPosition({ ...rawRef.current })
    scheduledRef.current = false
  }, [])

  useEffect(() => {
    const onMove = (e: MouseEvent) => {
      rawRef.current = { x: e.clientX, y: e.clientY }
      if (!scheduledRef.current) {
        scheduledRef.current = true
        rafRef.current = requestAnimationFrame(flush)
      }
    }

    window.addEventListener('mousemove', onMove, { passive: true })
    return () => {
      window.removeEventListener('mousemove', onMove)
      cancelAnimationFrame(rafRef.current)
    }
  }, [flush])

  return position
}

export function useMousePositionRef(): React.RefObject<MousePosition> {
  const ref = useRef<MousePosition>({ x: 0, y: 0 })

  useEffect(() => {
    const onMove = (e: MouseEvent) => {
      ref.current = { x: e.clientX, y: e.clientY }
    }
    window.addEventListener('mousemove', onMove, { passive: true })
    return () => window.removeEventListener('mousemove', onMove)
  }, [])

  return ref
}
