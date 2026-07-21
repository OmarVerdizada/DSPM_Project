import { useState, useEffect, useRef } from 'react'
import { ScrollTrigger } from 'gsap/ScrollTrigger'

export function useScrollProgress(
  triggerRef: React.RefObject<HTMLElement | null>,
  options?: {
    start?: string
    end?: string
    scrub?: boolean | number
  }
): number {
  const [progress, setProgress] = useState(0)
  const stRef = useRef<ScrollTrigger | null>(null)

  useEffect(() => {
    if (!triggerRef.current) return

    stRef.current = ScrollTrigger.create({
      trigger: triggerRef.current,
      start: options?.start ?? 'top top',
      end: options?.end ?? 'bottom bottom',
      scrub: options?.scrub ?? true,
      onUpdate: (self) => setProgress(self.progress),
    })

    return () => {
      stRef.current?.kill()
    }
  }, [triggerRef, options?.start, options?.end, options?.scrub])

  return progress
}
