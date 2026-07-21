import { useEffect, useRef } from 'react'
import Lenis from 'lenis'
import { gsap } from 'gsap'
import { ScrollTrigger } from 'gsap/ScrollTrigger'

gsap.registerPlugin(ScrollTrigger)

export function useSmoothScroll(): React.RefObject<Lenis | null> {
  const lenisRef = useRef<Lenis | null>(null)

  useEffect(() => {
    const lenis = new Lenis({ lerp: 0.08 })
    lenisRef.current = lenis

    lenis.on('scroll', ScrollTrigger.update)

    const rafFn = (time: number) => lenis.raf(time * 1000)
    gsap.ticker.add(rafFn)
    gsap.ticker.lagSmoothing(0)

    return () => {
      gsap.ticker.remove(rafFn)
      lenis.destroy()
      lenisRef.current = null
    }
  }, [])

  return lenisRef
}
