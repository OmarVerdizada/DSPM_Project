import { useState, useEffect, useRef, useCallback } from 'react'
import { gsap } from 'gsap'
import { ScrollTrigger } from 'gsap/ScrollTrigger'
import Lenis from 'lenis'

import CustomCursor from './components/Layout/CustomCursor'
import Navbar from './components/Layout/Navbar'
import Intro from './components/Intro/Intro'
import DataFlowSection from './components/DataFlow/DataFlowSection'
import FeaturesGrid from './components/Features/FeaturesGrid'
import LiveDashboard from './components/Dashboard/LiveDashboard'
import HorizontalSteps from './components/HowItWorks/HorizontalSteps'
import CTASection from './components/CTA/CTASection'
import { COLORS } from './utils/constants'
import { lerp } from './utils/lerp'

gsap.registerPlugin(ScrollTrigger)

const hasSeenIntro = (): boolean => {
  try {
    return sessionStorage.getItem('sentro-intro-seen') === 'true'
  } catch {
    return false
  }
}

export default function App() {
  const seenBefore = useRef(hasSeenIntro())
  const [introGone, setIntroGone] = useState(() => seenBefore.current)
  const [coverDone, setCoverDone] = useState(() => seenBefore.current)
  const [coverFading, setCoverFading] = useState(false)

  // Global mouse spotlight state
  const spotlightRef = useRef<HTMLDivElement>(null)
  const mouseRef = useRef({ x: 0, y: 0 })
  const spotlightPosRef = useRef({ x: 0, y: 0 })
  const rafRef = useRef<number>(0)

  const handleIntroComplete = useCallback(() => {
    try {
      sessionStorage.setItem('sentro-intro-seen', 'true')
    } catch {}

    setIntroGone(true)

    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        setCoverFading(true)
        window.dispatchEvent(new Event('sentro-hero-reveal'))
        setTimeout(() => setCoverDone(true), 900)
      })
    })
  }, [])

  // Lenis smooth scroll
  useEffect(() => {
    if (!introGone) return

    const lenis = new Lenis({ lerp: 0.1 })

    lenis.on('scroll', ScrollTrigger.update)

    const rafFn = (time: number) => lenis.raf(time * 1000)
    gsap.ticker.add(rafFn)
    gsap.ticker.lagSmoothing(0)

    return () => {
      gsap.ticker.remove(rafFn)
      lenis.destroy()
    }
  }, [introGone])

  // Global mouse tracking for spotlight
  useEffect(() => {
    const onMove = (e: MouseEvent) => {
      mouseRef.current = { x: e.clientX, y: e.clientY }
    }
    window.addEventListener('mousemove', onMove, { passive: true })

    const animateSpotlight = () => {
      spotlightPosRef.current.x = lerp(spotlightPosRef.current.x, mouseRef.current.x, 0.08)
      spotlightPosRef.current.y = lerp(spotlightPosRef.current.y, mouseRef.current.y, 0.08)

      if (spotlightRef.current) {
        const { x, y } = spotlightPosRef.current
        spotlightRef.current.style.background = `radial-gradient(400px circle at ${x}px ${y}px, rgba(0,229,255,0.04), transparent 65%)`
      }

      rafRef.current = requestAnimationFrame(animateSpotlight)
    }
    rafRef.current = requestAnimationFrame(animateSpotlight)

    return () => {
      window.removeEventListener('mousemove', onMove)
      cancelAnimationFrame(rafRef.current)
    }
  }, [])

  return (
    <>
      {/* Custom cursor */}
      <CustomCursor />

      {/* Global mouse spotlight */}
      <div
        ref={spotlightRef}
        aria-hidden="true"
        style={{
          position: 'fixed',
          inset: 0,
          pointerEvents: 'none',
          zIndex: 0,
        }}
      />

      {/* Opening animation (first visit only) */}
      {!introGone && <Intro onComplete={handleIntroComplete} />}

      {/* Bridge overlay */}
      {!coverDone && (
        <div
          aria-hidden="true"
          style={{
            position: 'fixed',
            inset: 0,
            background: COLORS.navyDeep,
            zIndex: 9998,
            pointerEvents: 'none',
            opacity: coverFading ? 0 : 1,
            transition: coverFading ? 'opacity 0.85s ease-out' : 'none',
          }}
        />
      )}

      {/* Main content */}
      <div
        style={{
          position: 'relative',
          zIndex: 1,
          opacity: introGone ? 1 : 0,
          visibility: introGone ? 'visible' : 'hidden',
        }}
      >
        <Navbar />

        <main>
          <DataFlowSection />
          <FeaturesGrid />
          <LiveDashboard />
          <HorizontalSteps />
          <CTASection />
        </main>
      </div>
    </>
  )
}
