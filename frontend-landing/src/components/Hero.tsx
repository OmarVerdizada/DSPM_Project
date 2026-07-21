import { useRef, useEffect, useLayoutEffect } from 'react'
import { gsap } from 'gsap'
import { APP_URL } from '../config'

export default function Hero() {
  const headlineRef  = useRef<HTMLDivElement>(null)
  const subRef       = useRef<HTMLParagraphElement>(null)
  const actionsRef   = useRef<HTMLDivElement>(null)
  const scrollCueRef = useRef<HTMLDivElement>(null)

  // useLayoutEffect fires synchronously after DOM commit but BEFORE the browser
  // paints, so elements are hidden before the first visible frame — no flash.
  useLayoutEffect(() => {
    gsap.set(headlineRef.current,  { y: 50, opacity: 0 })
    gsap.set(subRef.current,       { y: 30, opacity: 0 })
    gsap.set(actionsRef.current,   { y: 20, opacity: 0 })
    gsap.set(scrollCueRef.current, { opacity: 0 })
  }, [])

  useEffect(() => {
    const tl = gsap.timeline({ delay: 0.3 })
    tl.to(headlineRef.current,  { y: 0, opacity: 1, duration: 1,   ease: 'power3.out' })
    tl.to(subRef.current,       { y: 0, opacity: 1, duration: 0.8, ease: 'power2.out' }, '-=0.5')
    tl.to(actionsRef.current,   { y: 0, opacity: 1, duration: 0.7, ease: 'power2.out' }, '-=0.4')
    tl.to(scrollCueRef.current, {       opacity: 1, duration: 0.6, ease: 'power2.out' }, '-=0.2')
    return () => { tl.kill() }
  }, [])

  return (
    <section
      id="hero"
      className="relative min-h-screen flex flex-col items-center justify-center overflow-hidden grid-bg"
    >

      {/* Radial gradient background */}
      <div
        className="absolute inset-0 pointer-events-none"
        style={{
          background: `
            radial-gradient(ellipse 70% 60% at 25% 40%, rgba(37,99,235,0.12) 0%, transparent 70%),
            radial-gradient(ellipse 50% 50% at 75% 60%, rgba(56,189,248,0.07) 0%, transparent 60%),
            radial-gradient(ellipse 40% 40% at 50% 10%, rgba(91,140,255,0.06) 0%, transparent 50%)
          `,
        }}
      />

      {/* Animated glow orbs */}
      <div
        className="absolute pointer-events-none"
        style={{
          width: 600, height: 600, borderRadius: '50%',
          background: 'radial-gradient(circle, rgba(37,99,235,0.08) 0%, transparent 70%)',
          top: '10%', left: '-10%',
          animation: 'float 9s ease-in-out infinite',
        }}
      />
      <div
        className="absolute pointer-events-none"
        style={{
          width: 500, height: 500, borderRadius: '50%',
          background: 'radial-gradient(circle, rgba(56,189,248,0.06) 0%, transparent 70%)',
          bottom: '5%', right: '-5%',
          animation: 'float 7s ease-in-out infinite 2s',
        }}
      />

      {/* Hero content */}
      <div className="relative z-10 max-w-5xl mx-auto px-6 text-center pt-24 pb-32">
        <div className="section-label mb-8">Data Security Posture Management</div>

        <div ref={headlineRef}>
          <h1
            className="font-display text-fluid-hero text-text-primary tracking-tight"
            style={{ textShadow: '0 0 80px rgba(59,130,246,0.15)' }}
          >
            <span className="block">KNOW WHERE YOUR</span>
            <span className="block glow-text" style={{ color: '#5b8cff' }}>
              SENSITIVE DATA
            </span>
            <span className="block">LIVES</span>
          </h1>
        </div>

        <p
          ref={subRef}
          className="mt-8 max-w-2xl mx-auto text-fluid-md text-text-secondary leading-relaxed font-light"
        >
          SENTRO discovers, classifies, and scores your data security posture across
          every environment — so exposure is found before it becomes a breach.
        </p>

        <div ref={actionsRef} className="mt-12 flex flex-wrap items-center justify-center gap-4">
          <a href={APP_URL} className="btn-primary text-base px-8 py-4">
            Open SENTRO
            <svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true">
              <path d="M3 8h10M9 4l4 4-4 4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
            </svg>
          </a>
          <a href="#how-it-works" className="btn-ghost text-base px-8 py-4">
            See How It Works
          </a>
        </div>

        <p className="mt-10 text-xs text-text-muted tracking-wider uppercase">
          No data stored &nbsp;·&nbsp; Agent-optional &nbsp;·&nbsp; 30-minute deployment
        </p>
      </div>

      {/* Scroll cue */}
      <div
        ref={scrollCueRef}
        className="absolute bottom-10 left-1/2 -translate-x-1/2 flex flex-col items-center gap-2"
        style={{ animation: 'scrollBounce 2.2s ease-in-out infinite' }}
      >
        <span className="text-[10px] tracking-[0.25em] uppercase text-text-muted font-label">
          Scroll
        </span>
        <svg
          width="20" height="20" viewBox="0 0 20 20" fill="none"
          className="text-text-muted" aria-hidden="true"
        >
          <path d="M10 4v12M4 10l6 6 6-6" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
        </svg>
      </div>
    </section>
  )
}
