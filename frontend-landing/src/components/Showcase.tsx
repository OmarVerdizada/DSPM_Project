import { useRef, useEffect } from 'react'
import { gsap } from 'gsap'
import { ScrollTrigger } from 'gsap/ScrollTrigger'
import SentroLogo from './SentroLogo'
import { APP_URL } from '../config'

gsap.registerPlugin(ScrollTrigger)

export default function Showcase() {
  const sectionRef = useRef<HTMLElement>(null)
  const leftRef = useRef<HTMLDivElement>(null)
  const rightRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const ctx = gsap.context(() => {
      gsap.fromTo(leftRef.current,
        { opacity: 0, x: -60 },
        {
          opacity: 1, x: 0, duration: 1, ease: 'power2.out',
          scrollTrigger: { trigger: sectionRef.current, start: 'top 65%', toggleActions: 'play none none reverse' },
        }
      )
      gsap.fromTo(rightRef.current,
        { opacity: 0, x: 60 },
        {
          opacity: 1, x: 0, duration: 1, ease: 'power2.out', delay: 0.15,
          scrollTrigger: { trigger: sectionRef.current, start: 'top 65%', toggleActions: 'play none none reverse' },
        }
      )
    }, sectionRef)
    return () => ctx.revert()
  }, [])

  return (
    <section
      ref={sectionRef}
      className="relative py-32 px-6 overflow-hidden"
    >
      {/* Glow behind */}
      <div
        className="absolute pointer-events-none"
        style={{
          width: 800,
          height: 800,
          borderRadius: '50%',
          background: 'radial-gradient(circle, rgba(37,99,235,0.07) 0%, transparent 70%)',
          top: '50%',
          left: '50%',
          transform: 'translate(-50%, -50%)',
        }}
      />

      <div className="max-w-6xl mx-auto grid grid-cols-1 lg:grid-cols-2 gap-16 items-center">
        {/* Left: copy */}
        <div ref={leftRef}>
          <p className="section-label">Visibility</p>
          <h2
            className="font-display text-fluid-lg text-text-primary tracking-tight mb-6"
            style={{ lineHeight: '1.05' }}
          >
            From Blind Spots<br />
            <span className="glow-text" style={{ color: '#5b8cff' }}>to Full Clarity</span>
          </h2>
          <p className="text-text-secondary leading-relaxed mb-8 max-w-md">
            SENTRO gives your security team a living map of sensitive data exposure —
            updated in real time as your infrastructure evolves. Know your risk surface.
            Own your posture.
          </p>
          <div className="flex flex-col gap-4 mb-10">
            {[
              'Real-time inventory across 15+ data source types',
              'Continuous monitoring — not a one-time scan',
              'Board-ready risk reports in one click',
            ].map((item) => (
              <div key={item} className="flex items-start gap-3 text-sm text-text-secondary">
                <svg width="18" height="18" viewBox="0 0 18 18" fill="none" className="flex-none mt-0.5">
                  <circle cx="9" cy="9" r="8" stroke="rgba(59,130,246,0.3)" strokeWidth="1"/>
                  <path d="M5.5 9L7.5 11L12.5 7" stroke="#38BDF8" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
                </svg>
                {item}
              </div>
            ))}
          </div>
          <a href={APP_URL} className="btn-primary">
            Open SENTRO
            <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
              <path d="M3 8h10M9 4l4 4-4 4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
            </svg>
          </a>
        </div>

        {/* Right: dashboard mockup */}
        <div ref={rightRef} className="relative">
          <div
            className="rounded-2xl overflow-hidden"
            style={{
              background: '#0F1629',
              border: '1px solid rgba(37,99,235,0.2)',
              boxShadow: '0 0 60px rgba(37,99,235,0.12), inset 0 0 40px rgba(0,0,0,0.3)',
            }}
          >
            {/* Mockup header */}
            <div
              className="flex items-center gap-2 px-4 py-3"
              style={{ borderBottom: '1px solid rgba(37,99,235,0.12)' }}
            >
              <div className="flex gap-1.5">
                {['#FF5F57', '#FEBC2E', '#28C840'].map((c) => (
                  <div key={c} className="w-3 h-3 rounded-full" style={{ background: c, opacity: 0.7 }} />
                ))}
              </div>
              <span className="text-xs text-text-muted ml-2 font-label tracking-wider">
                SENTRO · DATA INVENTORY
              </span>
            </div>

            {/* Mockup body */}
            <div className="p-6 space-y-4">
              {/* Score bar */}
              <div>
                <div className="flex justify-between text-xs text-text-muted mb-2">
                  <span className="font-label tracking-wider uppercase">Security Posture Score</span>
                  <span className="text-blue-cyan font-semibold">74 / 100</span>
                </div>
                <div className="h-1.5 bg-bg-deep rounded-full overflow-hidden">
                  <div
                    className="h-full rounded-full"
                    style={{
                      width: '74%',
                      background: 'linear-gradient(90deg, #2563EB, #38BDF8)',
                      boxShadow: '0 0 8px rgba(59,130,246,0.5)',
                    }}
                  />
                </div>
              </div>

              {/* Data rows */}
              {[
                { name: 'prod-db-eu-west', type: 'PostgreSQL', risk: 'HIGH', count: '12.4K records' },
                { name: 's3://finance-backup', type: 'AWS S3', risk: 'CRITICAL', count: '3.2M records' },
                { name: 'sharepoint-legal', type: 'SharePoint', risk: 'MEDIUM', count: '841 files' },
                { name: 'dev-mongo-cluster', type: 'MongoDB', risk: 'LOW', count: '2.1K records' },
              ].map((row) => (
                <div
                  key={row.name}
                  className="flex items-center justify-between py-3"
                  style={{ borderBottom: '1px solid rgba(37,99,235,0.06)' }}
                >
                  <div className="flex items-center gap-3">
                    <SentroLogo size={20} withGlow={false} />
                    <div>
                      <div className="text-xs text-text-primary font-medium">{row.name}</div>
                      <div className="text-[10px] text-text-muted">{row.type} · {row.count}</div>
                    </div>
                  </div>
                  <span
                    className="text-[10px] font-label font-semibold tracking-wider px-2 py-1 rounded"
                    style={{
                      color: row.risk === 'CRITICAL' ? '#F87171'
                        : row.risk === 'HIGH' ? '#FB923C'
                        : row.risk === 'MEDIUM' ? '#FACC15'
                        : '#4ADE80',
                      background: row.risk === 'CRITICAL' ? 'rgba(248,113,113,0.1)'
                        : row.risk === 'HIGH' ? 'rgba(251,146,60,0.1)'
                        : row.risk === 'MEDIUM' ? 'rgba(250,204,21,0.1)'
                        : 'rgba(74,222,128,0.1)',
                    }}
                  >
                    {row.risk}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* Floating stat badge */}
          <div
            className="absolute -bottom-4 -right-4 px-4 py-3 rounded-xl text-center"
            style={{
              background: '#0F1629',
              border: '1px solid rgba(56,189,248,0.3)',
              boxShadow: '0 0 20px rgba(56,189,248,0.1)',
            }}
          >
            <div className="text-xl font-display text-blue-cyan">18.5M</div>
            <div className="text-[10px] text-text-muted tracking-wider uppercase font-label">records mapped</div>
          </div>
        </div>
      </div>
    </section>
  )
}
