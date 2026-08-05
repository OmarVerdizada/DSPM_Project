import { useRef, useEffect } from 'react'
import { gsap } from 'gsap'
import { ScrollTrigger } from 'gsap/ScrollTrigger'
import SentroLogo from './SentroLogo'
import { APP_URL } from '../config'

gsap.registerPlugin(ScrollTrigger)

const FOOTER_LINKS = {
  Product: ['Features', 'How It Works', 'Security', 'Pricing'],
  Company: ['About', 'Blog', 'Careers', 'Contact'],
  Legal: ['Privacy Policy', 'Terms of Service', 'Cookie Policy'],
}

export default function CTA() {
  const ctaRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const ctx = gsap.context(() => {
      gsap.fromTo(ctaRef.current,
        { opacity: 0, y: 50 },
        {
          opacity: 1, y: 0, duration: 1, ease: 'power2.out',
          scrollTrigger: {
            trigger: ctaRef.current,
            start: 'top 80%',
            toggleActions: 'play none none reverse',
          },
        }
      )
    })
    return () => ctx.revert()
  }, [])

  return (
    <footer
      className="relative overflow-hidden"
    >
      {/* CTA block */}
      <div
        className="relative py-28 px-6"
        style={{
          borderTop: '1px solid rgba(37,99,235,0.12)',
          borderBottom: '1px solid rgba(37,99,235,0.08)',
        }}
      >
        {/* Glow */}
        <div
          className="absolute inset-0 pointer-events-none"
          style={{
            background:
              'radial-gradient(ellipse 60% 60% at 50% 50%, rgba(37,99,235,0.08) 0%, transparent 70%)',
          }}
        />

        <div ref={ctaRef} className="relative max-w-3xl mx-auto text-center">
          <p className="section-label">Get Started</p>
          <h2
            className="font-display text-fluid-lg text-text-primary tracking-tight mb-6"
            style={{ lineHeight: 1.05 }}
          >
            Ready to see your<br />
            <span className="glow-text" style={{ color: '#5b8cff' }}>exposure?</span>
          </h2>
          <p className="text-text-secondary max-w-md mx-auto leading-relaxed mb-10">
            Join security teams using SENTRO to stay ahead of data risk.
            No credit card. 30-minute deployment. Real results.
          </p>

          <div className="flex flex-wrap items-center justify-center gap-4">
            <a href={APP_URL} className="btn-primary text-base px-8 py-4">
              Open SENTRO
              <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
                <path d="M3 8h10M9 4l4 4-4 4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
              </svg>
            </a>
            <a href="mailto:hello@sentro.io" className="btn-ghost text-base px-8 py-4">
              Talk to Us
            </a>
          </div>

          <p className="mt-8 text-xs text-text-muted">
            No data stored &nbsp;·&nbsp; GDPR / HIPAA ready &nbsp;·&nbsp; SOC 2 aligned
          </p>
        </div>
      </div>

      {/* Footer links */}
      <div className="max-w-6xl mx-auto px-6 py-16">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-10 mb-16">
          {/* Brand */}
          <div className="md:col-span-1">
            <div className="flex items-center gap-3 mb-4">
              <SentroLogo size={32} withGlow={false} />
              <span className="font-display text-sm tracking-widest text-text-primary">SENTRO</span>
            </div>
            <p className="text-text-muted text-xs leading-relaxed max-w-[220px]">
              Data Security Posture Management for modern enterprises.
            </p>
          </div>

          {/* Link columns */}
          {Object.entries(FOOTER_LINKS).map(([group, links]) => (
            <div key={group}>
              <h4 className="font-label text-xs tracking-[0.2em] uppercase text-text-muted mb-4">
                {group}
              </h4>
              <ul className="space-y-2.5">
                {links.map((link) => (
                  <li key={link}>
                    <a
                      href="#"
                      className="text-xs text-text-muted hover:text-text-secondary transition-colors duration-200"
                    >
                      {link}
                    </a>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>

        {/* Bottom bar */}
        <div
          className="flex flex-col md:flex-row items-center justify-between gap-4 pt-8"
          style={{ borderTop: '1px solid rgba(37,99,235,0.08)' }}
        >
          <p className="text-xs text-text-muted">
            © 2025 SENTRO. All rights reserved.
          </p>
          <p className="text-xs text-text-muted">
            Built for security teams who need answers, not alerts.
          </p>
        </div>
      </div>
    </footer>
  )
}
