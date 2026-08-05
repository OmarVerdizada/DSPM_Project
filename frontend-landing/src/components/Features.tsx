import { useRef, useEffect } from 'react'
import { gsap } from 'gsap'
import { ScrollTrigger } from 'gsap/ScrollTrigger'

gsap.registerPlugin(ScrollTrigger)

const FEATURES = [
  {
    icon: (
      <svg width="28" height="28" viewBox="0 0 28 28" fill="none">
        <circle cx="14" cy="14" r="12" stroke="#3B82F6" strokeWidth="1.5"/>
        <circle cx="14" cy="14" r="6" stroke="#38BDF8" strokeWidth="1.5" strokeDasharray="2 2"/>
        <circle cx="14" cy="14" r="2" fill="#38BDF8"/>
        <line x1="14" y1="14" x2="23" y2="6" stroke="#5b8cff" strokeWidth="1" opacity="0.6"/>
      </svg>
    ),
    title: 'Automated Discovery',
    body: 'Scan AWS S3, Azure Blob, Google Drive, databases, and endpoints. Full inventory in minutes — updated continuously.',
  },
  {
    icon: (
      <svg width="28" height="28" viewBox="0 0 28 28" fill="none">
        <rect x="3" y="5" width="22" height="18" rx="3" stroke="#3B82F6" strokeWidth="1.5"/>
        <path d="M8 11h5M8 14h8M8 17h5" stroke="#38BDF8" strokeWidth="1.5" strokeLinecap="round"/>
        <rect x="16" y="9" width="6" height="4" rx="1" fill="rgba(59,130,246,0.3)" stroke="#5b8cff" strokeWidth="1"/>
      </svg>
    ),
    title: 'ML Classification',
    body: '40+ sensitive data types identified with AI accuracy — PII, credentials, health records, and financial data. Under 2% false positive rate.',
  },
  {
    icon: (
      <svg width="28" height="28" viewBox="0 0 28 28" fill="none">
        <path d="M5 23 A11 11 0 0 1 23 23" stroke="#1B3A6B" strokeWidth="5" strokeLinecap="round"/>
        <path d="M5 23 A11 11 0 0 1 19 12" stroke="#3B82F6" strokeWidth="5" strokeLinecap="round"/>
        <circle cx="14" cy="23" r="2" fill="#38BDF8"/>
        <line x1="14" y1="23" x2="20" y2="12" stroke="#38BDF8" strokeWidth="1.5" strokeLinecap="round"/>
      </svg>
    ),
    title: 'Risk Scoring',
    body: 'Every data store gets a posture score based on exposure, access controls, encryption, and compliance mapping. Focus effort where it matters.',
  },
  {
    icon: (
      <svg width="28" height="28" viewBox="0 0 28 28" fill="none">
        <path d="M14 3 L24 7.5 V15 C24 21 14 25 14 25 C14 25 4 21 4 15 V7.5 Z"
          stroke="#3B82F6" strokeWidth="1.5" fill="rgba(37,99,235,0.08)"/>
        <path d="M9 14.5 L12.5 18 L19 11" stroke="#38BDF8" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"/>
      </svg>
    ),
    title: 'Zero-Friction Deploy',
    body: 'Agent-based or agentless. Get full visibility in under 30 minutes. No database credentials stored. No sensitive data leaves your perimeter.',
  },
]

export default function Features() {
  const sectionRef = useRef<HTMLElement>(null)
  const cardRefs = useRef<(HTMLDivElement | null)[]>([])

  useEffect(() => {
    const ctx = gsap.context(() => {
      cardRefs.current.forEach((el, i) => {
        if (!el) return
        gsap.fromTo(
          el,
          { opacity: 0, y: 50 },
          {
            opacity: 1,
            y: 0,
            duration: 0.7,
            ease: 'power2.out',
            delay: (i % 2) * 0.12,
            scrollTrigger: {
              trigger: el,
              start: 'top 80%',
              toggleActions: 'play none none reverse',
            },
          }
        )
      })
    }, sectionRef)

    return () => ctx.revert()
  }, [])

  return (
    <section
      id="features"
      ref={sectionRef}
      className="relative py-32 px-6"
    >
      <div className="max-w-6xl mx-auto">
        <div className="text-center mb-16">
          <p className="section-label">Features</p>
          <h2 className="font-display text-fluid-lg text-text-primary tracking-tight">
            Security Precision, Built In
          </h2>
          <p className="mt-4 text-text-secondary max-w-xl mx-auto leading-relaxed">
            Every capability designed to give your security team complete clarity
            over sensitive data — without the complexity.
          </p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-6">
          {FEATURES.map((feat, i) => (
            <div
              key={feat.title}
              ref={(el) => { cardRefs.current[i] = el }}
              className="glass-card p-8"
            >
              <div
                className="w-12 h-12 rounded-xl flex items-center justify-center mb-6"
                style={{
                  background: 'rgba(37,99,235,0.1)',
                  border: '1px solid rgba(37,99,235,0.2)',
                }}
              >
                {feat.icon}
              </div>
              <h3 className="font-display text-base tracking-wider text-text-primary mb-3">
                {feat.title}
              </h3>
              <p className="text-text-secondary text-sm leading-relaxed">{feat.body}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  )
}
