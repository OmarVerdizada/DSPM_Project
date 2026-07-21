import { useRef, useEffect } from 'react'
import { gsap } from 'gsap'
import { ScrollTrigger } from 'gsap/ScrollTrigger'

gsap.registerPlugin(ScrollTrigger)

const STEPS = [
  {
    num: '01',
    title: 'DISCOVER',
    headline: 'Find every data store in minutes',
    body: 'SENTRO automatically scans cloud storage, databases, endpoints, and shared drives — building a complete, living data inventory without disrupting operations.',
  },
  {
    num: '02',
    title: 'CLASSIFY',
    headline: 'Know exactly what you hold',
    body: 'Intelligent classification engines identify 40+ sensitive data types — PII, financial records, credentials, health data — with context-aware accuracy and under 2% false positives.',
  },
  {
    num: '03',
    title: 'SCORE',
    headline: 'Prioritize your highest risks',
    body: 'Each data store receives a security posture score based on exposure, access controls, encryption status, and compliance mapping to GDPR, HIPAA, and SOC 2.',
  },
  {
    num: '04',
    title: 'REMEDIATE',
    headline: 'Close gaps before they become incidents',
    body: 'Guided remediation workflows and real-time alerts help your team act on the highest-risk exposures first — with full audit trail and reporting built in.',
  },
]

export default function Process() {
  const sectionRef = useRef<HTMLElement>(null)
  const stepRefs = useRef<(HTMLDivElement | null)[]>([])

  useEffect(() => {
    const ctx = gsap.context(() => {
      stepRefs.current.forEach((el) => {
        if (!el) return
        gsap.fromTo(
          el,
          { opacity: 0, y: 60 },
          {
            opacity: 1,
            y: 0,
            duration: 0.85,
            ease: 'power2.out',
            scrollTrigger: {
              trigger: el,
              start: 'top 78%',
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
      id="how-it-works"
      ref={sectionRef}
      className="relative py-32 px-6 overflow-hidden"
    >
      {/* Vertical line accent */}
      <div
        className="absolute left-1/2 top-0 bottom-0 w-px pointer-events-none hidden lg:block"
        style={{ background: 'linear-gradient(to bottom, transparent, rgba(37,99,235,0.15) 20%, rgba(37,99,235,0.15) 80%, transparent)' }}
      />

      <div className="max-w-6xl mx-auto">
        <div className="text-center mb-20">
          <p className="section-label">How It Works</p>
          <h2 className="font-display text-fluid-lg text-text-primary tracking-tight">
            From Blind Spot to Full Clarity
          </h2>
          <p className="mt-4 text-text-secondary max-w-xl mx-auto leading-relaxed">
            Four steps that transform how your team understands and controls data risk.
          </p>
        </div>

        <div className="grid grid-cols-1 gap-16 lg:gap-24">
          {STEPS.map((step, i) => (
            <div
              key={step.num}
              ref={(el) => { stepRefs.current[i] = el }}
              className={`flex flex-col lg:flex-row items-start gap-8 lg:gap-16 ${
                i % 2 === 1 ? 'lg:flex-row-reverse' : ''
              }`}
            >
              {/* Step number */}
              <div className="flex-none">
                <div
                  className="font-display text-[4.5rem] leading-none font-bold select-none"
                  style={{
                    color: 'transparent',
                    WebkitTextStroke: '1px rgba(91,140,255,0.25)',
                    letterSpacing: '-0.02em',
                  }}
                >
                  {step.num}
                </div>
              </div>

              {/* Content */}
              <div className="flex-1 min-w-0">
                <p className="section-label !mb-2">{step.title}</p>
                <h3 className="font-display text-fluid-md text-text-primary tracking-tight mb-4">
                  {step.headline}
                </h3>
                <p className="text-text-secondary leading-relaxed max-w-xl">
                  {step.body}
                </p>
              </div>

              {/* Visual accent */}
              <div
                className="flex-none w-full lg:w-64 h-32 lg:h-40 rounded-xl overflow-hidden"
                style={{
                  background: `linear-gradient(135deg, rgba(15,22,41,0.8) 0%, rgba(27,58,107,0.3) 100%)`,
                  border: '1px solid rgba(37,99,235,0.15)',
                  boxShadow: 'inset 0 0 40px rgba(59,130,246,0.04)',
                }}
              >
                <div className="w-full h-full flex items-center justify-center">
                  <StepIcon index={i} />
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  )
}

function StepIcon({ index }: { index: number }) {
  const icons = [
    // Discover: radar rings
    <svg key="discover" width="60" height="60" viewBox="0 0 60 60" fill="none" opacity="0.6">
      <circle cx="30" cy="30" r="28" stroke="#3B82F6" strokeWidth="1" strokeDasharray="3 4"/>
      <circle cx="30" cy="30" r="18" stroke="#5b8cff" strokeWidth="1" strokeDasharray="3 3"/>
      <circle cx="30" cy="30" r="8" stroke="#38BDF8" strokeWidth="1.5"/>
      <circle cx="30" cy="30" r="2.5" fill="#38BDF8"/>
      <line x1="30" y1="30" x2="50" y2="10" stroke="#38BDF8" strokeWidth="1" opacity="0.5"/>
    </svg>,
    // Classify: tag grid
    <svg key="classify" width="60" height="60" viewBox="0 0 60 60" fill="none" opacity="0.6">
      {[0,1,2].map(row => [0,1,2].map(col => (
        <rect key={`${row}-${col}`} x={8+col*18} y={8+row*18} width="12" height="10" rx="2"
          fill="none" stroke={col===1&&row===1?"#38BDF8":"#3B82F6"} strokeWidth="1"/>
      )))}
    </svg>,
    // Score: gauge
    <svg key="score" width="60" height="60" viewBox="0 0 60 60" fill="none" opacity="0.6">
      <path d="M10 42 A22 22 0 0 1 50 42" stroke="#1B3A6B" strokeWidth="6" strokeLinecap="round"/>
      <path d="M10 42 A22 22 0 0 1 42 20" stroke="#3B82F6" strokeWidth="6" strokeLinecap="round"/>
      <circle cx="30" cy="42" r="3" fill="#38BDF8"/>
      <line x1="30" y1="42" x2="42" y2="22" stroke="#38BDF8" strokeWidth="1.5" strokeLinecap="round"/>
    </svg>,
    // Remediate: shield check
    <svg key="remediate" width="60" height="60" viewBox="0 0 60 60" fill="none" opacity="0.6">
      <path d="M30 6 L50 14 V30 C50 42 30 54 30 54 C30 54 10 42 10 30 V14 Z"
        stroke="#3B82F6" strokeWidth="1.5" fill="rgba(37,99,235,0.08)"/>
      <path d="M20 30 L27 37 L40 24" stroke="#38BDF8" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
    </svg>,
  ]
  return icons[index]
}
