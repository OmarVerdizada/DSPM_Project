import { useEffect, useRef, useState } from 'react'
import { gsap } from 'gsap'
import { ScrollTrigger } from 'gsap/ScrollTrigger'
import { COLORS, FONTS } from '../../utils/constants'

gsap.registerPlugin(ScrollTrigger)

interface Feature {
  title: string
  description: string
  iconPath: string
  iconViewBox: string
  iconLength: number
}

// Icon paths are lucide icon geometry (24x24) inlined as single paths so the
// existing stroke draw-in animation keeps working without adding a dependency.
const FEATURES: Feature[] = [
  {
    title: 'File & Endpoint Discovery',
    description: 'Discover sensitive data across SMB servers, local files, and Windows endpoints.',
    // lucide: folder-search
    iconViewBox: '0 0 24 24',
    iconLength: 95,
    iconPath: 'M10.7 20H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h3.9a2 2 0 0 1 1.69.9l.81 1.2a2 2 0 0 0 1.67.9H20a2 2 0 0 1 2 2v4.1 M14 17a3 3 0 1 0 6 0a3 3 0 1 0-6 0 M21 21l-1.9-1.9',
  },
  {
    title: 'Sensitive Data Detection',
    description: 'Detect PII, PCI, PHI, secrets, private keys, financial data, and more.',
    // lucide: scan-search
    iconViewBox: '0 0 24 24',
    iconLength: 75,
    iconPath: 'M3 7V5a2 2 0 0 1 2-2h2 M17 3h2a2 2 0 0 1 2 2v2 M21 17v2a2 2 0 0 1-2 2h-2 M7 21H5a2 2 0 0 1-2-2v-2 M9 12a3 3 0 1 0 6 0a3 3 0 1 0-6 0 M16 16l-1.9-1.9',
  },
  {
    title: 'Contextual Risk Scoring',
    description: 'Score every file from 0–100 using sensitivity, access, exposure, and business context.',
    // lucide: gauge
    iconViewBox: '0 0 24 24',
    iconLength: 55,
    iconPath: 'M12 14l4-4 M3.34 19a10 10 0 1 1 17.32 0',
  },
  {
    title: 'Guided Remediation',
    description: 'Turn risky findings into clear priorities, owners, SLAs, and recommended actions.',
    // lucide: list-checks
    iconViewBox: '0 0 24 24',
    iconLength: 50,
    iconPath: 'M3 17l2 2 4-4 M3 7l2 2 4-4 M13 6h8 M13 12h8 M13 18h8',
  },
  {
    title: 'Multi-Tenant MSSP',
    description: 'Manage isolated customer environments, users, scans, credentials, and reports in one platform.',
    // lucide: building-2
    iconViewBox: '0 0 24 24',
    iconLength: 115,
    iconPath: 'M6 22V4a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v18Z M6 12H4a2 2 0 0 0-2 2v6a2 2 0 0 0 2 2h2 M18 9h2a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2h-2 M10 6h4 M10 10h4 M10 14h4 M10 18h4',
  },
  {
    title: 'Executive Analytics & Reports',
    description: 'Track posture, trends, priority risks, and export executive-ready reports.',
    // lucide: chart-no-axes-combined
    iconViewBox: '0 0 24 24',
    iconLength: 70,
    iconPath: 'M12 16v5 M16 14v7 M20 10v11 M22 3l-8.646 8.646a.5.5 0 0 1-.708 0L9.354 8.354a.5.5 0 0 0-.707 0L2 15 M4 18v3 M8 14v7',
  },
]

interface FeatureCardProps {
  feature: Feature
  index: number
}

function FeatureCard({ feature, index }: FeatureCardProps) {
  const cardRef = useRef<HTMLDivElement>(null)
  const iconRef = useRef<SVGPathElement>(null)
  const [hovered, setHovered] = useState(false)
  const [iconAnimated, setIconAnimated] = useState(false)

  useEffect(() => {
    if (!cardRef.current) return

    gsap.fromTo(
      cardRef.current,
      { opacity: 0, y: 40 },
      {
        opacity: 1,
        y: 0,
        duration: 0.7,
        ease: 'power2.out',
        delay: (index % 3) * 0.1,
        scrollTrigger: {
          trigger: cardRef.current,
          start: 'top 82%',
          toggleActions: 'play none none reverse',
          onEnter: () => {
            setIconAnimated(true)
          },
        },
      }
    )
  }, [index])

  return (
    <div
      ref={cardRef}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{
        background: COLORS.navyMid,
        border: `1px solid ${hovered ? COLORS.accentCyan : COLORS.navyLight}`,
        borderRadius: '12px',
        padding: '32px',
        transition: 'border-color 0.3s ease, box-shadow 0.3s ease, transform 0.3s ease',
        boxShadow: hovered
          ? `0 0 0 1px rgba(0,229,255,0.25), 0 0 28px rgba(0,229,255,0.16), 0 8px 32px rgba(0,0,0,0.3)`
          : '0 4px 16px rgba(0,0,0,0.2)',
        transform: hovered ? 'translateY(-4px)' : 'translateY(0)',
        willChange: 'transform',
        opacity: 0,
      }}
    >
      {/* Icon */}
      <div
        style={{
          width: '56px',
          height: '56px',
          marginBottom: '24px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
        }}
      >
        <svg
          viewBox={feature.iconViewBox}
          width="48"
          height="48"
          fill="none"
          aria-hidden="true"
        >
          <path
            ref={iconRef}
            d={feature.iconPath}
            stroke={COLORS.accentCyan}
            strokeWidth="1"
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeDasharray={feature.iconLength}
            strokeDashoffset={iconAnimated ? 0 : feature.iconLength}
            style={{
              transition: iconAnimated
                ? `stroke-dashoffset 1.2s ${index * 0.08}s ease`
                : 'none',
            }}
          />
        </svg>
      </div>

      {/* Title */}
      <h3
        style={{
          fontFamily: FONTS.display,
          fontSize: '19px',
          fontWeight: 600,
          color: COLORS.cloudWhite,
          marginBottom: '12px',
          letterSpacing: '0.01em',
        }}
      >
        {feature.title}
      </h3>

      {/* Description */}
      <p
        style={{
          fontFamily: FONTS.body,
          fontSize: '15px',
          lineHeight: 1.65,
          color: COLORS.cloudMuted,
          fontWeight: 400,
        }}
      >
        {feature.description}
      </p>
    </div>
  )
}

export default function FeaturesGrid() {
  const sectionRef = useRef<HTMLElement>(null)
  const labelRef = useRef<HTMLDivElement>(null)
  const headingRef = useRef<HTMLHeadingElement>(null)

  useEffect(() => {
    if (!sectionRef.current) return

    const ctx = gsap.context(() => {
      gsap.fromTo(
        [labelRef.current, headingRef.current],
        { opacity: 0, y: 30 },
        {
          opacity: 1,
          y: 0,
          duration: 0.8,
          stagger: 0.15,
          ease: 'power2.out',
          scrollTrigger: {
            trigger: sectionRef.current,
            start: 'top 75%',
            toggleActions: 'play none none reverse',
          },
        }
      )
    }, sectionRef)

    return () => ctx.revert()
  }, [])

  return (
    <section
      id="features"
      ref={sectionRef}
      aria-label="Platform capabilities"
      style={{
        position: 'relative',
        padding: '120px 8vw',
        background: COLORS.navyDeep,
      }}
    >
      {/* Subtle radial glow at top center */}
      <div
        aria-hidden="true"
        style={{
          position: 'absolute',
          top: 0,
          left: '50%',
          transform: 'translateX(-50%)',
          width: '600px',
          height: '300px',
          background: 'radial-gradient(ellipse at center top, rgba(0,229,255,0.03) 0%, transparent 70%)',
          pointerEvents: 'none',
        }}
      />

      <div style={{ maxWidth: '1200px', margin: '0 auto' }}>
        {/* Section header */}
        <div style={{ textAlign: 'center', marginBottom: '72px' }}>
          <div
            ref={labelRef}
            style={{
              fontFamily: FONTS.mono,
              fontSize: '12px',
              letterSpacing: '0.25em',
              textTransform: 'uppercase',
              color: COLORS.accentCyan,
              marginBottom: '16px',
              opacity: 0,
            }}
          >
            CAPABILITIES
          </div>
          <h2
            ref={headingRef}
            style={{
              fontFamily: FONTS.display,
              fontSize: 'clamp(1.8rem, 3.5vw, 48px)',
              fontWeight: 600,
              color: COLORS.cloudWhite,
              letterSpacing: '-0.01em',
              lineHeight: 1.15,
              opacity: 0,
            }}
          >
            Built to Find, Understand, and Reduce Data Risk
          </h2>
        </div>

        {/* Grid */}
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(3, 1fr)',
            gap: '24px',
          }}
          className="features-grid"
        >
          {FEATURES.map((feature, i) => (
            <FeatureCard key={feature.title} feature={feature} index={i} />
          ))}
        </div>
      </div>

      <style>{`
        @media (max-width: 1024px) {
          .features-grid {
            grid-template-columns: repeat(2, 1fr) !important;
          }
        }
        @media (max-width: 640px) {
          .features-grid {
            grid-template-columns: 1fr !important;
          }
        }
      `}</style>
    </section>
  )
}
