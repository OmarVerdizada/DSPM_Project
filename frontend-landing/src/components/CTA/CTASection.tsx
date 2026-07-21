import { COLORS, FONTS } from '../../utils/constants'
import Footer from '../Layout/Footer'

export default function CTASection() {
  return (
    <>
      <section
        id="cta"
        aria-label="Call to action"
        style={{
          position: 'relative',
          padding: '160px 8vw',
          background: COLORS.navyDeep,
          textAlign: 'center',
          overflow: 'hidden',
        }}
      >
        {/* Watermark SENTRO text */}
        <div
          aria-hidden="true"
          style={{
            position: 'absolute',
            top: '50%',
            left: '50%',
            transform: 'translate(-50%, -50%)',
            fontFamily: FONTS.display,
            fontWeight: 700,
            fontSize: 'clamp(8rem, 20vw, 22rem)',
            color: COLORS.navyLight,
            opacity: 0.08,
            letterSpacing: '0.05em',
            userSelect: 'none',
            pointerEvents: 'none',
            whiteSpace: 'nowrap',
            animation: 'spin-slow 120s linear infinite',
          }}
        >
          SENTRO
        </div>

        {/* Background glows */}
        <div
          aria-hidden="true"
          style={{
            position: 'absolute',
            inset: 0,
            background: `
              radial-gradient(ellipse 60% 50% at 50% 50%, rgba(0,229,255,0.04) 0%, transparent 70%),
              radial-gradient(ellipse 40% 40% at 30% 30%, rgba(123,91,242,0.04) 0%, transparent 60%)
            `,
            pointerEvents: 'none',
          }}
        />

        <div style={{ position: 'relative', zIndex: 1, maxWidth: '700px', margin: '0 auto' }}>
          <h2
            style={{
              fontFamily: FONTS.display,
              fontWeight: 700,
              fontSize: 'clamp(2rem, 4.5vw, 56px)',
              lineHeight: 1.1,
              letterSpacing: '-0.01em',
              background: `linear-gradient(135deg, ${COLORS.accentCyan} 0%, ${COLORS.accentPurple} 100%)`,
              WebkitBackgroundClip: 'text',
              WebkitTextFillColor: 'transparent',
              backgroundClip: 'text',
              marginBottom: '24px',
            }}
          >
            Ready to See Your Blind Spots?
          </h2>

          <p
            style={{
              fontFamily: FONTS.body,
              fontSize: '18px',
              lineHeight: 1.6,
              color: COLORS.cloudMuted,
              marginBottom: '48px',
            }}
          >
            Deploy SENTRO in minutes. Full visibility from Day 1.
          </p>

          <div style={{ display: 'flex', gap: '16px', justifyContent: 'center', flexWrap: 'wrap' }}>
            <a
              href="/login"
              style={{
                fontFamily: FONTS.body,
                fontSize: '16px',
                fontWeight: 600,
                color: '#ffffff',
                background: COLORS.accentBlue,
                border: 'none',
                borderRadius: '10px',
                padding: '18px 48px',
                textDecoration: 'none',
                display: 'inline-block',
                animation: 'cta-glow-pulse 2.5s ease-in-out infinite',
                transition: 'transform 0.2s ease',
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.transform = 'translateY(-3px) scale(1.02)'
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.transform = 'translateY(0) scale(1)'
              }}
            >
              Get Started
            </a>

            <a
              href="#how-it-works"
              onClick={(e) => {
                e.preventDefault()
                document.getElementById('how-it-works')?.scrollIntoView({ behavior: 'smooth' })
              }}
              style={{
                fontFamily: FONTS.body,
                fontSize: '16px',
                fontWeight: 500,
                color: COLORS.cloudWhite,
                background: 'transparent',
                border: `1px solid ${COLORS.navyLight}`,
                borderRadius: '10px',
                padding: '18px 48px',
                textDecoration: 'none',
                display: 'inline-flex',
                alignItems: 'center',
                gap: '8px',
                transition: 'border-color 0.25s ease',
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.borderColor = COLORS.accentCyan
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.borderColor = COLORS.navyLight
              }}
            >
              Learn More
              <svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true">
                <path d="M3 8h10M9 4l4 4-4 4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
              </svg>
            </a>
          </div>

          {/* Trust signals */}
          <div
            style={{
              marginTop: '48px',
              display: 'flex',
              gap: '32px',
              justifyContent: 'center',
              flexWrap: 'wrap',
            }}
          >
            {['No data stored', 'Agent-optional', '30-min deploy', 'SOC2 ready'].map((item) => (
              <div
                key={item}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                  fontFamily: FONTS.mono,
                  fontSize: '12px',
                  color: COLORS.cloudMuted,
                  letterSpacing: '0.05em',
                }}
              >
                <svg width="12" height="12" viewBox="0 0 12 12" fill="none" aria-hidden="true">
                  <circle cx="6" cy="6" r="5" stroke={COLORS.accentCyan} strokeWidth="1.2" />
                  <path d="M3.5 6l1.5 1.5 3-3" stroke={COLORS.accentCyan} strokeWidth="1.2" strokeLinecap="round" strokeLinejoin="round" />
                </svg>
                {item}
              </div>
            ))}
          </div>
        </div>
      </section>

      <Footer />
    </>
  )
}
