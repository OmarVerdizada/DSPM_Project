import { useState, useEffect } from 'react'
import { COLORS, FONTS } from '../../utils/constants'
import SentroLogo from '../SentroLogo'

const NAV_LINKS = [
  { label: 'Features', href: '#features' },
  { label: 'How It Works', href: '#how-it-works' },
  { label: 'Dashboard', href: '#dashboard' },
]

export default function Navbar() {
  const [menuOpen, setMenuOpen] = useState(false)
  const [scrolled, setScrolled] = useState(false)

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 40)
    window.addEventListener('scroll', onScroll, { passive: true })
    return () => window.removeEventListener('scroll', onScroll)
  }, [])

  const scrollTo = (href: string) => {
    setMenuOpen(false)
    const el = document.querySelector(href)
    if (el) el.scrollIntoView({ behavior: 'smooth' })
  }

  return (
    <header
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        right: 0,
        zIndex: 9000,
        background: scrolled
          ? 'rgba(7, 11, 26, 0.95)'
          : 'rgba(7, 11, 26, 0.85)',
        backdropFilter: 'blur(12px)',
        WebkitBackdropFilter: 'blur(12px)',
        borderBottom: `1px solid ${COLORS.navyLight}`,
        transition: 'background 0.3s ease',
      }}
    >
      <nav
        className="main-nav"
        style={{
          width: '100%',
          padding: '0 32px',
          height: '64px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
        }}
        aria-label="Main navigation"
      >
        {/* Logo */}
        <a
          href="#"
          onClick={(e) => { e.preventDefault(); window.scrollTo({ top: 0, behavior: 'smooth' }) }}
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '10px',
            fontFamily: FONTS.display,
            fontWeight: 600,
            fontSize: '1.25rem',
            color: COLORS.cloudWhite,
            textDecoration: 'none',
            letterSpacing: '0.06em',
          }}
        >
          <SentroLogo size={30} glowBlur={1.2} />
          SENTRO
        </a>

        {/* Desktop links */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '32px',
          }}
          className="desktop-nav"
        >
          {NAV_LINKS.map((link) => (
            <a
              key={link.href}
              href={link.href}
              onClick={(e) => { e.preventDefault(); scrollTo(link.href) }}
              style={{
                fontFamily: FONTS.body,
                fontSize: '0.875rem',
                fontWeight: 500,
                color: COLORS.cloudMuted,
                textDecoration: 'none',
                transition: 'color 0.2s ease',
                letterSpacing: '0.01em',
              }}
              onMouseEnter={(e) => ((e.target as HTMLElement).style.color = COLORS.cloudWhite)}
              onMouseLeave={(e) => ((e.target as HTMLElement).style.color = COLORS.cloudMuted)}
            >
              {link.label}
            </a>
          ))}
          <a
            href="/login"
            style={{
              fontFamily: FONTS.body,
              fontSize: '0.875rem',
              fontWeight: 600,
              color: '#fff',
              textDecoration: 'none',
              background: COLORS.accentBlue,
              padding: '8px 20px',
              borderRadius: '8px',
              transition: 'box-shadow 0.2s ease, transform 0.2s ease',
            }}
            onMouseEnter={(e) => {
              const el = e.currentTarget
              el.style.boxShadow = `0 0 20px rgba(59, 107, 245, 0.5)`
              el.style.transform = 'translateY(-1px)'
            }}
            onMouseLeave={(e) => {
              const el = e.currentTarget
              el.style.boxShadow = 'none'
              el.style.transform = 'translateY(0)'
            }}
          >
            Get Access
          </a>
        </div>

        {/* Mobile hamburger */}
        <button
          aria-label={menuOpen ? 'Close menu' : 'Open menu'}
          aria-expanded={menuOpen}
          onClick={() => setMenuOpen(!menuOpen)}
          style={{
            display: 'none',
            background: 'none',
            border: 'none',
            color: COLORS.cloudWhite,
            padding: '8px',
          }}
          className="hamburger-btn"
        >
          {menuOpen ? (
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none">
              <path d="M6 6l12 12M18 6L6 18" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
            </svg>
          ) : (
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none">
              <path d="M4 6h16M4 12h16M4 18h16" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
            </svg>
          )}
        </button>
      </nav>

      {/* Mobile menu */}
      {menuOpen && (
        <div
          style={{
            background: 'rgba(7, 11, 26, 0.98)',
            borderTop: `1px solid ${COLORS.navyLight}`,
            padding: '24px 8vw',
            display: 'flex',
            flexDirection: 'column',
            gap: '20px',
          }}
        >
          {NAV_LINKS.map((link) => (
            <a
              key={link.href}
              href={link.href}
              onClick={(e) => { e.preventDefault(); scrollTo(link.href) }}
              style={{
                fontFamily: FONTS.body,
                fontSize: '1rem',
                fontWeight: 500,
                color: COLORS.cloudMuted,
                textDecoration: 'none',
              }}
            >
              {link.label}
            </a>
          ))}
          <a
            href="/login"
            onClick={() => setMenuOpen(false)}
            style={{
              fontFamily: FONTS.body,
              fontSize: '1rem',
              fontWeight: 600,
              color: '#fff',
              textDecoration: 'none',
              background: COLORS.accentBlue,
              padding: '12px 20px',
              borderRadius: '8px',
              display: 'inline-block',
              textAlign: 'center',
            }}
          >
            Get Access
          </a>
        </div>
      )}

      <style>{`
        @media (max-width: 768px) {
          .desktop-nav { display: none !important; }
          .hamburger-btn { display: block !important; }
          .main-nav { padding: 0 20px !important; }
        }
      `}</style>
    </header>
  )
}
