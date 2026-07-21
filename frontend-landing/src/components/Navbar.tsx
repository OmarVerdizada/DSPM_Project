import { useState, useEffect } from 'react'
import SentroLogo from './SentroLogo'
import { APP_URL } from '../config'

export default function Navbar() {
  const [scrolled, setScrolled] = useState(false)
  const [menuOpen, setMenuOpen] = useState(false)

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 60)
    window.addEventListener('scroll', onScroll, { passive: true })
    return () => window.removeEventListener('scroll', onScroll)
  }, [])

  return (
    <nav
      className={`fixed top-0 left-0 right-0 z-50 transition-all duration-400 ${
        scrolled
          ? 'bg-bg-dark/90 backdrop-blur-sm border-b border-blue-primary/20 py-3'
          : 'bg-transparent py-5'
      }`}
    >
      <div className="max-w-7xl mx-auto px-6 flex items-center justify-between">
        {/* Logo */}
        <a href="#" className="flex items-center gap-3 group">
          <SentroLogo size={36} withGlow={false} className="group-hover:opacity-90 transition-opacity" />
          <span
            className="font-display text-base tracking-widest text-text-primary"
            style={{ textShadow: '0 0 8px rgba(91,140,255,0.3)' }}
          >
            SENTRO
          </span>
        </a>

        {/* Desktop nav */}
        <div className="hidden md:flex items-center gap-8">
          <a
            href="#features"
            className="text-sm text-text-secondary hover:text-text-primary transition-colors duration-200"
          >
            Features
          </a>
          <a
            href="#how-it-works"
            className="text-sm text-text-secondary hover:text-text-primary transition-colors duration-200"
          >
            How It Works
          </a>
          <a
            href="#faq"
            className="text-sm text-text-secondary hover:text-text-primary transition-colors duration-200"
          >
            FAQ
          </a>
        </div>

        {/* CTA */}
        <div className="hidden md:flex items-center gap-4">
          <a href={APP_URL} className="btn-primary text-sm">Request Access</a>
        </div>

        {/* Mobile hamburger */}
        <button
          className="md:hidden flex flex-col gap-1.5 p-2"
          onClick={() => setMenuOpen(!menuOpen)}
          aria-label="Toggle menu"
        >
          <span
            className={`block w-5 h-0.5 bg-text-secondary transition-all duration-300 ${
              menuOpen ? 'rotate-45 translate-y-2' : ''
            }`}
          />
          <span
            className={`block w-5 h-0.5 bg-text-secondary transition-all duration-300 ${
              menuOpen ? 'opacity-0' : ''
            }`}
          />
          <span
            className={`block w-5 h-0.5 bg-text-secondary transition-all duration-300 ${
              menuOpen ? '-rotate-45 -translate-y-2' : ''
            }`}
          />
        </button>
      </div>

      {/* Mobile menu */}
      <div
        className={`md:hidden overflow-hidden transition-all duration-300 ${
          menuOpen ? 'max-h-64 opacity-100' : 'max-h-0 opacity-0'
        }`}
      >
        <div className="px-6 pb-4 pt-2 flex flex-col gap-4 bg-bg-dark/95 backdrop-blur-sm border-t border-blue-primary/10">
          <a href="#features" className="text-sm text-text-secondary" onClick={() => setMenuOpen(false)}>Features</a>
          <a href="#how-it-works" className="text-sm text-text-secondary" onClick={() => setMenuOpen(false)}>How It Works</a>
          <a href="#faq" className="text-sm text-text-secondary" onClick={() => setMenuOpen(false)}>FAQ</a>
          <a href={APP_URL} className="btn-primary text-sm w-fit">Request Access</a>
        </div>
      </div>
    </nav>
  )
}
