import { useState, useEffect, useRef, type FormEvent, type ReactNode } from 'react'
import { Eye, EyeOff, Sun, Moon } from 'lucide-react'
import CustomCursor from '../Layout/CustomCursor'
import SentroLogo from '../SentroLogo'
import { COLORS, FONTS, prefersReducedMotion } from '../../utils/constants'
import { APP_URL } from '../../config'

// ─────────────────────────────────────────────────────────────────────────────
// Premium split-screen login page.
// Defaults to an airy light theme; toggles to the signature deep-navy palette.
// Reuses the site's tokens (COLORS/FONTS), logo, and custom cursor.
// ─────────────────────────────────────────────────────────────────────────────

type Mode = 'light' | 'dark'

const THEMES = {
  light: {
    brandBg: '#FAFAFA',
    brandTint: 'radial-gradient(ellipse 70% 60% at 12% 0%, rgba(0,229,255,0.07) 0%, transparent 60%)',
    panelBg: '#FFFFFF',
    cardBg: '#FFFFFF',
    cardShadow: '0 8px 40px rgba(10,14,26,0.08), 0 2px 8px rgba(10,14,26,0.04)',
    cardBorder: '#E5E7EB',
    text: '#0A0E1A',
    muted: '#6B7280',
    border: '#E5E7EB',
    inputBg: '#FFFFFF',
    gridLine: 'rgba(94,148,160,0.16)',
    ssoHoverBg: 'rgba(0,229,255,0.05)',
    seamShadow: '-40px 0 64px -36px rgba(10,14,26,0.14)',
    seamTint: 'linear-gradient(to right, rgba(30,58,138,0), rgba(30,58,138,0.07) 50%, rgba(30,58,138,0))',
    panelBlend: 'linear-gradient(to right, #FAFAFA, #FFFFFF 220px)',
  },
  dark: {
    brandBg: '#0A0E1A',
    brandTint: 'radial-gradient(ellipse 70% 60% at 12% 0%, rgba(0,229,255,0.05) 0%, transparent 60%)',
    panelBg: '#0D1220',
    cardBg: '#0D1220',
    cardShadow: `0 0 0 1px ${COLORS.navyLight}, 0 0 28px rgba(0,229,255,0.07)`,
    cardBorder: COLORS.navyLight,
    text: COLORS.cloudWhite,
    muted: COLORS.cloudMuted,
    border: COLORS.navyLight,
    inputBg: 'rgba(15,21,53,0.5)',
    gridLine: 'rgba(0,229,255,0.10)',
    ssoHoverBg: 'rgba(0,229,255,0.06)',
    seamShadow: '-40px 0 64px -36px rgba(0,0,0,0.5)',
    seamTint: 'linear-gradient(to right, rgba(0,0,0,0), rgba(0,0,0,0.26) 50%, rgba(0,0,0,0))',
    panelBlend: 'linear-gradient(to right, #0A0E1A, #0D1220 220px)',
  },
} as const

const EASE = 'background-color 0.3s ease, color 0.3s ease, border-color 0.3s ease, box-shadow 0.3s ease'
const GRAIN =
  `url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='140' height='140'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='2'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)'/%3E%3C/svg%3E")`

// ─── Brand-mark SVGs (monochrome, inherit currentColor) ──────────────────────
const GitHubMark = (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
    <path d="M12 0.3a12 12 0 0 0-3.8 23.38c0.6 0.12 0.82-0.26 0.82-0.58l-0.01-2.03c-3.34 0.72-4.04-1.61-4.04-1.61-0.55-1.39-1.34-1.76-1.34-1.76-1.08-0.74 0.09-0.73 0.09-0.73 1.2 0.09 1.83 1.24 1.83 1.24 1.07 1.83 2.8 1.3 3.49 1 0.1-0.78 0.42-1.31 0.76-1.61-2.66-0.3-5.47-1.33-5.47-5.93 0-1.31 0.47-2.38 1.24-3.22-0.13-0.3-0.54-1.52 0.11-3.18 0 0 1-0.32 3.3 1.23a11.5 11.5 0 0 1 6 0c2.28-1.55 3.29-1.23 3.29-1.23 0.66 1.66 0.24 2.88 0.12 3.18 0.77 0.84 1.23 1.91 1.23 3.22 0 4.61-2.8 5.62-5.48 5.92 0.43 0.37 0.81 1.1 0.81 2.22l-0.01 3.29c0 0.32 0.21 0.7 0.82 0.58A12 12 0 0 0 12 0.3z" />
  </svg>
)
const GoogleMark = (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
    <path d="M21.8 12.23c0-0.7-0.06-1.37-0.18-2.02H12v3.83h5.5a4.7 4.7 0 0 1-2.04 3.08v2.56h3.3c1.93-1.78 3.04-4.4 3.04-7.45z" opacity="0.95" />
    <path d="M12 22c2.76 0 5.07-0.91 6.76-2.47l-3.3-2.56c-0.91 0.61-2.08 0.97-3.46 0.97-2.66 0-4.92-1.8-5.72-4.22H2.86v2.65A10.2 10.2 0 0 0 12 22z" opacity="0.75" />
    <path d="M6.28 13.72a6.1 6.1 0 0 1 0-3.9V7.17H2.86a10.2 10.2 0 0 0 0 9.2l3.42-2.65z" opacity="0.55" />
    <path d="M12 6.06c1.5 0 2.85 0.52 3.9 1.53l2.93-2.93A10.16 10.16 0 0 0 12 1.83a10.2 10.2 0 0 0-9.14 5.34l3.42 2.65C7.08 7.86 9.34 6.06 12 6.06z" opacity="0.85" />
  </svg>
)

// ─── Floating-label input ─────────────────────────────────────────────────────
function FloatingInput({ id, label, type, value, onChange, error, theme, autoComplete, trailing }: {
  id: string
  label: string
  type: string
  value: string
  onChange: (v: string) => void
  error?: string
  theme: (typeof THEMES)[Mode]
  autoComplete?: string
  trailing?: ReactNode
}) {
  const [focused, setFocused] = useState(false)
  const floated = focused || value.length > 0

  return (
    <div style={{ marginBottom: error ? '6px' : '18px' }}>
      <div style={{ position: 'relative' }}>
        <input
          id={id}
          type={type}
          value={value}
          autoComplete={autoComplete}
          aria-label={label}
          aria-invalid={!!error}
          aria-describedby={error ? `${id}-error` : undefined}
          onChange={(e) => onChange(e.target.value)}
          onFocus={() => setFocused(true)}
          onBlur={() => setFocused(false)}
          style={{
            width: '100%',
            padding: trailing ? '22px 46px 8px 14px' : '22px 14px 8px 14px',
            fontFamily: FONTS.body,
            fontSize: '15px',
            color: theme.text,
            background: theme.inputBg,
            border: `1px solid ${error ? COLORS.alertRed : focused ? COLORS.accentCyan : theme.border}`,
            borderRadius: '8px',
            outline: 'none',
            boxShadow: focused ? '0 2px 14px rgba(0,229,255,0.18)' : 'none',
            transition: `${EASE}, box-shadow 0.25s ease`,
          }}
        />
        <label
          htmlFor={id}
          style={{
            position: 'absolute',
            left: '14px',
            top: floated ? '6px' : '50%',
            transform: floated ? 'translateY(0)' : 'translateY(-50%)',
            fontFamily: FONTS.body,
            fontSize: floated ? '11px' : '15px',
            letterSpacing: floated ? '0.03em' : '0',
            color: focused ? COLORS.accentCyan : theme.muted,
            pointerEvents: 'none',
            transition: 'all 0.2s ease',
          }}
        >
          {label}
        </label>
        {trailing && (
          <div style={{ position: 'absolute', right: '10px', top: '50%', transform: 'translateY(-50%)' }}>
            {trailing}
          </div>
        )}
      </div>
      {error && (
        <div id={`${id}-error`} role="alert" style={{
          fontFamily: FONTS.body, fontSize: '12px', color: COLORS.alertRed,
          margin: '5px 2px 12px', opacity: 0.9,
        }}>
          {error}
        </div>
      )}
    </div>
  )
}

// ─── SSO button ───────────────────────────────────────────────────────────────
function SsoButton({ icon, label, theme }: { icon: ReactNode; label: string; theme: (typeof THEMES)[Mode] }) {
  return (
    <button
      type="button"
      onClick={() => { /* placeholder — real SSO wired later */ }}
      style={{
        width: '100%',
        display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '10px',
        position: 'relative',
        padding: '12px 16px',
        fontFamily: FONTS.body, fontSize: '14px', fontWeight: 500,
        color: theme.text,
        background: 'transparent',
        border: `1px solid ${theme.border}`,
        borderRadius: '8px',
        transition: `${EASE}, transform 0.2s ease`,
        marginBottom: '10px',
      }}
      onMouseEnter={(e) => {
        e.currentTarget.style.borderColor = COLORS.accentCyan
        e.currentTarget.style.background = theme.ssoHoverBg
        e.currentTarget.style.transform = 'translateY(-1px)'
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.borderColor = theme.border
        e.currentTarget.style.background = 'transparent'
        e.currentTarget.style.transform = 'translateY(0)'
      }}
    >
      <span style={{ position: 'absolute', left: '16px', display: 'flex', color: theme.muted }}>{icon}</span>
      {label}
    </button>
  )
}

// ─────────────────────────────────────────────────────────────────────────────
export default function LoginPage() {
  const reduced = prefersReducedMotion()
  const [mode, setMode] = useState<Mode>('light')
  const t = THEMES[mode]

  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [showPw, setShowPw] = useState(false)
  const [remember, setRemember] = useState(false)
  const [errors, setErrors] = useState<{ email?: string; password?: string }>({})
  const [formError, setFormError] = useState('')
  const [loading, setLoading] = useState(false)
  const [pulse, setPulse] = useState(false)
  const timerRef = useRef<number[]>([])

  useEffect(() => {
    document.title = 'Sign in — SENTRO'
    return () => { timerRef.current.forEach(clearTimeout) }
  }, [])

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault()
    if (loading) return

    const next: typeof errors = {}
    if (!email.trim()) next.email = 'Email or username is required.'
    if (!password) next.password = 'Password is required.'
    setErrors(next)
    setFormError('')
    if (Object.keys(next).length > 0) return

    setLoading(true)
    try {
      const response = await fetch(`${APP_URL}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: email.trim(), password }),
      })

      if (!response.ok) {
        let detail =
          response.status === 401
            ? 'Invalid username or password.'
            : response.status === 429
              ? 'Too many sign-in attempts. Try again in a few minutes.'
              : 'Sign-in failed. Please try again.'
        try {
          const payload = await response.json()
          if (response.status !== 401 && payload?.detail) detail = payload.detail
        } catch { /* keep the safe generic message */ }
        setFormError(detail)
        setLoading(false)
        return
      }

      const result = await response.json()
      // Hand the session to the console via the URL fragment — it is never
      // sent to the server; a small script on the dashboard stores it.
      const fragment = new URLSearchParams({
        sso: result.access_token,
        tenant: result.tenant_id || 'default',
        role: result.role || 'viewer',
        user: email.trim(),
      })
      const target = `${APP_URL}/dashboard#${fragment.toString()}`

      if (!reduced) setPulse(true)
      timerRef.current.push(window.setTimeout(() => {
        window.location.href = target
      }, reduced ? 150 : 950))
    } catch {
      setFormError('Cannot reach the SENTRO console. Is it running?')
      setLoading(false)
    }
  }

  const anim = (delay: number) =>
    reduced ? undefined : { animation: `lp-rise 0.5s ease ${delay}s both` }

  return (
    <div
      className="login-page"
      style={{
        minHeight: '100vh',
        position: 'relative',
        display: 'flex',
        background: t.brandBg,
        transition: EASE,
      }}
    >
      <CustomCursor />

      {/* ── Theme toggle ─────────────────────────────────────────────────── */}
      <button
        type="button"
        onClick={() => setMode(mode === 'light' ? 'dark' : 'light')}
        aria-label={mode === 'light' ? 'Switch to dark mode' : 'Switch to light mode'}
        aria-pressed={mode === 'dark'}
        style={{
          position: 'fixed', top: '20px', right: '20px', zIndex: 50,
          width: '40px', height: '40px',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          color: t.muted,
          background: t.cardBg,
          border: `1px solid ${t.border}`,
          borderRadius: '50%',
          transition: EASE,
        }}
        onMouseEnter={(e) => { e.currentTarget.style.borderColor = COLORS.accentCyan; e.currentTarget.style.color = COLORS.accentCyan }}
        onMouseLeave={(e) => { e.currentTarget.style.borderColor = t.border; e.currentTarget.style.color = t.muted }}
      >
        {mode === 'light' ? <Moon size={17} /> : <Sun size={17} />}
      </button>

      {/* ── Left panel — brand showcase ──────────────────────────────────── */}
      <div
        className="lp-brand"
        style={{
          flex: '0 0 55%',
          position: 'relative',
          display: 'flex', flexDirection: 'column', justifyContent: 'center',
          padding: 'clamp(32px, 5vw, 80px)',
          background: `${t.brandTint}, ${t.brandBg}`.replace(/^,\s*/, ''),
          backgroundColor: t.brandBg,
          backgroundImage: t.brandTint,
          overflow: 'hidden',
          transition: EASE,
        }}
      >
        {/* Drifting grid — echo of the hero scene's floor */}
        <div
          aria-hidden="true"
          className={reduced ? undefined : 'lp-grid-drift'}
          style={{
            position: 'absolute', left: '-30%', right: '-30%', top: '30%', bottom: '-45%',
            backgroundImage: `linear-gradient(${t.gridLine} 1px, transparent 1px), linear-gradient(90deg, ${t.gridLine} 1px, transparent 1px)`,
            backgroundSize: '56px 56px',
            transform: 'perspective(620px) rotateX(58deg)',
            transformOrigin: '50% 0%',
            maskImage: 'radial-gradient(ellipse 75% 85% at 50% 15%, black 30%, transparent 78%)',
            WebkitMaskImage: 'radial-gradient(ellipse 75% 85% at 50% 15%, black 30%, transparent 78%)',
            pointerEvents: 'none',
            transition: 'background-image 0.3s ease',
          }}
        />
        {/* Grain */}
        <div aria-hidden="true" style={{
          position: 'absolute', inset: 0, backgroundImage: GRAIN,
          opacity: 0.03, pointerEvents: 'none',
        }} />

        {/* Logo — top-left of the panel */}
        <div style={{
          position: 'absolute', top: 'clamp(24px, 4vh, 44px)', left: 'clamp(32px, 5vw, 80px)',
          display: 'flex', alignItems: 'center', gap: '12px',
        }}>
          <SentroLogo size={38} glowBlur={1.2} variant={mode} />
          <span style={{
            fontFamily: FONTS.display, fontWeight: 600, fontSize: '1.05rem',
            letterSpacing: '0.14em', color: t.text, transition: EASE,
          }}>
            SENTRO
          </span>
        </div>

        <div className="lp-brand-copy" style={{ position: 'relative', zIndex: 1, maxWidth: '560px', ...anim(0.05) }}>
          <h1 style={{
            fontFamily: FONTS.display, fontWeight: 700,
            fontSize: 'clamp(2rem, 3.6vw, 52px)',
            lineHeight: 1.08, letterSpacing: '-0.02em',
            color: t.text, marginBottom: '20px', transition: EASE,
          }}>
            Your data. Fully visible.{' '}
            <span style={{
              background: `linear-gradient(135deg, ${COLORS.accentCyan}, ${COLORS.accentBlue})`,
              WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent', backgroundClip: 'text',
            }}>
              Fully secured.
            </span>
          </h1>
          <p style={{
            fontFamily: FONTS.body, fontSize: '16px', lineHeight: 1.6,
            color: t.muted, transition: EASE,
          }}>
            Sign in to your posture command center.
          </p>
        </div>

        {/* Trust indicators */}
        <div className="lp-trust" style={{
          position: 'absolute', bottom: 'clamp(24px, 5vh, 48px)', left: 'clamp(32px, 5vw, 80px)',
          display: 'flex', gap: '28px', flexWrap: 'wrap',
          fontFamily: FONTS.mono, fontSize: '11px', letterSpacing: '0.14em',
          color: t.muted, opacity: 0.75, transition: EASE, zIndex: 1,
        }}>
          {['GDPR', 'NIST', 'PCI DSS'].map((item, i, arr) => (
            <span key={item} style={{ display: 'flex', alignItems: 'center', gap: '28px' }}>
              {item}
              {i < arr.length - 1 && <span aria-hidden="true" style={{ opacity: 0.5 }}>·</span>}
            </span>
          ))}
        </div>
      </div>

      {/* ── Right panel — form ───────────────────────────────────────────── */}
      <div
        className="lp-form-panel"
        style={{
          flex: '1 1 45%',
          position: 'relative', zIndex: 1,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          padding: '48px clamp(24px, 4vw, 64px)',
          background: t.panelBlend,
          boxShadow: t.seamShadow,
          transition: EASE,
        }}
      >
        {/* Seam overlay — straddles the panel boundary (40px each side) and
            tints it with a feathered indigo wash so the halves blend. */}
        <div
          aria-hidden="true"
          className="lp-seam"
          style={{
            position: 'absolute', top: 0, bottom: 0, left: 0, width: '80px',
            transform: 'translateX(-50%)',
            background: t.seamTint,
            pointerEvents: 'none',
          }}
        />
        <form
          noValidate
          onSubmit={handleSubmit}
          aria-label="Sign in to SENTRO"
          style={{
            width: '100%', maxWidth: '380px',
            position: 'relative', zIndex: 1,
            padding: '36px 32px',
            background: t.cardBg,
            border: `1px solid ${t.cardBorder}`,
            borderRadius: '14px',
            boxShadow: t.cardShadow,
            transition: EASE,
          }}
        >
          <div style={anim(0.1)}>
            <h2 style={{
              fontFamily: FONTS.display, fontWeight: 600, fontSize: '1.65rem',
              color: t.text, marginBottom: '6px', transition: EASE,
            }}>
              Welcome back
            </h2>
            <p style={{
              fontFamily: FONTS.body, fontSize: '14px', color: t.muted,
              marginBottom: '28px', transition: EASE,
            }}>
              Sign in to continue to SENTRO
            </p>
          </div>

          <div style={anim(0.18)}>
            <SsoButton icon={GitHubMark} label="Continue with GitHub" theme={t} />
            <SsoButton icon={GoogleMark} label="Continue with Google" theme={t} />
          </div>

          {/* Divider */}
          <div aria-hidden="true" style={{
            display: 'flex', alignItems: 'center', gap: '14px',
            margin: '22px 0', ...anim(0.24),
          }}>
            <span style={{ flex: 1, height: '1px', background: t.border, transition: EASE }} />
            <span style={{ fontFamily: FONTS.body, fontSize: '12px', color: t.muted, transition: EASE }}>or</span>
            <span style={{ flex: 1, height: '1px', background: t.border, transition: EASE }} />
          </div>

          <div style={anim(0.3)}>
            <FloatingInput
              id="login-email" label="Email or username" type="text" autoComplete="username"
              value={email} onChange={(v) => { setEmail(v); if (errors.email) setErrors((p) => ({ ...p, email: undefined })) }}
              error={errors.email} theme={t}
            />
          </div>

          <div style={anim(0.36)}>
            <FloatingInput
              id="login-password" label="Password" type={showPw ? 'text' : 'password'} autoComplete="current-password"
              value={password} onChange={(v) => { setPassword(v); if (errors.password) setErrors((p) => ({ ...p, password: undefined })) }}
              error={errors.password} theme={t}
              trailing={
                <button
                  type="button"
                  onClick={() => setShowPw(!showPw)}
                  aria-label={showPw ? 'Hide password' : 'Show password'}
                  style={{
                    display: 'flex', padding: '6px', background: 'none', border: 'none',
                    color: t.muted, transition: 'color 0.2s ease',
                  }}
                  onMouseEnter={(e) => (e.currentTarget.style.color = COLORS.accentCyan)}
                  onMouseLeave={(e) => (e.currentTarget.style.color = t.muted)}
                >
                  {showPw ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              }
            />
          </div>

          {/* Remember / forgot row */}
          <div style={{
            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
            margin: '2px 0 24px', ...anim(0.42),
          }}>
            <label style={{
              display: 'flex', alignItems: 'center', gap: '8px',
              fontFamily: FONTS.body, fontSize: '13px', color: t.muted,
              userSelect: 'none', transition: EASE,
            }}>
              <input
                type="checkbox"
                checked={remember}
                onChange={(e) => setRemember(e.target.checked)}
                style={{
                  appearance: 'none', WebkitAppearance: 'none',
                  width: '16px', height: '16px', margin: 0,
                  border: `1.5px solid ${remember ? COLORS.accentCyan : t.border}`,
                  borderRadius: '4px',
                  background: remember
                    ? `${COLORS.accentCyan} url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16'%3E%3Cpath d='M4 8.5l2.5 2.5L12 5' fill='none' stroke='%23070B1A' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E") center/12px no-repeat`
                    : 'transparent',
                  transition: 'all 0.2s ease',
                }}
              />
              Remember me
            </label>
            <a
              href="#forgot"
              onClick={(e) => e.preventDefault()}
              style={{
                fontFamily: FONTS.body, fontSize: '13px',
                color: COLORS.accentCyan, textDecoration: 'none',
              }}
              onMouseEnter={(e) => (e.currentTarget.style.textDecoration = 'underline')}
              onMouseLeave={(e) => (e.currentTarget.style.textDecoration = 'none')}
            >
              Forgot password?
            </a>
          </div>

          {/* Server-side error */}
          {formError && (
            <div role="alert" style={{
              fontFamily: FONTS.body, fontSize: '13px', color: COLORS.alertRed,
              background: mode === 'light' ? 'rgba(239,68,68,0.06)' : 'rgba(239,68,68,0.10)',
              border: `1px solid rgba(239,68,68,0.35)`,
              borderRadius: '8px', padding: '10px 14px', marginBottom: '16px',
            }}>
              {formError}
            </div>
          )}

          {/* Submit */}
          <div style={anim(0.48)}>
            <button
              type="submit"
              disabled={loading}
              aria-busy={loading}
              style={{
                width: '100%', height: '48px',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                fontFamily: FONTS.body, fontSize: '15px', fontWeight: 600,
                color: '#ffffff',
                background: `linear-gradient(135deg, ${COLORS.accentCyan} 0%, ${COLORS.accentBlue} 100%)`,
                border: 'none', borderRadius: '8px',
                cursor: loading ? 'wait' : undefined,
                transition: 'box-shadow 0.25s ease, transform 0.2s ease, opacity 0.2s ease',
                opacity: loading ? 0.85 : 1,
              }}
              onMouseEnter={(e) => {
                if (loading) return
                e.currentTarget.style.boxShadow = '0 0 24px rgba(0,229,255,0.4), 0 0 48px rgba(59,107,245,0.2)'
                e.currentTarget.style.transform = 'translateY(-1px)'
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.boxShadow = 'none'
                e.currentTarget.style.transform = 'translateY(0)'
              }}
              onMouseDown={(e) => { if (!loading) e.currentTarget.style.transform = 'scale(0.98)' }}
              onMouseUp={(e) => { if (!loading) e.currentTarget.style.transform = 'translateY(-1px)' }}
            >
              {loading
                ? <span aria-hidden="true" style={{
                    width: '18px', height: '18px', borderRadius: '50%',
                    border: '2px solid rgba(255,255,255,0.35)', borderTopColor: '#ffffff',
                    animation: 'lp-spin 0.7s linear infinite',
                  }} />
                : 'Sign in'}
            </button>
          </div>

          {/* Footer */}
          <p style={{
            fontFamily: FONTS.body, fontSize: '13px', color: t.muted,
            textAlign: 'center', marginTop: '24px', transition: EASE, ...anim(0.54),
          }}>
            Don&apos;t have an account?{' '}
            <a
              href={APP_URL}
              style={{ color: COLORS.accentCyan, textDecoration: 'none', fontWeight: 500 }}
              onMouseEnter={(e) => (e.currentTarget.style.textDecoration = 'underline')}
              onMouseLeave={(e) => (e.currentTarget.style.textDecoration = 'none')}
            >
              Get Access
            </a>
          </p>
        </form>
      </div>

      {/* ── Success pulse — the "secured" moment ─────────────────────────── */}
      {pulse && (
        <div aria-hidden="true" style={{
          position: 'fixed', inset: 0, zIndex: 60, pointerEvents: 'none',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
        }}>
          <div style={{
            position: 'absolute', inset: 0, background: COLORS.accentCyan,
            animation: 'lp-wash 0.9s ease-out forwards',
          }} />
          <div style={{
            width: '20vmax', height: '20vmax', borderRadius: '50%',
            border: `2px solid ${COLORS.accentCyan}`,
            boxShadow: `0 0 40px ${COLORS.glowCyan}`,
            animation: 'lp-ripple 0.9s ease-out forwards',
          }} />
        </div>
      )}

      <style>{`
        @keyframes lp-rise {
          from { opacity: 0; transform: translateY(20px); }
          to   { opacity: 1; transform: translateY(0); }
        }
        @keyframes lp-spin { to { transform: rotate(360deg); } }
        @keyframes lp-ripple {
          from { transform: scale(0.2); opacity: 0.9; }
          to   { transform: scale(6);   opacity: 0; }
        }
        @keyframes lp-wash {
          0%   { opacity: 0; }
          25%  { opacity: 0.12; }
          100% { opacity: 0; }
        }
        @keyframes lp-drift {
          from { background-position: 0 0; }
          to   { background-position: 0 56px; }
        }
        .lp-grid-drift { animation: lp-drift 14s linear infinite; }

        .login-page a:focus-visible,
        .login-page button:focus-visible,
        .login-page input:focus-visible {
          outline: none;
          box-shadow: 0 0 0 2px rgba(0,229,255,0.55), 0 0 12px rgba(0,229,255,0.25) !important;
        }

        @media (max-width: 1024px) {
          .lp-brand { flex: 0 0 42% !important; }
        }
        @media (max-width: 768px) {
          .login-page { flex-direction: column; }
          .lp-brand {
            flex: 0 0 auto !important;
            padding: 84px 24px 28px !important;
            min-height: 0;
          }
          .lp-brand-copy h1 { display: none; }
          .lp-trust { display: none !important; }
          .lp-form-panel { padding: 28px 20px 48px !important; box-shadow: none !important; background: ${t.panelBg} !important; }
          .lp-seam { display: none; }
        }
      `}</style>
    </div>
  )
}
