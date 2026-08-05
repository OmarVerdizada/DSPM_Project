import { useEffect, useRef, useState } from 'react'
import { gsap } from 'gsap'
import { ScrollTrigger } from 'gsap/ScrollTrigger'
import { COLORS, FONTS } from '../../utils/constants'
import { lerp } from '../../utils/lerp'

gsap.registerPlugin(ScrollTrigger)

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
const BAR_VALUES = [42, 67, 55, 80, 73, 90, 85, 92, 78, 88, 95, 100]
const SPARKLINE_DATA = [60, 75, 65, 80, 72, 85, 90]

interface Alert {
  icon: React.ReactNode
  text: string
  time: string
  color: string
}

// Alert mini icons use inlined lucide geometry (24x24) rendered at 14px.
function FingerprintIcon({ color }: { color: string }) {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M12 10a2 2 0 0 0-2 2c0 1.02-.1 2.51-.26 4"/>
      <path d="M14 13.12c0 2.38 0 6.38-1 8.88"/>
      <path d="M17.29 21.02c.12-.6.43-2.3.5-3.02"/>
      <path d="M2 12a10 10 0 0 1 18-6"/>
      <path d="M2 16h.01"/>
      <path d="M21.8 16c.2-2 .131-5.354 0-6"/>
      <path d="M5 19.5C5.5 18 6 15 6 12a6 6 0 0 1 .34-2"/>
      <path d="M8.65 22c.21-.66.45-1.32.57-2"/>
      <path d="M9 6.8a6 6 0 0 1 9 5.2v2"/>
    </svg>
  )
}

function UsersIcon({ color }: { color: string }) {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/>
      <circle cx="9" cy="7" r="4"/>
      <path d="M22 21v-2a4 4 0 0 0-3-3.87"/>
      <path d="M16 3.13a4 4 0 0 1 0 7.75"/>
    </svg>
  )
}

function KeyRoundIcon({ color }: { color: string }) {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M2.586 17.414A2 2 0 0 0 2 18.828V21a1 1 0 0 0 1 1h3a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h1a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h.172a2 2 0 0 0 1.414-.586l.814-.814a6.5 6.5 0 1 0-4-4z"/>
      <circle cx="16.5" cy="7.5" r=".5" fill={color}/>
    </svg>
  )
}

function CreditCardIcon({ color }: { color: string }) {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <rect width="20" height="14" x="2" y="5" rx="2"/>
      <line x1="2" x2="22" y1="10" y2="10"/>
    </svg>
  )
}

function ShieldAlertIcon({ color }: { color: string }) {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/>
      <path d="M12 8v4"/>
      <path d="M12 16h.01"/>
    </svg>
  )
}

const ALERTS: Alert[] = [
  { icon: <FingerprintIcon color={COLORS.alertOrange} />, text: 'Sensitive employee data detected — HR_Payroll_2023.xlsx', time: '2 min ago', color: COLORS.alertOrange },
  { icon: <UsersIcon color={COLORS.accentCyan} />, text: 'Broad access found — finance_shared.xlsx', time: '5 min ago', color: COLORS.accentCyan },
  { icon: <KeyRoundIcon color={COLORS.accentPurple} />, text: 'Private key detected — backup_config.pem', time: '8 min ago', color: COLORS.accentPurple },
  { icon: <CreditCardIcon color={COLORS.alertGreen} />, text: 'PCI DSS data detected — payments_2026.xlsx', time: '12 min ago', color: COLORS.alertGreen },
  { icon: <ShieldAlertIcon color={COLORS.alertRed} />, text: 'Critical file risk identified — customer_export.csv', time: '18 min ago', color: COLORS.alertRed },
]

function Sparkline({ data }: { data: number[] }) {
  const max = Math.max(...data)
  const w = 64
  const h = 24
  const points = data.map((v, i) => {
    const x = (i / (data.length - 1)) * w
    const y = h - (v / max) * h
    return `${x},${y}`
  }).join(' ')

  return (
    <svg width={w} height={h} aria-hidden="true">
      <polyline
        points={points}
        fill="none"
        stroke={COLORS.accentCyan}
        strokeWidth="1.5"
        strokeLinejoin="round"
        opacity="0.7"
      />
    </svg>
  )
}

function StatCard({ value, label, accent, isPercent = false, animateFrom = 0 }: {
  value: number
  label: string
  accent: string
  isPercent?: boolean
  animateFrom?: number
}) {
  const valueRef = useRef<HTMLSpanElement>(null)
  const cardRef = useRef<HTMLDivElement>(null)
  const animatedRef = useRef(false)

  useEffect(() => {
    if (!cardRef.current) return

    ScrollTrigger.create({
      trigger: cardRef.current,
      start: 'top 85%',
      onEnter: () => {
        if (animatedRef.current) return
        animatedRef.current = true
        const obj = { val: animateFrom }
        gsap.to(obj, {
          val: value,
          duration: 1.8,
          ease: 'power2.out',
          onUpdate: () => {
            if (valueRef.current) {
              const v = Math.round(obj.val)
              valueRef.current.textContent = isPercent
                ? `${(obj.val).toFixed(1)}%`
                : v.toLocaleString()
            }
          },
        })
      },
    })
  }, [value, animateFrom, isPercent])

  return (
    <div
      ref={cardRef}
      style={{
        background: `${COLORS.navyMid}`,
        border: `1px solid ${COLORS.navyLight}`,
        borderRadius: '10px',
        padding: '20px',
        flex: 1,
        minWidth: 0,
      }}
    >
      <div
        style={{
          fontFamily: FONTS.mono,
          fontSize: '32px',
          fontWeight: 500,
          color: accent,
          lineHeight: 1,
          marginBottom: '6px',
        }}
      >
        <span ref={valueRef}>{animateFrom.toLocaleString()}</span>
      </div>
      <div
        style={{
          fontFamily: FONTS.body,
          fontSize: '12px',
          color: COLORS.cloudMuted,
          marginBottom: '10px',
          letterSpacing: '0.04em',
        }}
      >
        {label}
      </div>
      <Sparkline data={SPARKLINE_DATA} />
    </div>
  )
}

function CircularProgress({ value }: { value: number }) {
  const radius = 28
  const circumference = 2 * Math.PI * radius
  const offset = circumference * (1 - value / 100)

  return (
    <svg width="70" height="70" viewBox="0 0 70 70" aria-hidden="true">
      <circle cx="35" cy="35" r={radius} fill="none" stroke={COLORS.navyLight} strokeWidth="4" />
      <circle
        cx="35"
        cy="35"
        r={radius}
        fill="none"
        stroke={COLORS.accentCyan}
        strokeWidth="4"
        strokeDasharray={circumference}
        strokeDashoffset={offset}
        strokeLinecap="round"
        transform="rotate(-90 35 35)"
        style={{ transition: 'stroke-dashoffset 1.5s ease' }}
      />
      <text x="35" y="40" textAnchor="middle" fontSize="13" fontFamily="'JetBrains Mono', monospace" fill={COLORS.accentCyan}>
        {value}%
      </text>
    </svg>
  )
}

function BarChart({ animated }: { animated: boolean }) {
  return (
    <div>
      <div
        style={{
          fontFamily: FONTS.mono,
          fontSize: '11px',
          color: COLORS.cloudMuted,
          letterSpacing: '0.1em',
          textTransform: 'uppercase',
          marginBottom: '20px',
        }}
      >
        Data Discovery Over Time
      </div>
      <div style={{ display: 'flex', alignItems: 'flex-end', gap: '6px', height: '120px' }}>
        {BAR_VALUES.map((v, i) => (
          <div
            key={i}
            style={{
              flex: 1,
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              gap: '4px',
              height: '100%',
              justifyContent: 'flex-end',
            }}
          >
            <div
              style={{
                width: '100%',
                height: animated ? `${v}%` : '0%',
                background: `linear-gradient(to top, ${COLORS.accentBlue}, ${COLORS.accentCyan})`,
                borderRadius: '3px 3px 0 0',
                transition: animated ? `height ${0.8 + i * 0.05}s ease` : 'none',
                boxShadow: `0 0 8px rgba(0,229,255,0.2)`,
              }}
            />
          </div>
        ))}
      </div>
      <div
        style={{
          display: 'flex',
          gap: '6px',
          marginTop: '6px',
        }}
      >
        {MONTHS.map((m) => (
          <div
            key={m}
            style={{
              flex: 1,
              fontFamily: FONTS.mono,
              fontSize: '8px',
              color: COLORS.cloudMuted,
              textAlign: 'center',
              letterSpacing: '0.02em',
            }}
          >
            {m}
          </div>
        ))}
      </div>
    </div>
  )
}

function AlertFeed({ visibleCount }: { visibleCount: number }) {
  return (
    <div>
      <div
        style={{
          fontFamily: FONTS.mono,
          fontSize: '11px',
          color: COLORS.cloudMuted,
          letterSpacing: '0.1em',
          textTransform: 'uppercase',
          marginBottom: '16px',
        }}
      >
        Recent Alerts
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
        {ALERTS.slice(0, visibleCount).map((alert, i) => (
          <div
            key={i}
            style={{
              display: 'flex',
              alignItems: 'flex-start',
              gap: '10px',
              padding: '10px 12px',
              background: `${alert.color}08`,
              border: `1px solid ${alert.color}25`,
              borderRadius: '7px',
              animation: i === visibleCount - 1 ? 'fadeSlideIn 0.3s ease' : 'none',
            }}
          >
            <span style={{ flexShrink: 0, marginTop: '1px' }}>{alert.icon}</span>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div
                style={{
                  fontFamily: FONTS.mono,
                  fontSize: '11px',
                  color: COLORS.cloudWhite,
                  lineHeight: 1.4,
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  whiteSpace: 'nowrap',
                }}
              >
                {alert.text}
              </div>
              <div
                style={{
                  fontFamily: FONTS.mono,
                  fontSize: '10px',
                  color: COLORS.cloudMuted,
                  marginTop: '2px',
                }}
              >
                {alert.time}
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

export default function LiveDashboard() {
  const sectionRef = useRef<HTMLElement>(null)
  const panelRef = useRef<HTMLDivElement>(null)
  const [barsAnimated, setBarsAnimated] = useState(false)
  const [alertCount, setAlertCount] = useState(0)
  const [tiltX, setTiltX] = useState(0)
  const [tiltY, setTiltY] = useState(0)
  const tiltRef = useRef({ x: 0, y: 0 })
  const rafRef = useRef<number>(0)

  useEffect(() => {
    if (!sectionRef.current) return

    const st = ScrollTrigger.create({
      trigger: sectionRef.current,
      start: 'top 70%',
      onEnter: () => {
        setBarsAnimated(true)
        let count = 0
        const addAlert = () => {
          count++
          setAlertCount(count)
          if (count < ALERTS.length) {
            setTimeout(addAlert, 400)
          }
        }
        setTimeout(addAlert, 600)
      },
    })

    return () => st.kill()
  }, [])

  useEffect(() => {
    const panel = panelRef.current
    if (!panel) return

    const onMouseMove = (e: MouseEvent) => {
      const rect = panel.getBoundingClientRect()
      const cx = rect.left + rect.width / 2
      const cy = rect.top + rect.height / 2
      tiltRef.current = {
        x: ((e.clientY - cy) / (rect.height / 2)) * 3,
        y: -((e.clientX - cx) / (rect.width / 2)) * 3,
      }
    }

    const onMouseLeave = () => {
      tiltRef.current = { x: 0, y: 0 }
    }

    const animate = () => {
      setTiltX((prev) => lerp(prev, tiltRef.current.x, 0.08))
      setTiltY((prev) => lerp(prev, tiltRef.current.y, 0.08))
      rafRef.current = requestAnimationFrame(animate)
    }
    rafRef.current = requestAnimationFrame(animate)

    panel.addEventListener('mousemove', onMouseMove)
    panel.addEventListener('mouseleave', onMouseLeave)

    return () => {
      cancelAnimationFrame(rafRef.current)
      panel.removeEventListener('mousemove', onMouseMove)
      panel.removeEventListener('mouseleave', onMouseLeave)
    }
  }, [])

  return (
    <section
      id="dashboard"
      ref={sectionRef}
      aria-label="Live dashboard preview"
      style={{
        padding: '120px 6vw',
        background: COLORS.navyDeep,
      }}
    >
      <div style={{ maxWidth: '1200px', margin: '0 auto' }}>
        {/* Section header */}
        <div style={{ textAlign: 'center', marginBottom: '56px' }}>
          <div style={{ fontFamily: FONTS.mono, fontSize: '12px', letterSpacing: '0.25em', textTransform: 'uppercase', color: COLORS.accentCyan, marginBottom: '12px' }}>
            LIVE MONITORING
          </div>
          <h2 style={{ fontFamily: FONTS.display, fontSize: 'clamp(1.6rem, 3vw, 40px)', fontWeight: 600, color: COLORS.cloudWhite }}>
            Your Posture, in Real Time
          </h2>
        </div>

        {/* Dashboard panel */}
        <div
          ref={panelRef}
          style={{
            background: 'rgba(15, 21, 53, 0.85)',
            backdropFilter: 'blur(20px)',
            WebkitBackdropFilter: 'blur(20px)',
            border: `1px solid ${COLORS.navyLight}`,
            borderRadius: '16px',
            overflow: 'hidden',
            transform: `perspective(1000px) rotateX(${tiltX}deg) rotateY(${tiltY}deg)`,
            transition: 'box-shadow 0.3s ease',
            boxShadow: `0 20px 60px rgba(0,0,0,0.5), 0 0 40px rgba(0,229,255,0.04)`,
            willChange: 'transform',
          }}
        >
          {/* Top bar */}
          <div
            style={{
              padding: '14px 20px',
              borderBottom: `1px solid ${COLORS.navyLight}`,
              display: 'flex',
              alignItems: 'center',
              gap: '12px',
              background: `${COLORS.navyMid}80`,
            }}
          >
            <div style={{ display: 'flex', gap: '6px' }}>
              {['#EF4444', '#F59E0B', '#10B981'].map((c, i) => (
                <div key={i} style={{ width: '10px', height: '10px', borderRadius: '50%', background: c, opacity: 0.8 }} />
              ))}
            </div>
            <span
              style={{
                fontFamily: FONTS.mono,
                fontSize: '12px',
                color: COLORS.cloudMuted,
                letterSpacing: '0.06em',
              }}
            >
              SENTRO // Live Posture Monitor
            </span>
            <div style={{ marginLeft: 'auto', display: 'flex', gap: '6px', alignItems: 'center' }}>
              <div style={{ width: '6px', height: '6px', borderRadius: '50%', background: COLORS.alertGreen, animation: 'shimmer 2s infinite' }} />
              <span style={{ fontFamily: FONTS.mono, fontSize: '10px', color: COLORS.alertGreen, letterSpacing: '0.05em' }}>LIVE</span>
            </div>
          </div>

          <div style={{ padding: '24px' }}>
            {/* Stat cards */}
            <div style={{ display: 'flex', gap: '16px', marginBottom: '28px', flexWrap: 'wrap' }}>
              <StatCard value={12847} label="Total Assets" accent={COLORS.accentCyan} />
              <StatCard value={3291} label="Sensitive Data Found" accent={COLORS.alertOrange} />
              <StatCard value={47} label="Policy Violations" accent={COLORS.alertRed} />
              <div
                style={{
                  background: COLORS.navyMid,
                  border: `1px solid ${COLORS.navyLight}`,
                  borderRadius: '10px',
                  padding: '20px',
                  flex: 1,
                  minWidth: '140px',
                  display: 'flex',
                  flexDirection: 'column',
                  alignItems: 'center',
                  justifyContent: 'center',
                  gap: '8px',
                }}
              >
                <CircularProgress value={barsAnimated ? 94 : 0} />
                <div style={{ fontFamily: FONTS.body, fontSize: '12px', color: COLORS.cloudMuted, letterSpacing: '0.04em' }}>
                  Posture Score
                </div>
              </div>
            </div>

            {/* Main area: chart + alerts */}
            <div style={{ display: 'flex', gap: '24px', flexWrap: 'wrap' }}>
              <div style={{ flex: '3', minWidth: '280px' }}>
                <BarChart animated={barsAnimated} />
              </div>
              <div style={{ flex: '2', minWidth: '240px' }}>
                <AlertFeed visibleCount={alertCount} />
              </div>
            </div>
          </div>
        </div>
      </div>

      <style>{`
        @keyframes fadeSlideIn {
          from { opacity: 0; transform: translateY(10px); }
          to { opacity: 1; transform: translateY(0); }
        }
      `}</style>
    </section>
  )
}
