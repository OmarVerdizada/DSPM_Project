export const COLORS = {
  navyDeep: '#070B1A',
  navyMid: '#0F1535',
  navyLight: '#1A2250',
  cloudWhite: '#E8ECF4',
  cloudMuted: '#8891A5',
  accentCyan: '#00E5FF',
  accentBlue: '#3B6BF5',
  accentPurple: '#7B5BF2',
  glowCyan: 'rgba(0, 229, 255, 0.15)',
  glowPurple: 'rgba(123, 91, 242, 0.10)',
  alertOrange: '#F59E0B',
  alertRed: '#EF4444',
  alertGreen: '#10B981',
} as const

export const FONTS = {
  display: "'Space Grotesk', sans-serif",
  body: "'Inter', sans-serif",
  mono: "'JetBrains Mono', monospace",
} as const

export const BREAKPOINTS = {
  mobile: 768,
  tablet: 1024,
  desktop: 1440,
} as const

export const isMobile = (): boolean =>
  typeof window !== 'undefined' && window.innerWidth < BREAKPOINTS.mobile

export const prefersReducedMotion = (): boolean =>
  typeof window !== 'undefined' &&
  window.matchMedia('(prefers-reduced-motion: reduce)').matches
