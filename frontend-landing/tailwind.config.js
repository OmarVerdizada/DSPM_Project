/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        bg: {
          deep: '#060914',
          dark: '#0A0E1A',
          surface: '#0F1629',
          card: '#111d3c',
        },
        blue: {
          primary: '#1B3A6B',
          accent: '#2563EB',
          glow: '#3B82F6',
          cyan: '#38BDF8',
          ring: '#5b8cff',
          light: '#9fc2ff',
        },
        text: {
          primary: '#E2E8F0',
          secondary: '#94A3B8',
          muted: '#64748B',
        },
      },
      fontFamily: {
        display: ['Audiowide', 'sans-serif'],
        body: ['Inter', 'sans-serif'],
        label: ['Rajdhani', 'sans-serif'],
      },
      animation: {
        'float-slow': 'float 8s ease-in-out infinite',
        'float-mid': 'float 6s ease-in-out infinite 1s',
        'pulse-glow': 'pulseGlow 3s ease-in-out infinite',
        'scroll-bounce': 'scrollBounce 2s ease-in-out infinite',
      },
      keyframes: {
        float: {
          '0%, 100%': { transform: 'translateY(0px)' },
          '50%': { transform: 'translateY(-24px)' },
        },
        pulseGlow: {
          '0%, 100%': { opacity: '0.4', transform: 'scale(1)' },
          '50%': { opacity: '0.8', transform: 'scale(1.05)' },
        },
        scrollBounce: {
          '0%, 100%': { transform: 'translateY(0)', opacity: '1' },
          '50%': { transform: 'translateY(8px)', opacity: '0.5' },
        },
      },
      backdropBlur: {
        xs: '2px',
      },
    },
  },
  plugins: [],
}
