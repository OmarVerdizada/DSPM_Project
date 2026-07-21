// URL of the DSPM console (FastAPI app). Override at build/dev time with
// VITE_APP_URL, e.g. VITE_APP_URL=https://console.sentro.io npm run build.
// Production builds are served BY the console itself, so default to
// same-origin ('' -> relative /api/... calls); an absolute localhost URL
// breaks login when the page is opened via 127.0.0.1 (CSP connect-src 'self').
// The Vite dev server (:5173) still needs the absolute console URL.
export const APP_URL = import.meta.env.VITE_APP_URL ?? (import.meta.env.DEV ? 'http://localhost:8000' : '')
