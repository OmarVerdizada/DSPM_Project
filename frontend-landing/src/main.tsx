import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App'
import LoginPage from './components/Login/LoginPage'
import './styles/globals.css'
import './styles/fonts.css'

// Minimal routing: /login renders the login page, everything else the landing.
const page = window.location.pathname === '/login' ? <LoginPage /> : <App />

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>{page}</React.StrictMode>
)
