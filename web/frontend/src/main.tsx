import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './fonts.css'
import './index.css'
import App from './App.tsx'
import { initialTheme } from './components/theme-provider'

// Set the theme class before the first paint (no inline script: the server's
// CSP forbids it).
initialTheme()

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
