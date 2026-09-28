/* eslint-disable react-refresh/only-export-components */
import { createContext, useContext, useEffect, useState } from "react"

export type Theme = "dark" | "light" | "system"

type ThemeProviderState = {
  theme: Theme
  resolved: "dark" | "light"
  setTheme: (theme: Theme) => void
}

const ThemeProviderContext = createContext<ThemeProviderState>({
  theme: "system",
  resolved: "light",
  setTheme: () => null,
})

const media = () => window.matchMedia("(prefers-color-scheme: dark)")

function readTheme(storageKey: string, fallback: Theme): Theme {
  try {
    const v = localStorage.getItem(storageKey)
    if (v === "dark" || v === "light" || v === "system") return v
  } catch {
    // ignore
  }
  return fallback
}

/** Applies the theme class to <html>; also called before the first render. */
export function applyTheme(theme: Theme): "dark" | "light" {
  const resolved = theme === "system" ? (media().matches ? "dark" : "light") : theme
  const root = document.documentElement
  root.classList.remove("light", "dark")
  root.classList.add(resolved)
  const meta = document.querySelector('meta[name="theme-color"]')
  if (meta) meta.setAttribute("content", resolved === "dark" ? "#0a1520" : "#edf2f5")
  return resolved
}

export function initialTheme(storageKey = "ui-theme", fallback: Theme = "system") {
  return applyTheme(readTheme(storageKey, fallback))
}

export function ThemeProvider({
  children,
  defaultTheme = "system",
  storageKey = "ui-theme",
}: {
  children: React.ReactNode
  defaultTheme?: Theme
  storageKey?: string
}) {
  const [theme, setThemeState] = useState<Theme>(() => readTheme(storageKey, defaultTheme))
  const [resolved, setResolved] = useState<"dark" | "light">(() => applyTheme(readTheme(storageKey, defaultTheme)))

  useEffect(() => {
    setResolved(applyTheme(theme))
    if (theme !== "system") return
    // Follow OS changes live while in "system" mode.
    const mql = media()
    const onChange = () => setResolved(applyTheme("system"))
    mql.addEventListener("change", onChange)
    return () => mql.removeEventListener("change", onChange)
  }, [theme])

  const setTheme = (t: Theme) => {
    try {
      localStorage.setItem(storageKey, t)
    } catch {
      // ignore
    }
    setThemeState(t)
  }

  return <ThemeProviderContext.Provider value={{ theme, resolved, setTheme }}>{children}</ThemeProviderContext.Provider>
}

export const useTheme = () => useContext(ThemeProviderContext)
