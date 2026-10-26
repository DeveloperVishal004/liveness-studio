import { useEffect, useState } from 'react'

export const ROUTES = ['/', '/pipeline', '/integrity', '/lab', '/analytics', '/diagnostics'] as const
export type Route = (typeof ROUTES)[number]

function current(): Route {
  const p = window.location.pathname.replace(/\/+$/, '') || '/'
  return (ROUTES as readonly string[]).includes(p) ? (p as Route) : '/'
}

/** Tiny history-API router. The access token lives in the URL fragment, which is preserved across navigation. */
export function navigate(to: Route) {
  if (current() === to) return
  window.history.pushState({}, '', to + window.location.hash)
  window.dispatchEvent(new PopStateEvent('popstate'))
}

export function useRoute(): Route {
  const [r, setR] = useState<Route>(current)
  useEffect(() => {
    const on = () => setR(current())
    window.addEventListener('popstate', on)
    return () => window.removeEventListener('popstate', on)
  }, [])
  return r
}
