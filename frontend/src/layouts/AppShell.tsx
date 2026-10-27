import { useState } from 'react'
import { clsx } from 'clsx'
import { PanelLeftClose, PanelLeftOpen } from 'lucide-react'
import { Link, NavLink, Outlet, useLocation } from 'react-router'
import { TourBar } from '../components/TourBar.tsx'
import { useAuth } from '../hooks/useAuth.ts'
import { DemoBanner } from '../components/DemoBanner.tsx'
import { ToastViewport } from '../components/ToastViewport.tsx'
import { useDataMode } from '../hooks/useDataMode.ts'
import { useServiceHealth } from '../hooks/useServiceHealth.ts'
import { useDemoNotice } from '../services/demoNotice.ts'
import { NAV_ITEMS } from '../navigation.ts'

export function AppShell() {
  const [collapsed, setCollapsed] = useState(false)
  const mode = useDataMode()
  const backend = useServiceHealth()
  const sawDemo = useDemoNotice()
  const auth = useAuth()
  const showDemo = mode === 'demo' || backend === 'demo' || sawDemo
  const pill =
    backend === 'down' && mode === 'live' && !showDemo
      ? 'API DOWN'
      : backend === 'loading' && mode === 'live' && !showDemo
        ? 'CHECKING'
        : showDemo
          ? 'DEMO'
          : 'LIVE'
  const { pathname } = useLocation()
  const current = NAV_ITEMS.find((item) =>
    item.end
      ? pathname === item.to
      : pathname === item.to || pathname.startsWith(`${item.to}/`),
  )
  const title =
    pathname === '/dev/components'
      ? 'Components'
      : pathname === '/about'
        ? 'About'
        : pathname === '/tour'
          ? 'Tour'
          : (current?.label ?? 'SentinelForge')

  return (
    <div className="flex min-h-screen flex-col bg-bg text-text">
      {mode === 'demo' || sawDemo || backend === 'demo' ? <DemoBanner /> : null}
      <div className="flex min-h-0 flex-1">
        <aside
          className={clsx(
            'flex shrink-0 flex-col border-r border-border bg-surface',
            collapsed ? 'w-14' : 'w-56 max-md:w-14',
          )}
        >
          <div className="flex h-12 items-center border-b border-border px-3">
            <span
              className={clsx(
                'truncate text-sm font-semibold',
                collapsed ? 'sr-only' : 'max-md:sr-only',
              )}
            >
              SentinelForge
            </span>
            <span
              className={clsx(
                'text-sm font-semibold',
                !collapsed && 'hidden max-md:inline',
              )}
              aria-hidden="true"
            >
              SF
            </span>
          </div>
          <nav aria-label="Primary" className="flex flex-1 flex-col gap-1 p-2">
            {NAV_ITEMS.map((item) => {
              const Icon = item.icon
              return (
                <NavLink
                  key={item.to}
                  to={item.to}
                  end={item.end}
                  title={item.label}
                  className={({ isActive }) =>
                    clsx(
                      'flex items-center gap-3 rounded-md px-2 py-2 text-sm transition-colors duration-150',
                      collapsed ? 'justify-center' : 'max-md:justify-center',
                      isActive
                        ? 'bg-surface-2 text-accent shadow-[inset_2px_0_0_0_var(--color-accent)]'
                        : 'text-text-muted hover:bg-surface-2 hover:text-text',
                    )
                  }
                >
                  <Icon aria-hidden="true" size={18} />
                  <span
                    className={clsx(
                      'truncate',
                      collapsed ? 'sr-only' : 'max-md:sr-only',
                    )}
                  >
                    {item.label}
                  </span>
                </NavLink>
              )
            })}
          </nav>
          <div className="flex flex-col gap-1 border-t border-border p-2">
            {import.meta.env.DEV ? (
              <NavLink
                to="/dev/components"
                className={({ isActive }) =>
                  clsx(
                    'rounded-md px-2 py-2 text-xs text-text-muted hover:bg-surface-2 hover:text-text',
                    collapsed ? 'sr-only' : 'max-md:sr-only',
                    isActive && 'text-accent',
                  )
                }
              >
                Components
              </NavLink>
            ) : null}
            <button
              type="button"
              className="flex items-center justify-center rounded-md p-2 text-text-muted hover:bg-surface-2 hover:text-text"
              aria-expanded={!collapsed}
              aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
              onClick={() => setCollapsed((value) => !value)}
            >
              {collapsed ? (
                <PanelLeftOpen aria-hidden="true" size={18} />
              ) : (
                <PanelLeftClose aria-hidden="true" size={18} />
              )}
            </button>
          </div>
        </aside>
        <div className="flex min-w-0 flex-1 flex-col">
          <header className="flex h-12 items-center justify-between gap-3 border-b border-border bg-surface px-4 sm:px-6">
            <p className="min-w-0 flex-1 truncate text-xs font-medium tracking-wide text-text-muted uppercase">
              {title}
            </p>
            <div className="flex items-center gap-2 sm:gap-3">
              {mode === 'demo' ? (
                <Link
                  to="/tour"
                  className="rounded-md border border-border px-2 py-1 text-xs text-text transition-colors duration-150 hover:bg-surface-2"
                >
                  <span className="sm:hidden">Tour</span>
                  <span className="hidden sm:inline">Take the tour</span>
                </Link>
              ) : null}
              <Link
                to="/about"
                className="rounded-md border border-border px-2 py-1 text-xs text-text transition-colors duration-150 hover:bg-surface-2"
              >
                About
              </Link>
              <span
                className={clsx(
                  'rounded-full border px-2 py-0.5 text-xs font-medium',
                  pill === 'DEMO'
                    ? 'border-medium/40 bg-medium/15 text-medium'
                    : pill === 'LIVE'
                      ? 'border-ok/40 bg-ok/15 text-ok'
                      : 'border-border bg-surface-2 text-text-muted',
                )}
              >
                {pill}
              </span>
              <span className="hidden text-sm text-text-muted sm:inline">
                {auth.username ?? 'Analyst'}
              </span>
              {mode === 'live' ? (
                <button
                  type="button"
                  className="rounded-md border border-border px-2 py-1 text-xs text-text"
                  onClick={() => void auth.logout()}
                >
                  Logout
                </button>
              ) : null}
            </div>
          </header>
          <main className="min-w-0 flex-1 p-4 sm:p-6">
            <Outlet />
          </main>
          <ToastViewport />
        </div>
      </div>
      <TourBar />
    </div>
  )
}
