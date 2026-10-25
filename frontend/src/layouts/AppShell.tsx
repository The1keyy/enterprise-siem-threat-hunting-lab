import { useState } from 'react'
import { clsx } from 'clsx'
import { PanelLeftClose, PanelLeftOpen } from 'lucide-react'
import { NavLink, Outlet, useLocation } from 'react-router'
import { DemoBanner } from '../components/DemoBanner.tsx'
import { ToastViewport } from '../components/ToastViewport.tsx'
import { useDataMode } from '../hooks/useDataMode.ts'
import { NAV_ITEMS } from '../navigation.ts'

export function AppShell() {
  const [collapsed, setCollapsed] = useState(false)
  const mode = useDataMode()
  const { pathname } = useLocation()
  const current = NAV_ITEMS.find((item) =>
    item.end
      ? pathname === item.to
      : pathname === item.to || pathname.startsWith(`${item.to}/`),
  )
  const title =
    pathname === '/dev/components'
      ? 'Components'
      : (current?.label ?? 'SentinelForge')

  return (
    <div className="flex min-h-screen flex-col bg-bg text-text">
      {mode === 'demo' ? <DemoBanner /> : null}
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
                      'flex items-center gap-3 rounded-md px-2 py-2 text-sm',
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
          <header className="flex h-12 items-center justify-between gap-3 border-b border-border bg-surface px-4">
            <p className="truncate text-sm font-medium text-text">{title}</p>
            <div className="flex items-center gap-3">
              <span
                className={clsx(
                  'rounded-full border px-2 py-0.5 text-xs font-medium',
                  mode === 'demo'
                    ? 'border-medium/40 bg-medium/15 text-medium'
                    : 'border-ok/40 bg-ok/15 text-ok',
                )}
              >
                {mode === 'demo' ? 'DEMO' : 'LIVE'}
              </span>
              <span className="text-sm text-text-muted">Analyst</span>
            </div>
          </header>
          <main className="flex-1 p-4">
            <Outlet />
          </main>
          <ToastViewport />
        </div>
      </div>
    </div>
  )
}
