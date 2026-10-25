import type { LucideIcon } from 'lucide-react'
import {
  Activity,
  ClipboardList,
  Database,
  Grid2x2,
  LayoutDashboard,
  Library,
  Search,
  Settings,
  Users,
  Workflow,
} from 'lucide-react'

export type NavItem = {
  to: string
  label: string
  step: number
  end: boolean
  icon: LucideIcon
}

export const NAV_ITEMS: readonly NavItem[] = [
  { to: '/', label: 'SOC Overview', step: 4, end: true, icon: LayoutDashboard },
  {
    to: '/incidents',
    label: 'Incidents',
    step: 5,
    end: false,
    icon: ClipboardList,
  },
  {
    to: '/hunting',
    label: 'Threat Hunting',
    step: 6,
    end: false,
    icon: Search,
  },
  { to: '/entities', label: 'Entities', step: 6, end: false, icon: Users },
  {
    to: '/detections',
    label: 'Detections',
    step: 6,
    end: false,
    icon: Library,
  },
  { to: '/mitre', label: 'MITRE ATT&CK', step: 6, end: false, icon: Grid2x2 },
  {
    to: '/automation',
    label: 'Automation',
    step: 6,
    end: false,
    icon: Workflow,
  },
  {
    to: '/sources',
    label: 'Data Sources',
    step: 6,
    end: false,
    icon: Database,
  },
  {
    to: '/health',
    label: 'System Health',
    step: 6,
    end: false,
    icon: Activity,
  },
  { to: '/settings', label: 'Settings', step: 6, end: false, icon: Settings },
]
