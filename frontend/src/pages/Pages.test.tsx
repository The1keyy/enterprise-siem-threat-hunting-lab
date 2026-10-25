import { cleanup, render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { afterEach, describe, expect, it } from 'vitest'
import { AutomationPage } from './AutomationPage.tsx'
import { DetectionsPage } from './DetectionsPage.tsx'
import { EntitiesPage } from './EntitiesPage.tsx'
import { HealthPage } from './HealthPage.tsx'
import { HuntingPage } from './HuntingPage.tsx'
import { Incidents } from './Incidents.tsx'
import { MitrePage } from './MitrePage.tsx'
import { SettingsPage } from './SettingsPage.tsx'
import { SocOverview } from './SocOverview.tsx'
import { SourcesPage } from './SourcesPage.tsx'

const pages = [
  { element: <SocOverview />, heading: 'SOC Overview' },
  { element: <Incidents />, heading: 'Incidents' },
  { element: <HuntingPage />, heading: 'Threat Hunting' },
  { element: <EntitiesPage />, heading: 'Entities' },
  { element: <DetectionsPage />, heading: 'Detections' },
  { element: <MitrePage />, heading: 'MITRE ATT&CK' },
  { element: <AutomationPage />, heading: 'Automation' },
  { element: <SourcesPage />, heading: 'Data Sources' },
  { element: <HealthPage />, heading: 'System Health' },
  { element: <SettingsPage />, heading: 'Settings' },
]

describe('sidebar pages', () => {
  afterEach(() => {
    cleanup()
  })

  it.each(pages)('renders $heading', async ({ element, heading }) => {
    render(<MemoryRouter>{element}</MemoryRouter>)
    expect(
      await screen.findByRole('heading', { name: heading }),
    ).toBeInTheDocument()
  })

  it('links a user name to the profile route', async () => {
    render(
      <MemoryRouter>
        <EntitiesPage />
      </MemoryRouter>,
    )
    const links = await screen.findAllByRole('link', { name: 'sf-test-alice' })
    expect(links.length).toBeGreaterThan(0)
    for (const link of links) {
      expect(link).toHaveAttribute('href', '/entities/users/sf-test-alice')
    }
  })
})
