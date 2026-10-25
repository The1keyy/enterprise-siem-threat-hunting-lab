import { render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router'
import { describe, expect, it } from 'vitest'
import { AppShell } from '../layouts/AppShell.tsx'
import { SocOverview } from './SocOverview.tsx'

function renderOverview() {
  return render(
    <MemoryRouter>
      <Routes>
        <Route element={<AppShell />}>
          <Route index element={<SocOverview />} />
        </Route>
      </Routes>
    </MemoryRouter>,
  )
}

describe('SOC Overview', () => {
  it('renders the DEMO DATA banner', async () => {
    renderOverview()
    expect(
      await screen.findByText('DEMO DATA — fixtures only, not real telemetry'),
    ).toBeInTheDocument()
  })

  it('shows an em dash when mean time to investigate is null', async () => {
    renderOverview()
    const label = await screen.findByText('Mean Time to Investigate')
    const card = label.closest('section')
    expect(card).not.toBeNull()
    expect(card).toHaveTextContent('—')
    expect(card).toHaveTextContent('Not enough data yet')
  })
})
