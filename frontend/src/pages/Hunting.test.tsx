import { fireEvent, render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router'
import { beforeEach, describe, expect, it } from 'vitest'
import { resetDemoCatalog } from '../services/demoCatalog.ts'
import { resetDemoIncidents } from '../services/demoIncidents.ts'
import { HuntingPage } from './HuntingPage.tsx'
import { Incidents } from './Incidents.tsx'

function renderHunt() {
  return render(
    <MemoryRouter initialEntries={['/hunting']}>
      <Routes>
        <Route path="hunting" element={<HuntingPage />} />
        <Route path="incidents" element={<Incidents />} />
      </Routes>
    </MemoryRouter>,
  )
}

describe('hunt promotion', () => {
  beforeEach(() => {
    resetDemoIncidents()
    resetDemoCatalog()
  })

  it('adds an incident from a selected hunt result', async () => {
    renderHunt()
    expect(
      await screen.findByRole('button', { name: /Suspicious PowerShell/ }),
    ).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Run hunt' }))

    const checkboxes = await screen.findAllByRole('checkbox', {
      name: /Select 100200/,
    })
    const checkbox = checkboxes[0]
    if (!checkbox) throw new Error('Expected a hunt result')
    fireEvent.click(checkbox)
    fireEvent.click(screen.getByRole('button', { name: 'Promote to incident' }))
    fireEvent.click(screen.getByRole('button', { name: 'Create incident' }))

    expect(await screen.findByText('INC-0001')).toBeInTheDocument()
    expect(screen.getByText('3 incidents · 1 critical')).toBeInTheDocument()
  })
})
