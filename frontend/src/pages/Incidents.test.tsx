import { fireEvent, render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { incidentFixtures, storyIncidentId } from '../fixtures/incidents.ts'
import { DRY_RUN_MESSAGE } from '../types/incident.ts'
import { IncidentDetail } from './IncidentDetail.tsx'
import { Incidents } from './Incidents.tsx'
import * as api from '../services/api.ts'
import { resetDemoIncidents } from '../services/demoIncidents.ts'

function renderIncidents(path = '/incidents') {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="incidents" element={<Incidents />} />
        <Route path="incidents/:id" element={<IncidentDetail />} />
      </Routes>
    </MemoryRouter>,
  )
}

describe('incidents queue', () => {
  beforeEach(() => {
    resetDemoIncidents()
  })

  it('narrows the table when a severity filter is applied', async () => {
    renderIncidents()
    const critical = incidentFixtures.filter((item) => item.severity === 'critical')
    expect(await screen.findByText(storyIncidentId)).toBeInTheDocument()
    expect(
      screen.getByText(
        `${incidentFixtures.length} incidents · ${critical.length} critical`,
      ),
    ).toBeInTheDocument()

    fireEvent.click(screen.getByRole('checkbox', { name: 'Critical' }))

    expect(
      await screen.findByText(
        `${critical.length} ${critical.length === 1 ? 'incident' : 'incidents'} · ${critical.length} critical`,
      ),
    ).toBeInTheDocument()
    expect(screen.getByText(storyIncidentId)).toBeInTheDocument()
    for (const incident of incidentFixtures) {
      if (incident.severity === 'critical') continue
      expect(screen.queryByText(incident.id)).not.toBeInTheDocument()
    }
  })
})

describe('investigation response actions', () => {
  beforeEach(() => {
    resetDemoIncidents()
    vi.restoreAllMocks()
  })

  it('shows a confirm modal and does not execute the action', async () => {
    const execute = vi.spyOn(api, 'executeResponseAction')
    renderIncidents(`/incidents/${storyIncidentId}`)

    fireEvent.click(
      await screen.findByRole('button', { name: 'Isolate lab endpoint' }),
    )

    const dialog = screen.getByRole('dialog')
    expect(dialog).toHaveTextContent('Isolate lab endpoint')
    const story = incidentFixtures.find((item) => item.id === storyIncidentId)
    expect(dialog).toHaveTextContent(story?.hosts[0] ?? '')
    expect(execute).not.toHaveBeenCalled()
    expect(screen.queryByText(DRY_RUN_MESSAGE)).not.toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Confirm' }))

    expect(await screen.findByText(DRY_RUN_MESSAGE)).toBeInTheDocument()
    expect(execute).not.toHaveBeenCalled()
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  })
})
