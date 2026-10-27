import { fireEvent, render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router'
import { describe, expect, it } from 'vitest'
import { AppShell } from '../layouts/AppShell.tsx'
import { TourPage } from './TourPage.tsx'

describe('guided tour and command palette', () => {
  it('states that the incident queue is a demo fixture', () => {
    render(
      <MemoryRouter>
        <TourPage />
      </MemoryRouter>,
    )
    expect(
      screen.getByText(/built by the correlation engine from synthetic alerts/),
    ).toBeInTheDocument()
    expect(
      screen.getByText(/real detection rule from the repository/),
    ).toBeInTheDocument()
  })

  it('opens the command palette from the keyboard', async () => {
    render(
      <MemoryRouter>
        <Routes>
          <Route element={<AppShell />}>
            <Route index element={<p>Home</p>} />
          </Route>
        </Routes>
      </MemoryRouter>,
    )
    fireEvent.keyDown(window, { key: 'k', metaKey: true })
    expect(
      await screen.findByRole('dialog', {
        name: 'Jump to a page, incident, or detection',
      }),
    ).toBeInTheDocument()
  })
})
