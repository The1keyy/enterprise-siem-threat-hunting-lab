import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { describe, expect, it } from 'vitest'
import { TourPage } from './TourPage.tsx'

describe('guided tour', () => {
  it('states that the incident queue is a demo fixture', () => {
    render(
      <MemoryRouter>
        <TourPage />
      </MemoryRouter>,
    )
    expect(
      screen.getByText(/hand-written demo fixture/),
    ).toBeInTheDocument()
    expect(
      screen.getByText(/real detection rule from the repository/),
    ).toBeInTheDocument()
  })
})
