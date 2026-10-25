import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { beforeEach, describe, expect, it } from 'vitest'
import { resetDemoCatalog } from '../services/demoCatalog.ts'
import { DetectionsPage } from './DetectionsPage.tsx'

describe('detections library', () => {
  beforeEach(() => {
    resetDemoCatalog()
  })

  it('shows NOT TESTED on every detection row', async () => {
    render(
      <MemoryRouter>
        <DetectionsPage />
      </MemoryRouter>,
    )
    expect(await screen.findByText('SF-001')).toBeInTheDocument()
    expect(screen.getByText('SF-020')).toBeInTheDocument()
    const body = screen.getByRole('table').querySelector('tbody')
    expect(body).not.toBeNull()
    expect(body).toHaveTextContent('NOT TESTED')
    expect(body?.textContent ?? '').not.toMatch(
      /SYNTAX VALID|LOGTEST VALID|LAB VALIDATED|NEEDS TUNING/,
    )
  })
})
