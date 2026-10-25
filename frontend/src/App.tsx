import { lazy, Suspense } from 'react'
import { BrowserRouter, Route, Routes } from 'react-router'
import { LoadingState } from './components/LoadingState.tsx'
import { AppShell } from './layouts/AppShell.tsx'
import { AutomationPage } from './pages/AutomationPage.tsx'
import { DetectionsPage } from './pages/DetectionsPage.tsx'
import { EntitiesPage } from './pages/EntitiesPage.tsx'
import { HealthPage } from './pages/HealthPage.tsx'
import { HuntingPage } from './pages/HuntingPage.tsx'
import { IncidentsPage } from './pages/IncidentsPage.tsx'
import { MitrePage } from './pages/MitrePage.tsx'
import { IncidentDetailPage } from './pages/IncidentDetailPage.tsx'
import { SocOverview } from './pages/SocOverview.tsx'
import { SettingsPage } from './pages/SettingsPage.tsx'
import { SourcesPage } from './pages/SourcesPage.tsx'

const DevComponentsPage = import.meta.env.DEV
  ? lazy(() => import('./pages/DevComponentsPage.tsx'))
  : null

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<AppShell />}>
          <Route index element={<SocOverview />} />
          <Route path="incidents" element={<IncidentsPage />} />
          <Route path="incidents/:id" element={<IncidentDetailPage />} />
          <Route path="hunting" element={<HuntingPage />} />
          <Route path="entities" element={<EntitiesPage />} />
          <Route path="detections" element={<DetectionsPage />} />
          <Route path="mitre" element={<MitrePage />} />
          <Route path="automation" element={<AutomationPage />} />
          <Route path="sources" element={<SourcesPage />} />
          <Route path="health" element={<HealthPage />} />
          <Route path="settings" element={<SettingsPage />} />
          {DevComponentsPage ? (
            <Route
              path="dev/components"
              element={
                <Suspense
                  fallback={<LoadingState label="Loading component gallery" />}
                >
                  <DevComponentsPage />
                </Suspense>
              }
            />
          ) : null}
        </Route>
      </Routes>
    </BrowserRouter>
  )
}
