import { lazy, Suspense } from 'react'
import { BrowserRouter, Route, Routes } from 'react-router'
import { LoadingState } from './components/LoadingState.tsx'
import { AppShell } from './layouts/AppShell.tsx'
import { AutomationPage } from './pages/AutomationPage.tsx'
import { DetectionsPage } from './pages/DetectionsPage.tsx'
import { EntitiesPage } from './pages/EntitiesPage.tsx'
import { HostProfilePage } from './pages/HostProfilePage.tsx'
import { UserProfilePage } from './pages/UserProfilePage.tsx'
import { HealthPage } from './pages/HealthPage.tsx'
import { HuntingPage } from './pages/HuntingPage.tsx'
import { DetectionDetail } from './pages/DetectionDetail.tsx'
import { IncidentDetail } from './pages/IncidentDetail.tsx'
import { Incidents } from './pages/Incidents.tsx'
import { MitrePage } from './pages/MitrePage.tsx'
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
          <Route path="incidents" element={<Incidents />} />
          <Route path="incidents/:id" element={<IncidentDetail />} />
          <Route path="hunting" element={<HuntingPage />} />
          <Route path="entities" element={<EntitiesPage />} />
          <Route path="entities/users/:name" element={<UserProfilePage />} />
          <Route path="entities/hosts/:name" element={<HostProfilePage />} />
          <Route path="detections" element={<DetectionsPage />} />
          <Route path="detections/:id" element={<DetectionDetail />} />
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
