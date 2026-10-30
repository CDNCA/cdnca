import { lazy } from 'react'
const WidgetsPage = lazy(() => import('./pages/WidgetsPage'))
const OrphanPage = lazy(() => import('./pages/OrphanPage'))
export function App() {
  return (
    <Routes>
      <Route path="/widgets" element={<WidgetsPage />} />
      <Route path="/orphan" element={<OrphanPage />} />
      <Route path="/login" element={<OrphanPage />} />
    </Routes>
  )
}
