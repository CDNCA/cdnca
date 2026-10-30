import { CustomersPage } from './pages/CustomersPage'
export function App() {
  return <Routes><Route path="/customers" element={<CustomersPage />} /></Routes>
}
