import { Routes, Route, Navigate } from 'react-router-dom'
import Layout from './components/Layout'
import Dashboard from './pages/Dashboard'
import ScanPage from './pages/ScanPage'
import FindingsPage from './pages/FindingsPage'
import FraudIntelPage from './pages/FraudIntelPage'
import PolicyPage from './pages/PolicyPage'
import RulePacksPage from './pages/RulePacksPage'
import CLIPage from './pages/CLIPage'

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Layout />}>
        <Route index element={<Navigate to="/dashboard" replace />} />
        <Route path="dashboard" element={<Dashboard />} />
        <Route path="scan" element={<ScanPage />} />
        <Route path="findings" element={<FindingsPage />} />
        <Route path="fraud" element={<FraudIntelPage />} />
        <Route path="policy" element={<PolicyPage />} />
        <Route path="rules" element={<RulePacksPage />} />
        <Route path="cli" element={<CLIPage />} />
      </Route>
    </Routes>
  )
}
