import React from 'react'
import { BrowserRouter, Routes, Route, NavLink } from 'react-router-dom'

// Feature route placeholders — each feature/ subdirectory owns its own page
const Overview       = () => <div>Overview — system health and live metrics</div>
const Incidents      = () => <div>Incidents — active and historical incidents</div>
const Investigations = () => <div>Investigations — autonomous agent investigation results</div>
const Agents         = () => <div>Agents — agent activity monitor and task queue</div>
const Detections     = () => <div>Detections — live detection feed from the IDS engine</div>
const Approvals      = () => <div>Approvals — human approval queue for agent-proposed actions</div>
const Audit          = () => <div>Audit — full audit log</div>

/**
 * App — root component.
 *
 * Architecture: each feature owns its own route, components, hooks, and
 * service calls. No business logic lives here — only routing.
 */
export default function App() {
  return (
    <BrowserRouter>
      <nav style={{ padding: '1rem', borderBottom: '1px solid #333', display: 'flex', gap: '1.5rem' }}>
        <strong>Intriqo SOC</strong>
        {[
          ['/', 'Overview'],
          ['/incidents', 'Incidents'],
          ['/investigations', 'Investigations'],
          ['/detections', 'Detections'],
          ['/agents', 'Agents'],
          ['/approvals', 'Approvals'],
          ['/audit', 'Audit'],
        ].map(([to, label]) => (
          <NavLink key={to} to={to} end={to === '/'}>
            {label}
          </NavLink>
        ))}
      </nav>

      <main style={{ padding: '1.5rem' }}>
        <Routes>
          <Route path="/"               element={<Overview />} />
          <Route path="/incidents"      element={<Incidents />} />
          <Route path="/investigations" element={<Investigations />} />
          <Route path="/detections"     element={<Detections />} />
          <Route path="/agents"         element={<Agents />} />
          <Route path="/approvals"      element={<Approvals />} />
          <Route path="/audit"          element={<Audit />} />
        </Routes>
      </main>
    </BrowserRouter>
  )
}
