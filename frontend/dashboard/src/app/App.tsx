import { useEffect, useState, type ReactNode } from 'react'
import { BrowserRouter, Link, Navigate, NavLink, Outlet, Route, Routes, useLocation, useNavigate } from 'react-router-dom'
import { IoSettingsOutline } from 'react-icons/io5'
import { BsRobot } from 'react-icons/bs'
import { AuthProvider, useAuth } from '@/app/providers/AuthProvider'
import { ThemeProvider } from '@/app/providers/ThemeProvider'
import { initials } from '@/lib/format'
import type { IconName } from '@/components/ui'
import { Icon, Logo } from '@/components/ui'
import { ThemeToggle } from '@/components/ThemeToggle'
import {
  AgentsPage, AuditPage, DashboardPage, EventDetailPage, EventsPage, FindingDetailPage,
  FindingsPage, ForgotPasswordPage, IncidentDetailPage, IncidentsPage, LandingPage,
  ResetPasswordPage, SettingsPage, SignupPage, VerifyEmailPage,
} from '@/features/pages'
import { LoginConsole } from '@/features/login/LoginConsole'

interface NavigationItem {
  to: string
  label: string
  icon: IconName
}

const navigation: NavigationItem[] = [
  { to: '/dashboard', label: 'Overview', icon: 'grid' },
  { to: '/events', label: 'Events', icon: 'network' },
  { to: '/incidents', label: 'Incidents', icon: 'alert' },
  { to: '/agents', label: 'Agents', icon: 'bot' },
  { to: '/findings', label: 'Findings', icon: 'check' },
  { to: '/audit', label: 'Audit', icon: 'list' },
]

function LoadingScreen() {
  return <div className="route-loading"><span className="loading-spinner" /><span>Restoring secure session…</span></div>
}

function ProtectedRoute() {
  const { status } = useAuth()
  const location = useLocation()
  if (status === 'loading') return <LoadingScreen />
  if (status !== 'authenticated') return <Navigate to="/login" replace state={{ from: location }} />
  return <Outlet />
}

function PublicOnlyRoute({ children }: { children: ReactNode }) {
  const { status } = useAuth()
  if (status === 'loading') return <LoadingScreen />
  if (status === 'authenticated') return <Navigate to="/dashboard" replace />
  return <>{children}</>
}

function AppShell() {
  const { user, signOut } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()
  const [collapsed, setCollapsed] = useState(false)
  const [mobileOpen, setMobileOpen] = useState(false)

  useEffect(() => setMobileOpen(false), [location.pathname])

  const current = navigation.find((item) => location.pathname === item.to || location.pathname.startsWith(`${item.to}/`))
  const title = current?.label || (location.pathname.startsWith('/settings') ? 'Settings' : 'Workspace')

  const logout = () => {
    signOut()
    navigate('/login', { replace: true })
  }

  return <div className={`app-shell${collapsed ? ' sidebar-collapsed' : ''}${mobileOpen ? ' mobile-nav-open' : ''}`}>
    <aside className="sidebar" aria-label="SOC navigation">
      <div className="sidebar-header"><Link to="/dashboard" aria-label="Intriqo overview"><Logo compact={collapsed} /></Link><button className="sidebar-collapse" type="button" onClick={() => setCollapsed((value) => !value)} aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}><Icon name={collapsed ? 'chevron-right' : 'chevron-left'} size={16} /></button></div>
      <div className="sidebar-context"><span className="context-mark"><Icon name="shield" size={15} /></span><span><strong>CONTROL PLANE</strong><small>LOCAL WORKSPACE</small></span></div>
      <nav className="sidebar-nav"><p className="nav-label">OPERATIONS</p>{navigation.map((item) => <NavLink className={({ isActive }) => `sidebar-link${isActive ? ' is-active' : ''}`} to={item.to} end={item.to === '/dashboard'} key={item.to} title={collapsed ? item.label : undefined}>{item.to === '/agents' ? <BsRobot size={18} /> : <Icon name={item.icon} size={18} />}<span>{item.label}</span></NavLink>)}</nav>
      <div className="sidebar-bottom"><NavLink className={({ isActive }) => `sidebar-link${isActive ? ' is-active' : ''}`} to="/settings" title={collapsed ? 'Settings' : undefined}><IoSettingsOutline size={18} /><span>Settings</span></NavLink><button className="sidebar-link sidebar-logout" type="button" onClick={logout} title={collapsed ? 'Sign out' : undefined}><Icon name="logout" size={18} /><span>Sign out</span></button><div className="sidebar-user"><span className="avatar avatar-small">{initials(user?.username || 'Intriqo')}</span><span className="sidebar-user-copy"><strong>{user?.username || 'Operator'}</strong><small>{user?.role || 'ANALYST'}</small></span></div></div>
    </aside>
    {mobileOpen && <button type="button" className="mobile-nav-backdrop" aria-label="Close navigation" onClick={() => setMobileOpen(false)} />}
    <div className="app-main"><header className="topbar"><button type="button" className="mobile-menu-button" aria-label="Open navigation" onClick={() => setMobileOpen(true)}><Icon name="menu" size={20} /></button><div className="topbar-context"><span className="topbar-kicker">INTRIQO / SOC</span><span className="topbar-separator">/</span><strong>{title}</strong></div><div className="topbar-actions"><span className="topbar-status"><span className="status-pulse" /> API connected</span><ThemeToggle /><div className="topbar-user"><span className="avatar">{initials(user?.username || 'Intriqo')}</span><span><strong>{user?.username || 'Operator'}</strong><small>{user?.role || 'ANALYST'}</small></span></div></div></header><main className="app-content"><Outlet /></main></div>
  </div>
}

export default function App() {
  return <BrowserRouter><ThemeProvider><AuthProvider><Routes><Route path="/" element={<LandingPage />} /><Route path="/login" element={<PublicOnlyRoute><LoginConsole /></PublicOnlyRoute>} /><Route path="/signup" element={<PublicOnlyRoute><SignupPage /></PublicOnlyRoute>} /><Route path="/forgot-password" element={<PublicOnlyRoute><ForgotPasswordPage /></PublicOnlyRoute>} /><Route path="/verify-email" element={<VerifyEmailPage />} /><Route path="/reset-password" element={<ResetPasswordPage />} /><Route element={<ProtectedRoute />}><Route element={<AppShell />}><Route path="/dashboard" element={<DashboardPage />} /><Route path="/events" element={<EventsPage />} /><Route path="/events/:eventId" element={<EventDetailPage />} /><Route path="/incidents" element={<IncidentsPage />} /><Route path="/incidents/:incidentId" element={<IncidentDetailPage />} /><Route path="/agents" element={<AgentsPage />} /><Route path="/findings" element={<FindingsPage />} /><Route path="/findings/:findingId" element={<FindingDetailPage />} /><Route path="/audit" element={<AuditPage />} /><Route path="/settings" element={<SettingsPage />} /><Route path="/detections" element={<Navigate to="/events" replace />} /><Route path="/overview" element={<Navigate to="/dashboard" replace />} /><Route path="*" element={<Navigate to="/dashboard" replace />} /></Route></Route><Route path="*" element={<Navigate to="/" replace />} /></Routes></AuthProvider></ThemeProvider></BrowserRouter>
}
