import { Outlet, NavLink, useNavigate } from 'react-router-dom'
import { useState } from 'react'
import {
  LayoutDashboard, ScanLine, AlertTriangle, Shield,
  Settings, Package, Terminal, Bell, ChevronRight, Zap
} from 'lucide-react'

const NAV = [
  { to: '/dashboard', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/scan',      icon: ScanLine,        label: 'Scan' },
  { to: '/findings',  icon: AlertTriangle,   label: 'Findings', badge: 47 },
  { to: '/fraud',     icon: Shield,          label: 'FraudIntel', badge: 3 },
  { to: '/policy',    icon: Settings,        label: 'Policy Engine' },
  { to: '/rules',     icon: Package,         label: 'Rule Packs' },
  { to: '/cli',       icon: Terminal,        label: 'CLI / API' },
]

export default function Layout() {
  const navigate = useNavigate()
  const [collapsed, setCollapsed] = useState(false)

  return (
    <div style={{ display: 'flex', minHeight: '100vh', position: 'relative', zIndex: 1 }}>
      {/* Ambient orbs */}
      <div className="glow-orb" style={{ width: 400, height: 400, background: '#3b82f6', top: -100, left: -100 }} />
      <div className="glow-orb" style={{ width: 300, height: 300, background: '#8b5cf6', bottom: 0, right: 0 }} />
      <div className="grid-bg" />

      {/* Sidebar */}
      <aside style={{
        width: collapsed ? 60 : 220,
        background: 'rgba(5,8,16,0.92)',
        backdropFilter: 'blur(20px)',
        borderRight: '1px solid rgba(99,179,237,0.10)',
        display: 'flex', flexDirection: 'column',
        position: 'fixed', top: 0, left: 0, bottom: 0,
        zIndex: 50, transition: 'width 0.2s',
        flexShrink: 0,
      }}>
        {/* Logo */}
        <div style={{
          padding: '18px 14px', display: 'flex', alignItems: 'center',
          gap: 10, borderBottom: '1px solid rgba(99,179,237,0.10)',
          cursor: 'pointer',
        }} onClick={() => navigate('/dashboard')}>
          <div style={{
            width: 32, height: 32, flexShrink: 0,
            background: 'linear-gradient(135deg, #3b82f6, #8b5cf6)',
            borderRadius: 8, display: 'flex', alignItems: 'center',
            justifyContent: 'center', fontWeight: 800, fontSize: 16, color: 'white',
            fontFamily: 'JetBrains Mono',
          }}>S</div>
          {!collapsed && (
            <div style={{ overflow: 'hidden' }}>
              <div style={{ fontSize: 15, fontWeight: 800, letterSpacing: '-0.3px', whiteSpace: 'nowrap' }}>
                Santhosh<span style={{ color: '#3b82f6' }}> AI</span>
              </div>
              <div style={{ fontSize: 10, color: '#06b6d4', fontFamily: 'JetBrains Mono', marginTop: 1 }}>v2.0.0</div>
            </div>
          )}
        </div>

        {/* Nav items */}
        <nav style={{ flex: 1, padding: '12px 8px', display: 'flex', flexDirection: 'column', gap: 2 }}>
          {NAV.map(({ to, icon: Icon, label, badge }) => (
            <NavLink key={to} to={to} style={{ textDecoration: 'none' }}>
              {({ isActive }) => (
                <div style={{
                  display: 'flex', alignItems: 'center', gap: 10,
                  padding: collapsed ? '9px 14px' : '9px 12px',
                  borderRadius: 8,
                  background: isActive ? 'rgba(59,130,246,0.12)' : 'transparent',
                  border: `1px solid ${isActive ? 'rgba(59,130,246,0.25)' : 'transparent'}`,
                  color: isActive ? '#3b82f6' : '#94a3b8',
                  transition: 'all 0.15s', cursor: 'pointer',
                  justifyContent: collapsed ? 'center' : 'flex-start',
                }}>
                  <Icon size={16} style={{ flexShrink: 0 }} />
                  {!collapsed && (
                    <>
                      <span style={{ fontSize: 12, fontWeight: 500, flex: 1 }}>{label}</span>
                      {badge && (
                        <span style={{
                          fontSize: 10, background: badge > 10 ? '#ef4444' : '#f59e0b',
                          color: 'white', padding: '1px 5px', borderRadius: 10,
                          fontFamily: 'JetBrains Mono', fontWeight: 700,
                        }}>{badge}</span>
                      )}
                    </>
                  )}
                </div>
              )}
            </NavLink>
          ))}
        </nav>

        {/* Status & collapse */}
        <div style={{ padding: '12px 8px', borderTop: '1px solid rgba(99,179,237,0.10)' }}>
          {!collapsed && (
            <div style={{
              display: 'flex', alignItems: 'center', gap: 8, padding: '8px 10px',
              background: 'rgba(16,185,129,0.06)', borderRadius: 8,
              border: '1px solid rgba(16,185,129,0.15)', marginBottom: 8,
            }}>
              <div className="animate-pulse-dot" style={{ width: 7, height: 7, borderRadius: '50%', background: '#10b981', flexShrink: 0 }} />
              <span style={{ fontSize: 10, color: '#10b981', fontFamily: 'JetBrains Mono' }}>ALL ENGINES ACTIVE</span>
            </div>
          )}
          <div
            onClick={() => setCollapsed(!collapsed)}
            style={{
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              padding: '7px', borderRadius: 8, cursor: 'pointer',
              color: '#475569', transition: 'all 0.15s',
            }}
          >
            <ChevronRight size={14} style={{ transform: collapsed ? 'rotate(0)' : 'rotate(180deg)', transition: 'transform 0.2s' }} />
          </div>
        </div>
      </aside>

      {/* Main */}
      <div style={{
        flex: 1, display: 'flex', flexDirection: 'column',
        marginLeft: collapsed ? 60 : 220, transition: 'margin-left 0.2s',
        minHeight: '100vh',
      }}>
        {/* Top bar */}
        <header style={{
          height: 56, background: 'rgba(5,8,16,0.85)', backdropFilter: 'blur(20px)',
          borderBottom: '1px solid rgba(99,179,237,0.10)',
          display: 'flex', alignItems: 'center', justifyContent: 'flex-end',
          padding: '0 20px', gap: 12, position: 'sticky', top: 0, zIndex: 40,
        }}>
          <button className="btn-ghost" style={{ fontSize: 11, padding: '6px 10px' }}>
            <Bell size={13} /> Alerts <span style={{ background: '#ef4444', color: 'white', borderRadius: 10, padding: '1px 5px', fontSize: 10 }}>3</span>
          </button>
          <button className="btn-primary" onClick={() => navigate('/scan')}>
            <Zap size={13} /> New Scan
          </button>
        </header>

        {/* Page content */}
        <main style={{ flex: 1, padding: '20px', position: 'relative', zIndex: 1 }}>
          <Outlet />
        </main>
      </div>
    </div>
  )
}
