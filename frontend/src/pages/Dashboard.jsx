import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { AlertTriangle, ShieldAlert, FileSearch, Activity, TrendingUp, Cpu } from 'lucide-react'
import { RadialBarChart, RadialBar, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, Cell } from 'recharts'

const METRICS = [
  { label: 'Risk Score', value: '87', sub: '/100', color: '#ef4444', trend: '+12', up: true, icon: AlertTriangle },
  { label: 'Critical Findings', value: '12', sub: 'findings', color: '#ef4444', trend: '+5 today', up: true, icon: ShieldAlert },
  { label: 'Files Analyzed', value: '3,847', sub: 'last scan', color: '#3b82f6', trend: '14m ago', up: false, icon: FileSearch },
  { label: 'Fraud Score', value: '71', sub: '/100', color: '#f97316', trend: 'elevated', up: true, icon: Activity },
  { label: 'Secrets Found', value: '23', sub: 'in codebase', color: '#ef4444', trend: 'new', up: true, icon: ShieldAlert },
  { label: 'Supply Chain', value: '8', sub: 'risks', color: '#f59e0b', trend: 'packages', up: true, icon: TrendingUp },
  { label: 'Rules Triggered', value: '184', sub: 'total', color: '#8b5cf6', trend: '6 packs', up: false, icon: Cpu },
  { label: 'Analyzability', value: '94', sub: '/100', color: '#10b981', trend: 'excellent', up: false, icon: Activity },
]

const FINDINGS_PREVIEW = [
  { sev: 'CRITICAL', title: 'SQL Injection via user input', path: 'src/db/queries.py:247', engine: 'Taint Flow', score: 98 },
  { sev: 'CRITICAL', title: 'Hardcoded AWS secret key', path: 'config/settings.yaml:12', engine: 'Secrets Scanner', score: 97 },
  { sev: 'CRITICAL', title: 'Remote code execution via eval()', path: 'utils/executor.js:89', engine: 'Static Analyzer', score: 95 },
  { sev: 'HIGH', title: 'Data exfiltration via HTTP POST', path: 'lib/reporter.py:156', engine: 'Fraud Intelligence', score: 88 },
  { sev: 'HIGH', title: 'Prompt injection in PDF parser', path: 'parsers/pdf_reader.py:34', engine: 'Prompt Injection', score: 84 },
  { sev: 'HIGH', title: 'Malicious npm package: color@1.4.1', path: 'package.json:78', engine: 'Supply Chain', score: 82 },
  { sev: 'MEDIUM', title: 'Unsafe deserialization', path: 'api/serializers.py:202', engine: 'Static Analyzer', score: 65 },
]

const SEV_COLORS = { CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#f59e0b', LOW: '#10b981', INFO: '#94a3b8' }

const DIST_DATA = [
  { name: 'Critical', value: 12, fill: '#ef4444' },
  { name: 'High', value: 9, fill: '#f97316' },
  { name: 'Medium', value: 18, fill: '#f59e0b' },
  { name: 'Low', value: 8, fill: '#10b981' },
]

const HEATMAP = [
  { label: 'auth', h: 4 }, { label: 'db', h: 4 }, { label: 'api', h: 3 }, { label: 'parser', h: 3 },
  { label: 'utils', h: 2 }, { label: 'config', h: 4 }, { label: 'routes', h: 2 }, { label: 'models', h: 1 },
  { label: 'tests', h: 0 }, { label: 'docs', h: 0 }, { label: 'static', h: 1 }, { label: 'cache', h: 2 },
]

const HEAT_STYLES = [
  { bg: 'rgba(99,179,237,0.06)', color: '#475569' },
  { bg: 'rgba(16,185,129,0.18)', color: '#10b981' },
  { bg: 'rgba(245,158,11,0.22)', color: '#f59e0b' },
  { bg: 'rgba(249,115,22,0.28)', color: '#f97316' },
  { bg: 'rgba(239,68,68,0.32)', color: '#ef4444' },
]

const ACTIVITY = [
  { icon: '🔴', text: 'Critical: SQL injection found in db/queries.py', time: '2s ago' },
  { icon: '🟠', text: 'High: Exfiltration pattern matched in reporter.py', time: '14s ago' },
  { icon: '🔵', text: 'Scan completed: project-alpha.zip (3,847 files)', time: '14m ago' },
  { icon: '🟡', text: 'FraudIntel: Supply chain anomaly (8 packages)', time: '1h ago' },
  { icon: '🟢', text: 'Policy updated: strict preset applied', time: '2h ago' },
]

export default function Dashboard() {
  const navigate = useNavigate()
  const [tick, setTick] = useState(0)

  useEffect(() => {
    const t = setInterval(() => setTick(x => x + 1), 5000)
    return () => clearInterval(t)
  }, [])

  return (
    <div className="animate-fade-in">
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
        <div>
          <h1 style={{ fontSize: 20, fontWeight: 800 }}>Security Overview</h1>
          <p style={{ fontSize: 12, color: 'var(--text2)', marginTop: 2 }}>Last scan: 14 minutes ago — project-alpha.zip</p>
        </div>
        <button className="btn-primary" onClick={() => navigate('/scan')}>⚡ Run New Scan</button>
      </div>

      {/* Metrics grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12, marginBottom: 20 }}>
        {METRICS.map((m, i) => (
          <div key={i} className="panel-card" style={{ position: 'relative', overflow: 'hidden' }}>
            <div style={{ fontSize: 10, color: 'var(--text3)', textTransform: 'uppercase', letterSpacing: '0.8px', fontWeight: 600, marginBottom: 6 }}>{m.label}</div>
            <div style={{ fontSize: 26, fontWeight: 800, fontFamily: 'JetBrains Mono', color: m.color, lineHeight: 1 }}>
              {m.value}<span style={{ fontSize: 13, color: 'var(--text3)', fontWeight: 400 }}>{m.sub}</span>
            </div>
            <div style={{ fontSize: 10, color: m.up ? '#f97316' : 'var(--text3)', marginTop: 5 }}>
              {m.up ? '▲' : '●'} {m.trend}
            </div>
          </div>
        ))}
      </div>

      {/* Main 2-col row */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 300px', gap: 16, marginBottom: 16 }}>
        {/* Findings list */}
        <div className="panel-card">
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14 }}>
            <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text2)', textTransform: 'uppercase', letterSpacing: '0.8px' }}>
              Recent Findings
            </div>
            <button className="btn-ghost" style={{ fontSize: 10, padding: '4px 10px' }} onClick={() => navigate('/findings')}>
              View all →
            </button>
          </div>
          {FINDINGS_PREVIEW.map((f, i) => (
            <div key={i} style={{
              display: 'flex', alignItems: 'flex-start', gap: 10, padding: '9px 0',
              borderBottom: i < FINDINGS_PREVIEW.length - 1 ? '1px solid var(--border)' : 'none',
              cursor: 'pointer',
            }}>
              <span className={`sev-${f.sev}`} style={{ fontSize: 9, fontWeight: 700, padding: '2px 6px', borderRadius: 4, fontFamily: 'JetBrains Mono', whiteSpace: 'nowrap', marginTop: 2 }}>
                {f.sev}
              </span>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontSize: 12, fontWeight: 600 }}>{f.title}</div>
                <div style={{ fontSize: 10, color: 'var(--text3)', fontFamily: 'JetBrains Mono', marginTop: 1 }}>{f.path}</div>
                <div style={{ fontSize: 10, color: 'var(--text2)', marginTop: 1 }}>{f.engine} · Risk: {f.score}/100</div>
              </div>
            </div>
          ))}
        </div>

        {/* Right column */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          {/* Distribution */}
          <div className="panel-card">
            <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text2)', textTransform: 'uppercase', letterSpacing: '0.8px', marginBottom: 12 }}>
              Risk Distribution
            </div>
            <ResponsiveContainer width="100%" height={100}>
              <BarChart data={DIST_DATA} barSize={24}>
                <XAxis dataKey="name" tick={{ fontSize: 10, fill: '#475569' }} axisLine={false} tickLine={false} />
                <YAxis hide />
                <Tooltip
                  contentStyle={{ background: 'var(--panel)', border: '1px solid var(--border)', borderRadius: 8, fontSize: 11 }}
                  cursor={{ fill: 'rgba(255,255,255,0.04)' }}
                />
                <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                  {DIST_DATA.map((d, i) => <Cell key={i} fill={d.fill} fillOpacity={0.85} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 5, marginTop: 8 }}>
              {DIST_DATA.map(d => (
                <div key={d.name} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
                    <div style={{ width: 7, height: 7, borderRadius: '50%', background: d.fill }} />
                    <span style={{ fontSize: 11, color: 'var(--text2)' }}>{d.name}</span>
                  </div>
                  <span style={{ fontSize: 11, fontFamily: 'JetBrains Mono', color: d.fill, fontWeight: 700 }}>{d.value}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Activity */}
          <div className="panel-card" style={{ flex: 1 }}>
            <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text2)', textTransform: 'uppercase', letterSpacing: '0.8px', marginBottom: 10 }}>
              Live Activity
            </div>
            {ACTIVITY.map((a, i) => (
              <div key={i} style={{ display: 'flex', gap: 8, padding: '7px 0', borderBottom: i < ACTIVITY.length - 1 ? '1px solid var(--border)' : 'none' }}>
                <span style={{ fontSize: 12 }}>{a.icon}</span>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: 11, color: 'var(--text2)' }}>{a.text}</div>
                  <div style={{ fontSize: 10, color: 'var(--text3)', fontFamily: 'JetBrains Mono', marginTop: 1 }}>{a.time}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Heatmap */}
      <div className="panel-card">
        <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text2)', textTransform: 'uppercase', letterSpacing: '0.8px', marginBottom: 12 }}>
          File Risk Heatmap — Module Analysis
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(12, 1fr)', gap: 6 }}>
          {HEATMAP.map((d, i) => (
            <div key={i} style={{
              height: 36, borderRadius: 6, display: 'flex', alignItems: 'center', justifyContent: 'center',
              fontSize: 10, fontFamily: 'JetBrains Mono', fontWeight: 600, cursor: 'pointer',
              transition: 'transform 0.15s',
              background: HEAT_STYLES[d.h].bg,
              color: HEAT_STYLES[d.h].color,
            }}
              title={`${d.label}: risk level ${d.h}/4`}
              onMouseEnter={e => e.currentTarget.style.transform = 'scale(1.08)'}
              onMouseLeave={e => e.currentTarget.style.transform = 'scale(1)'}
            >
              {d.label}
            </div>
          ))}
        </div>
        <div style={{ display: 'flex', gap: 14, marginTop: 10 }}>
          {['No Risk', 'Low', 'Medium', 'High', 'Critical'].map((l, i) => (
            <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
              <div style={{ width: 10, height: 10, borderRadius: 2, background: HEAT_STYLES[i].bg, border: `1px solid ${HEAT_STYLES[i].color}` }} />
              <span style={{ fontSize: 10, color: 'var(--text3)' }}>{l}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
