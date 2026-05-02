// FraudIntelPage.jsx
import { RadarChart, Radar, PolarGrid, PolarAngleAxis, ResponsiveContainer, AreaChart, Area, XAxis, YAxis, Tooltip } from 'recharts'

const FRAUD_CARDS = [
  { title: 'Data Exfiltration Risk', value: 'HIGH', score: 82, color: '#ef4444', alert: true, desc: 'Suspicious network calls to external IPs detected in auth module' },
  { title: 'Supply Chain Compromise', value: '8 Pkgs', score: 65, color: '#f97316', alert: true, desc: '8 dependencies match known malicious package signatures' },
  { title: 'Insider Threat Signals', value: '3 Events', score: 35, color: '#f59e0b', alert: false, desc: 'Anomalous file access patterns detected in last 24h' },
  { title: 'Social Engineering', value: '12 Patterns', score: 48, color: '#f59e0b', alert: false, desc: 'Prompt injection attempts found in uploaded documents' },
]

const TIMELINE = [
  { dot: '🔴', color: 'rgba(239,68,68,0.15)', title: 'Exfiltration attempt detected', time: '2m ago', desc: 'POST /api/data → 185.23.44.12 with 2.4MB payload' },
  { dot: '🟠', color: 'rgba(249,115,22,0.15)', title: 'Malicious package installed', time: '1h ago', desc: 'color@1.4.1 — known infinite-loop sabotage package' },
  { dot: '🟡', color: 'rgba(245,158,11,0.15)', title: 'Sensitive file access', time: '3h ago', desc: '/etc/passwd accessed by user-service process' },
  { dot: '🔵', color: 'rgba(59,130,246,0.15)', title: 'Prompt injection in PDF', time: '6h ago', desc: 'Hidden instruction: "ignore all previous rules"' },
  { dot: '🟢', color: 'rgba(16,185,129,0.15)', title: 'Supply chain alert resolved', time: '1d ago', desc: 'lodash updated to clean version 4.17.21' },
]

const ML_SCORES = [
  { label: 'Behavioral Anomaly', score: 82 },
  { label: 'Exfil Probability', score: 76 },
  { label: 'Social Engineering', score: 45 },
  { label: 'Supply Chain Risk', score: 68 },
  { label: 'Insider Threat', score: 31 },
  { label: 'Obfuscation', score: 55 },
]

const RADAR_DATA = [
  { subject: 'Exfiltration', A: 82 },
  { subject: 'Injection', A: 76 },
  { subject: 'Supply Chain', A: 68 },
  { subject: 'Obfuscation', A: 55 },
  { subject: 'Social Eng.', A: 45 },
  { subject: 'Insider', A: 31 },
]

const TREND_DATA = Array.from({ length: 14 }, (_, i) => ({
  day: `D-${13 - i}`,
  fraud: Math.floor(Math.random() * 40 + 30),
  risk: Math.floor(Math.random() * 50 + 40),
}))

export function FraudIntelPage() {
  return (
    <div className="animate-fade-in">
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 18 }}>
        <div>
          <h1 style={{ fontSize: 20, fontWeight: 800 }}>FraudIntel Mode</h1>
          <p style={{ fontSize: 12, color: 'var(--text2)', marginTop: 2 }}>Behavioral anomaly detection & fraud intelligence dashboard</p>
        </div>
        <div style={{ background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)', color: '#ef4444', fontSize: 11, padding: '7px 14px', borderRadius: 7, fontFamily: 'JetBrains Mono', fontWeight: 700 }}>
          ⚠ 3 ACTIVE ALERTS
        </div>
      </div>

      {/* Alert cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 14, marginBottom: 16 }}>
        {FRAUD_CARDS.map((c, i) => (
          <div key={i} className="panel-card" style={{ position: 'relative', overflow: 'hidden',
            borderColor: c.alert ? 'rgba(239,68,68,0.3)' : 'var(--border)',
          }}>
            {c.alert && <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: 2, background: `linear-gradient(90deg, ${c.color}, #f97316)` }} />}
            {c.alert && <div style={{ position: 'absolute', top: 12, right: 12, background: 'rgba(239,68,68,0.12)', color: '#ef4444', fontSize: 10, padding: '2px 8px', borderRadius: 4, border: '1px solid rgba(239,68,68,0.3)', fontFamily: 'JetBrains Mono', fontWeight: 700 }}>ALERT</div>}
            <div style={{ fontSize: 12, fontWeight: 700, marginBottom: 4 }}>{c.title}</div>
            <div style={{ fontSize: 28, fontWeight: 800, fontFamily: 'JetBrains Mono', color: c.color }}>{c.value}</div>
            <div style={{ fontSize: 11, color: 'var(--text2)', marginTop: 4, marginBottom: 10 }}>{c.desc}</div>
            <div style={{ height: 4, background: 'rgba(255,255,255,0.06)', borderRadius: 2, overflow: 'hidden' }}>
              <div style={{ height: '100%', width: `${c.score}%`, background: `linear-gradient(90deg, ${c.color}, #f97316)`, borderRadius: 2, transition: 'width 1.2s' }} />
            </div>
          </div>
        ))}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 280px', gap: 14, marginBottom: 14 }}>
        {/* Timeline */}
        <div className="panel-card" style={{ gridColumn: '1' }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text2)', textTransform: 'uppercase', letterSpacing: '0.8px', marginBottom: 12 }}>Attack Chain Timeline</div>
          {TIMELINE.map((t, i) => (
            <div key={i} style={{ display: 'flex', gap: 10, padding: '9px 0', borderBottom: i < TIMELINE.length - 1 ? '1px solid var(--border)' : 'none', position: 'relative' }}>
              {i < TIMELINE.length - 1 && <div style={{ position: 'absolute', left: 14, top: 32, bottom: -9, width: 1, background: 'var(--border)' }} />}
              <div style={{ width: 28, height: 28, borderRadius: '50%', background: t.color, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 12, flexShrink: 0 }}>{t.dot}</div>
              <div>
                <div style={{ fontSize: 12, fontWeight: 700 }}>{t.title}</div>
                <div style={{ fontSize: 10, color: 'var(--text3)', fontFamily: 'JetBrains Mono' }}>{t.time}</div>
                <div style={{ fontSize: 11, color: 'var(--text2)', marginTop: 2 }}>{t.desc}</div>
              </div>
            </div>
          ))}
        </div>

        {/* Trend */}
        <div className="panel-card">
          <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text2)', textTransform: 'uppercase', letterSpacing: '0.8px', marginBottom: 12 }}>14-Day Fraud Trend</div>
          <ResponsiveContainer width="100%" height={180}>
            <AreaChart data={TREND_DATA}>
              <defs>
                <linearGradient id="gFraud" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="gRisk" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.25} />
                  <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                </linearGradient>
              </defs>
              <XAxis dataKey="day" tick={{ fontSize: 9, fill: '#475569' }} axisLine={false} tickLine={false} />
              <YAxis hide />
              <Tooltip contentStyle={{ background: 'var(--panel)', border: '1px solid var(--border)', borderRadius: 8, fontSize: 11 }} />
              <Area type="monotone" dataKey="fraud" stroke="#ef4444" fill="url(#gFraud)" strokeWidth={2} />
              <Area type="monotone" dataKey="risk" stroke="#3b82f6" fill="url(#gRisk)" strokeWidth={2} />
            </AreaChart>
          </ResponsiveContainer>
          <div style={{ display: 'flex', gap: 14, marginTop: 6 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}><div style={{ width: 8, height: 2, background: '#ef4444', borderRadius: 1 }} /><span style={{ fontSize: 10, color: 'var(--text2)' }}>Fraud Score</span></div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}><div style={{ width: 8, height: 2, background: '#3b82f6', borderRadius: 1 }} /><span style={{ fontSize: 10, color: 'var(--text2)' }}>Risk Score</span></div>
          </div>
        </div>

        {/* ML scores */}
        <div className="panel-card">
          <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text2)', textTransform: 'uppercase', letterSpacing: '0.8px', marginBottom: 14 }}>ML Anomaly Scores</div>
          {ML_SCORES.map(s => (
            <div key={s.label} style={{ marginBottom: 12 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                <span style={{ fontSize: 11, color: 'var(--text2)' }}>{s.label}</span>
                <span style={{ fontSize: 11, fontFamily: 'JetBrains Mono', fontWeight: 700, color: s.score >= 70 ? '#ef4444' : s.score >= 50 ? '#f59e0b' : '#10b981' }}>{s.score}</span>
              </div>
              <div className="progress-bar">
                <div className="progress-fill" style={{ width: `${s.score}%`, background: s.score >= 70 ? '#ef4444' : s.score >= 50 ? '#f59e0b' : '#10b981' }} />
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Radar */}
      <div className="panel-card">
        <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text2)', textTransform: 'uppercase', letterSpacing: '0.8px', marginBottom: 12 }}>Threat Vector Radar</div>
        <ResponsiveContainer width="100%" height={200}>
          <RadarChart data={RADAR_DATA}>
            <PolarGrid stroke="rgba(99,179,237,0.1)" />
            <PolarAngleAxis dataKey="subject" tick={{ fontSize: 11, fill: '#475569' }} />
            <Radar name="Score" dataKey="A" stroke="#3b82f6" fill="#3b82f6" fillOpacity={0.15} strokeWidth={2} />
          </RadarChart>
        </ResponsiveContainer>
      </div>
    </div>
  )
}

export default FraudIntelPage
