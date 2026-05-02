// PolicyPage.jsx
import { useState } from 'react'
import toast from 'react-hot-toast'

const SECTIONS = {
  static:   { label: 'Static Analysis',  count: 12 },
  taint:    { label: 'Taint Flow',        count: 8  },
  secrets:  { label: 'Secrets Scanner',   count: 15 },
  fraud:    { label: 'Fraud Detection',   count: 9  },
  bash:     { label: 'Bash / Script',     count: 6  },
  prompt:   { label: 'Prompt Injection',  count: 4  },
}

const RULES = {
  static: [
    { id:'SA-001', name:'eval() Detection',             desc:'Detects eval() with user-controlled data',    enabled:true,  sev:'CRITICAL' },
    { id:'SA-002', name:'exec() Detection',             desc:'Dangerous arbitrary code execution via exec()',enabled:true,  sev:'CRITICAL' },
    { id:'SA-003', name:'Shell=True subprocess',        desc:'Shell injection risk in subprocess calls',    enabled:true,  sev:'HIGH'     },
    { id:'SA-005', name:'Unsafe YAML load',             desc:'yaml.load() without SafeLoader',             enabled:true,  sev:'HIGH'     },
    { id:'SA-009', name:'Hardcoded Credentials',        desc:'Passwords/keys hardcoded in source',         enabled:true,  sev:'CRITICAL' },
    { id:'SA-010', name:'Weak Crypto Hash',             desc:'MD5/SHA1 used for security',                 enabled:false, sev:'LOW'      },
    { id:'SA-012', name:'SSL Verification Disabled',    desc:'SSL cert verification bypassed',             enabled:true,  sev:'HIGH'     },
  ],
  taint: [
    { id:'TF-001', name:'Source→SQL Sink',              desc:'Taint flow from user input to SQL query',    enabled:true,  sev:'CRITICAL' },
    { id:'TF-002', name:'Source→Command Sink',          desc:'Taint flow to os.system/subprocess',         enabled:true,  sev:'CRITICAL' },
    { id:'TF-003', name:'Cross-function Taint',         desc:'Track taint across function boundaries',     enabled:false, sev:'HIGH'     },
    { id:'TF-005', name:'Template Injection',           desc:'Taint flow to render_template_string',       enabled:true,  sev:'CRITICAL' },
  ],
  secrets: [
    { id:'SS-001', name:'AWS Access Key',               desc:'AKIA[0-9A-Z]{16} pattern',                  enabled:true,  sev:'CRITICAL' },
    { id:'SS-003', name:'Google API Key',               desc:'AIza[0-9A-Za-z-_]{35} pattern',             enabled:true,  sev:'CRITICAL' },
    { id:'SS-004', name:'OpenAI Key',                   desc:'sk-[a-zA-Z0-9]{48} pattern',                enabled:true,  sev:'CRITICAL' },
    { id:'SS-006', name:'Private Key Block',            desc:'-----BEGIN PRIVATE KEY----- pattern',        enabled:true,  sev:'CRITICAL' },
    { id:'SS-007', name:'Hardcoded Password',           desc:'password=... in source',                    enabled:true,  sev:'HIGH'     },
  ],
  fraud: [
    { id:'FRD-001', name:'Exfiltration Channel',        desc:'Suspicious external network POSTs',          enabled:true,  sev:'HIGH'     },
    { id:'FRD-002', name:'Social Engineering',          desc:'Urgency/phishing patterns in content',       enabled:true,  sev:'MEDIUM'   },
    { id:'FRD-003', name:'Insider Threat Signals',      desc:'Sensitive path access anomalies',            enabled:true,  sev:'HIGH'     },
    { id:'FRD-004', name:'Obfuscation Detection',       desc:'Base64/hex encoded payloads',               enabled:true,  sev:'HIGH'     },
  ],
  bash: [
    { id:'SH-001', name:'Curl Pipe to Shell',           desc:'curl ... | bash pattern',                   enabled:true,  sev:'CRITICAL' },
    { id:'SH-003', name:'chmod 777',                    desc:'World-writable permissions',                 enabled:true,  sev:'HIGH'     },
    { id:'SH-005', name:'Base64 Shell Exec',            desc:'base64 -d | bash evasion pattern',           enabled:true,  sev:'CRITICAL' },
  ],
  prompt: [
    { id:'PI-001', name:'Instruction Override',         desc:'"ignore previous instructions" variants',   enabled:true,  sev:'CRITICAL' },
    { id:'PI-002', name:'Role Hijacking',               desc:'"you are now..." injection patterns',        enabled:true,  sev:'HIGH'     },
    { id:'PI-004', name:'Fake System Tags',             desc:'<system> or [INST] injection tags',          enabled:true,  sev:'HIGH'     },
  ],
}

const SEV_COLORS = { CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#f59e0b', LOW: '#10b981' }
const PRESETS = ['balanced', 'strict', 'permissive']

export function PolicyPage() {
  const [section, setSection] = useState('static')
  const [preset, setPreset] = useState('balanced')
  const [rules, setRules] = useState(RULES)
  const [showYAML, setShowYAML] = useState(false)

  const toggle = (ruleId) => {
    setRules(prev => ({
      ...prev,
      [section]: prev[section].map(r => r.id === ruleId ? { ...r, enabled: !r.enabled } : r)
    }))
  }

  const yamlContent = `# Santhosh AI — Policy Configuration
version: "2.0.0"
preset: "${preset}"

engines:
  static_analyzer: true
  taint_flow: true
  secrets_scanner: true
  fraud_detection: true
  supply_chain: true
  prompt_injection: true

thresholds:
  fail_on: "${preset === 'strict' ? 'MEDIUM' : preset === 'permissive' ? 'CRITICAL' : 'HIGH'}"
  max_risk_score: ${preset === 'strict' ? 40 : preset === 'permissive' ? 90 : 70}

fraud:
  behavioral_anomaly: ${preset !== 'permissive'}
  ml_scoring: ${preset !== 'permissive'}
  exfil_detection: ${preset !== 'permissive'}
  supply_chain_check: true

llm_enrichment:
  enabled: ${preset !== 'permissive'}
  phase: 2
  false_positive_reduction: true`

  return (
    <div className="animate-fade-in">
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 18 }}>
        <div>
          <h1 style={{ fontSize: 20, fontWeight: 800 }}>Policy Engine</h1>
          <p style={{ fontSize: 12, color: 'var(--text2)', marginTop: 2 }}>Configure scan policies, rule thresholds, and engine settings</p>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <select value={preset} onChange={e => setPreset(e.target.value)} style={{ background: 'var(--panel)', border: '1px solid var(--border)', color: 'var(--text)', padding: '7px 12px', borderRadius: 8, fontSize: 12, fontFamily: 'Sora, sans-serif', cursor: 'pointer' }}>
            {PRESETS.map(p => <option key={p} value={p}>{p.charAt(0).toUpperCase() + p.slice(1)}</option>)}
          </select>
          <button className="btn-ghost" style={{ fontSize: 11 }} onClick={() => setShowYAML(!showYAML)}>
            {showYAML ? 'Hide' : 'View'} YAML
          </button>
          <button className="btn-primary" style={{ fontSize: 11, padding: '7px 14px' }} onClick={() => toast.success('Policy saved!')}>
            Save Policy
          </button>
        </div>
      </div>

      {showYAML && (
        <div className="panel-card animate-fade-in" style={{ marginBottom: 16 }}>
          <pre style={{ fontFamily: 'JetBrains Mono', fontSize: 11, lineHeight: 1.7, color: 'var(--text2)', whiteSpace: 'pre-wrap' }}>
            {yamlContent.split('\n').map((line, i) => {
              const colored = line
                .replace(/^(version|preset|engines|thresholds|fraud|llm_enrichment):/g, '<key>$&</key>')
                .replace(/:\s*(true|false)/g, ': <val>$1</val>')
                .replace(/:\s*"([^"]+)"/g, ': <str>"$1"</str>')
                .replace(/:\s*(\d+)/g, ': <num>$1</num>')
              return <span key={i} dangerouslySetInnerHTML={{ __html: line.replace(/^(#.*)/, '<span style="color:#475569">$1</span>').replace(/^(\s*[\w_]+):/, '<span style="color:#60a5fa">$&</span>').replace(/true|false/, m => `<span style="color:#34d399">${m}</span>`).replace(/"[^"]*"/, m => `<span style="color:#f9a8d4">${m}</span>`) + '\n' }} />
            })}
          </pre>
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: '200px 1fr', gap: 14 }}>
        {/* Sidebar */}
        <div style={{ background: 'var(--panel)', border: '1px solid var(--border)', borderRadius: 12, overflow: 'hidden' }}>
          {Object.entries(SECTIONS).map(([key, sec]) => (
            <div key={key} onClick={() => setSection(key)} style={{
              padding: '11px 14px', cursor: 'pointer', transition: 'background 0.15s',
              borderBottom: '1px solid var(--border)',
              background: section === key ? 'rgba(59,130,246,0.08)' : 'transparent',
              borderLeft: section === key ? '3px solid #3b82f6' : '3px solid transparent',
            }}>
              <div style={{ fontSize: 12, fontWeight: 600, color: section === key ? '#3b82f6' : 'var(--text)' }}>{sec.label}</div>
              <div style={{ fontSize: 10, color: 'var(--text3)', fontFamily: 'JetBrains Mono', marginTop: 2 }}>{sec.count} rules</div>
            </div>
          ))}
        </div>

        {/* Rules */}
        <div className="panel-card">
          <div style={{ fontSize: 12, fontWeight: 700, marginBottom: 14, color: 'var(--text2)', textTransform: 'uppercase', letterSpacing: '0.8px' }}>
            {SECTIONS[section]?.label} Rules
          </div>
          {(rules[section] || []).map(r => (
            <div key={r.id} style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '11px 0', borderBottom: '1px solid var(--border)' }}>
              <div style={{ flex: 1 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 3 }}>
                  <span style={{ fontSize: 12, fontWeight: 600 }}>{r.name}</span>
                  <span style={{ fontSize: 9, padding: '1px 5px', borderRadius: 3, fontFamily: 'JetBrains Mono', fontWeight: 700,
                    background: `${SEV_COLORS[r.sev]}18`, color: SEV_COLORS[r.sev], border: `1px solid ${SEV_COLORS[r.sev]}40` }}>
                    {r.sev}
                  </span>
                </div>
                <div style={{ fontSize: 11, color: 'var(--text2)' }}>{r.desc}</div>
                <div style={{ fontSize: 10, color: 'var(--text3)', fontFamily: 'JetBrains Mono', marginTop: 2 }}>{r.id}</div>
              </div>
              {/* Toggle */}
              <div onClick={() => toggle(r.id)} style={{
                width: 38, height: 22, borderRadius: 11, cursor: 'pointer', position: 'relative',
                background: r.enabled ? '#3b82f6' : 'rgba(255,255,255,0.08)',
                border: `1px solid ${r.enabled ? '#3b82f6' : 'var(--border)'}`,
                transition: 'all 0.2s', flexShrink: 0,
              }}>
                <div style={{
                  position: 'absolute', width: 16, height: 16, borderRadius: '50%', background: 'white',
                  top: 2, left: r.enabled ? 18 : 2, transition: 'left 0.2s',
                }} />
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

export default PolicyPage
