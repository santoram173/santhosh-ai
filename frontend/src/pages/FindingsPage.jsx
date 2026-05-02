// FindingsPage.jsx
import { useState } from 'react'
import { Download, Filter } from 'lucide-react'
import toast from 'react-hot-toast'

const FINDINGS = [
  { sev:'CRITICAL', title:'SQL Injection via user input', path:'src/db/queries.py:247', cat:'Injection', engine:'Taint Flow', score:98, rule:'TF-001', desc:'User-controlled data reaches SQL sink without sanitization.', fix:'Use parameterized queries or an ORM.' },
  { sev:'CRITICAL', title:'Hardcoded AWS secret key', path:'config/settings.yaml:12', cat:'Secrets', engine:'Secrets Scanner', score:97, rule:'SS-002', desc:'AWS secret access key found hardcoded.', fix:'Use AWS Secrets Manager or environment variables.' },
  { sev:'CRITICAL', title:'RCE via eval()', path:'utils/executor.js:89', cat:'Code Injection', engine:'Static Analyzer', score:95, rule:'SA-001', desc:'eval() called with user-controlled data.', fix:'Remove eval(). Use JSON.parse or safe alternatives.' },
  { sev:'CRITICAL', title:'Private RSA key exposed', path:'certs/server.pem:1', cat:'Secrets', engine:'Secrets Scanner', score:99, rule:'SS-006', desc:'RSA private key committed to codebase.', fix:'Revoke the key immediately. Use secrets vault.' },
  { sev:'HIGH', title:'Data exfiltration via HTTP POST', path:'lib/reporter.py:156', cat:'Data Exfiltration', engine:'Fraud Intelligence', score:88, rule:'FRD-001', desc:'Suspicious bulk POST to external IP.', fix:'Audit all external calls. Apply egress filtering.' },
  { sev:'HIGH', title:'Prompt injection in PDF parser', path:'parsers/pdf_reader.py:34', cat:'Prompt Injection', engine:'Prompt Injection', score:84, rule:'PI-001', desc:'Instruction override pattern found in processed PDF.', fix:'Sanitize LLM inputs. Apply output filtering.' },
  { sev:'HIGH', title:'Malicious npm: color@1.4.1', path:'package.json:78', cat:'Supply Chain', engine:'Supply Chain', score:82, rule:'SC-001', desc:'color@1.4.1 contains intentional infinite loop.', fix:'Remove package. Use color@1.3.0 or alternatives.' },
  { sev:'HIGH', title:'Shell=True subprocess call', path:'deploy/run.py:45', cat:'Command Injection', engine:'Static Analyzer', score:79, rule:'SA-003', desc:'shell=True enables injection if args are user-controlled.', fix:'Use shell=False with explicit arg list.' },
  { sev:'MEDIUM', title:'Unsafe YAML deserialization', path:'config/loader.py:22', cat:'Deserialization', engine:'Static Analyzer', score:65, rule:'SA-005', desc:'yaml.load() without SafeLoader.', fix:'Replace with yaml.safe_load().' },
  { sev:'MEDIUM', title:'Weak MD5 hash for password', path:'auth/utils.py:88', cat:'Cryptography', engine:'Static Analyzer', score:55, rule:'SA-010', desc:'MD5 is cryptographically broken.', fix:'Use bcrypt, argon2, or SHA-256+salt.' },
  { sev:'MEDIUM', title:'Insecure random for token', path:'auth/tokens.py:34', cat:'Cryptography', engine:'Static Analyzer', score:52, rule:'SA-011', desc:'random module used for security token generation.', fix:'Use secrets.token_hex() or os.urandom().' },
  { sev:'LOW', title:'assert used for auth check', path:'api/middleware.py:67', cat:'Logic Error', engine:'Static Analyzer', score:25, rule:'SA-013', desc:'assert is stripped in optimized mode.', fix:'Replace with explicit if/raise.' },
]

const SEV_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 }

export default function FindingsPage() {
  const [sevFilter, setSevFilter] = useState('ALL')
  const [catFilter, setCatFilter] = useState('ALL')
  const [search, setSearch] = useState('')
  const [expanded, setExpanded] = useState(null)

  const categories = ['ALL', ...new Set(FINDINGS.map(f => f.cat))]
  const sevs = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

  const filtered = FINDINGS
    .filter(f => sevFilter === 'ALL' || f.sev === sevFilter)
    .filter(f => catFilter === 'ALL' || f.cat === catFilter)
    .filter(f => !search || f.title.toLowerCase().includes(search.toLowerCase()) || f.path.toLowerCase().includes(search.toLowerCase()))
    .sort((a, b) => SEV_ORDER[a.sev] - SEV_ORDER[b.sev])

  return (
    <div className="animate-fade-in">
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 18 }}>
        <div>
          <h1 style={{ fontSize: 20, fontWeight: 800 }}>Findings Explorer</h1>
          <p style={{ fontSize: 12, color: 'var(--text2)', marginTop: 2 }}>{filtered.length} findings shown</p>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button className="btn-ghost" style={{ fontSize: 11 }} onClick={() => toast.success('SARIF export ready')}>
            <Download size={12} /> Export SARIF
          </button>
          <button className="btn-ghost" style={{ fontSize: 11 }} onClick={() => toast.success('JSON export ready')}>
            <Download size={12} /> Export JSON
          </button>
        </div>
      </div>

      {/* Filters */}
      <div style={{ display: 'flex', gap: 8, marginBottom: 16, flexWrap: 'wrap' }}>
        <input
          placeholder="Search findings…"
          value={search} onChange={e => setSearch(e.target.value)}
          style={{ background: 'var(--panel)', border: '1px solid var(--border)', color: 'var(--text)', padding: '7px 12px', borderRadius: 8, fontSize: 12, flex: 1, minWidth: 180, fontFamily: 'Sora, sans-serif' }}
        />
        {sevs.map(s => (
          <button key={s} onClick={() => setSevFilter(s)} style={{
            padding: '7px 12px', borderRadius: 8, fontSize: 11, cursor: 'pointer', fontFamily: 'Sora',
            background: sevFilter === s ? 'rgba(59,130,246,0.12)' : 'var(--panel)',
            border: `1px solid ${sevFilter === s ? 'rgba(59,130,246,0.35)' : 'var(--border)'}`,
            color: sevFilter === s ? '#3b82f6' : 'var(--text2)',
          }}>{s}</button>
        ))}
      </div>

      {/* Findings */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
        {filtered.map((f, i) => (
          <div key={i} className="panel-card" style={{ cursor: 'pointer' }} onClick={() => setExpanded(expanded === i ? null : i)}>
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10 }}>
              <span className={`sev-${f.sev}`} style={{ fontSize: 9, fontWeight: 700, padding: '2px 7px', borderRadius: 4, fontFamily: 'JetBrains Mono', whiteSpace: 'nowrap', marginTop: 2 }}>
                {f.sev}
              </span>
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: 13, fontWeight: 600 }}>{f.title}</div>
                <div style={{ fontSize: 11, color: 'var(--text3)', fontFamily: 'JetBrains Mono', marginTop: 2 }}>{f.path}</div>
                <div style={{ display: 'flex', gap: 14, marginTop: 4 }}>
                  <span style={{ fontSize: 11, color: 'var(--text2)' }}>Category: {f.cat}</span>
                  <span style={{ fontSize: 11, color: 'var(--text2)' }}>Engine: {f.engine}</span>
                  <span style={{ fontSize: 11, color: '#3b82f6', fontFamily: 'JetBrains Mono' }}>{f.rule}</span>
                  <span style={{ fontSize: 11, color: '#ef4444' }}>Risk: {f.score}/100</span>
                </div>
              </div>
              <span style={{ fontSize: 12, color: 'var(--text3)', marginTop: 2 }}>{expanded === i ? '▲' : '▼'}</span>
            </div>
            {expanded === i && (
              <div style={{ marginTop: 12, paddingTop: 12, borderTop: '1px solid var(--border)', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }} className="animate-fade-in">
                <div>
                  <div style={{ fontSize: 10, color: 'var(--text3)', marginBottom: 4, textTransform: 'uppercase', letterSpacing: '0.6px' }}>Description</div>
                  <div style={{ fontSize: 12, color: 'var(--text2)' }}>{f.desc}</div>
                </div>
                <div>
                  <div style={{ fontSize: 10, color: 'var(--text3)', marginBottom: 4, textTransform: 'uppercase', letterSpacing: '0.6px' }}>Remediation</div>
                  <div style={{ fontSize: 12, color: '#10b981' }}>{f.fix}</div>
                </div>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}
