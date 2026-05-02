// RulePacksPage.jsx
import toast from 'react-hot-toast'

const PACKS = [
  { id:'owasp-top10',       name:'OWASP Top 10',         rules:127, author:'Santhosh AI', version:'2024.1', tags:['injection','xss','broken-auth','deserialization','ssrf'],   active:true,  desc:'Comprehensive coverage of the OWASP Top 10 vulnerabilities including SQL injection, XSS, broken authentication, insecure deserialization, and SSRF.' },
  { id:'secrets-sentinel',  name:'Secrets Sentinel',     rules:84,  author:'Santhosh AI', version:'1.5.0',  tags:['api-keys','tokens','credentials','pem','env-vars'],          active:true,  desc:'Detects 84+ secret patterns including AWS, GCP, Azure, GitHub, OpenAI, Stripe, Twilio keys, private certs, and database connection strings.' },
  { id:'fraudshield-pro',   name:'FraudShield Pro',      rules:63,  author:'Santhosh AI', version:'2.1.0',  tags:['exfiltration','behavioral','supply-chain','obfuscation'],    active:true,  desc:'Advanced fraud detection covering data exfiltration, behavioral anomalies, supply chain attacks, and code obfuscation patterns.' },
  { id:'yara-malware',      name:'YARA Malware Pack',    rules:218, author:'Community',   version:'3.0.0',  tags:['malware','ransomware','trojan','rootkit','cryptominer'],      active:true,  desc:'218 YARA rules from the community covering common malware families, ransomware, trojans, rootkits, and cryptominer patterns.' },
  { id:'ai-prompt-guard',   name:'AI Prompt Guard',      rules:41,  author:'Santhosh AI', version:'1.0.0',  tags:['prompt-injection','llm','jailbreak','instruction-override'], active:true,  desc:'Specialized ruleset for detecting prompt injection attacks, LLM jailbreak attempts, and instruction override patterns in documents and assets.' },
  { id:'supply-chain-intel',name:'Supply Chain Intel',   rules:56,  author:'Santhosh AI', version:'1.3.0',  tags:['dependency','typosquat','compromise','malicious-npm'],       active:true,  desc:'Identifies compromised dependencies, typosquatting attacks, dependency confusion, and known malicious npm/pip packages from threat feeds.' },
]

export function RulePacksPage() {
  return (
    <div className="animate-fade-in">
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 18 }}>
        <div>
          <h1 style={{ fontSize: 20, fontWeight: 800 }}>Rule Pack Manager</h1>
          <p style={{ fontSize: 12, color: 'var(--text2)', marginTop: 2 }}>
            {PACKS.length} packs active · {PACKS.reduce((a, p) => a + p.rules, 0)} total rules
          </p>
        </div>
        <button className="btn-primary" style={{ fontSize: 11, padding: '7px 14px' }} onClick={() => toast.success('Upload feature coming soon!')}>
          + Upload Custom Pack
        </button>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 14 }}>
        {PACKS.map(p => (
          <div key={p.id} className="panel-card" style={{ cursor: 'pointer', transition: 'border-color 0.2s' }}>
            <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 8 }}>
              <div style={{ fontSize: 14, fontWeight: 700 }}>{p.name}</div>
              <span style={{ background: 'rgba(16,185,129,0.12)', color: '#10b981', fontSize: 10, padding: '2px 8px', borderRadius: 4, border: '1px solid rgba(16,185,129,0.25)', fontFamily: 'JetBrains Mono', fontWeight: 700, flexShrink: 0 }}>
                ACTIVE
              </span>
            </div>
            <div style={{ fontSize: 12, color: 'var(--text2)', marginBottom: 10, lineHeight: 1.5 }}>{p.desc}</div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 10 }}>
              <span style={{ fontSize: 11, fontFamily: 'JetBrains Mono', color: '#3b82f6', fontWeight: 700 }}>{p.rules} rules</span>
              <span style={{ fontSize: 11, color: 'var(--text3)' }}>by {p.author}</span>
              <span style={{ fontSize: 11, color: 'var(--text3)' }}>v{p.version}</span>
            </div>
            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
              {p.tags.map(t => (
                <span key={t} style={{ fontSize: 10, padding: '2px 7px', borderRadius: 4, background: 'rgba(255,255,255,0.04)', color: 'var(--text2)', border: '1px solid var(--border)' }}>
                  {t}
                </span>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

export default RulePacksPage

// ─────────────────────────────────────────────
// CLIPage.jsx
export function CLIPage() {
  const COMMANDS = [
    { cmd: 'santhosh scan ./myproject', out: [
      ['out','  Santhosh AI v2.0.0 — Security & Fraud Intelligence'],
      ['out','  ─────────────────────────────────────────────────'],
      ['out','  [✓] Loading policy: balanced'],
      ['out','  [✓] Initializing 8 analysis engines'],
      ['out','  [→] Scanning 3,847 files...'],
      ['out',''],
      ['warn',' [WARN] SS-007: Hardcoded password in config.py:14'],
      ['err', ' [CRIT] TF-001: Taint flow: user input → SQL sink'],
      ['err', ' [CRIT] FRD-001: Data exfiltration pattern detected'],
      ['warn',' [HIGH] SC-001: Malicious package: color@1.4.1'],
      ['out',''],
      ['suc', '  SCAN COMPLETE — Risk Score: 87/100 [CRITICAL]'],
      ['out','  Findings: 12 Critical, 9 High, 18 Medium, 8 Low'],
      ['out','  Report: ./santhosh-report.sarif'],
    ]},
    { cmd: 'santhosh generate-policy --preset strict', out: [
      ['suc','  [✓] Policy generated: santhosh-policy-strict.yaml'],
    ]},
    { cmd: 'santhosh scan ./app --policy strict --output json', out: [
      ['out','  [→] Running strict scan...'],
      ['suc','  [✓] JSON report saved: santhosh-report-1714000000.json'],
    ]},
  ]

  const YAML_SAMPLE = `# Santhosh AI Policy Configuration v2.0.0
version: "2.0.0"
preset: "balanced"

engines:
  static_analyzer: true
  taint_flow: true
  secrets_scanner: true
  fraud_detection: true
  supply_chain: true
  prompt_injection: true
  bytecode_integrity: false
  bash_analyzer: true

thresholds:
  fail_on: "HIGH"
  max_risk_score: 70
  max_fraud_score: 60

fraud:
  behavioral_anomaly: true
  ml_scoring: true
  exfil_detection: true
  supply_chain_check: true
  insider_threat: true
  obfuscation_detection: true

llm_enrichment:
  enabled: true
  phase: 2
  false_positive_reduction: true
  correlation_grouping: true

reporting:
  formats: ["sarif", "json", "html"]
  include_remediation: true
  include_evidence: true`

  return (
    <div className="animate-fade-in">
      <h1 style={{ fontSize: 20, fontWeight: 800, marginBottom: 4 }}>CLI & API Reference</h1>
      <p style={{ fontSize: 12, color: 'var(--text2)', marginBottom: 20 }}>Full command-line interface and REST API documentation</p>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        {/* Terminal */}
        <div>
          <div style={{ fontSize: 12, fontWeight: 700, marginBottom: 10, color: 'var(--text2)', textTransform: 'uppercase', letterSpacing: '0.8px' }}>CLI Terminal</div>
          <div style={{ background: '#000', border: '1px solid rgba(99,179,237,0.18)', borderRadius: 12, overflow: 'hidden' }}>
            <div style={{ padding: '10px 14px', background: 'rgba(255,255,255,0.03)', display: 'flex', alignItems: 'center', gap: 8, borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
              <div style={{ display: 'flex', gap: 6 }}>
                {['#ef4444','#f59e0b','#10b981'].map(c => <div key={c} style={{ width: 10, height: 10, borderRadius: '50%', background: c }} />)}
              </div>
              <span style={{ fontSize: 11, color: 'var(--text3)', fontFamily: 'JetBrains Mono' }}>santhosh-cli</span>
            </div>
            <div style={{ padding: '14px 16px', fontFamily: 'JetBrains Mono', fontSize: 11, lineHeight: 1.9 }}>
              {COMMANDS.map((c, ci) => (
                <div key={ci} style={{ marginBottom: 8 }}>
                  <div><span style={{ color: '#06b6d4' }}>$ </span><span style={{ color: '#e2e8f0' }}>{c.cmd}</span></div>
                  {c.out.map(([type, line], li) => (
                    <div key={li} style={{
                      color: type === 'err' ? '#ef4444' : type === 'warn' ? '#f59e0b' : type === 'suc' ? '#10b981' : '#64748b'
                    }}>{line}</div>
                  ))}
                </div>
              ))}
              <span style={{ color: '#06b6d4' }}>$ </span><span style={{ color: '#e2e8f0', borderRight: '2px solid #3b82f6', animation: 'pulse 1s infinite' }}>_</span>
            </div>
          </div>
        </div>

        {/* YAML + API */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          <div>
            <div style={{ fontSize: 12, fontWeight: 700, marginBottom: 10, color: 'var(--text2)', textTransform: 'uppercase', letterSpacing: '0.8px' }}>Sample Policy YAML</div>
            <div style={{ background: 'rgba(0,0,0,0.4)', border: '1px solid var(--border)', borderRadius: 10, padding: '14px 16px', fontFamily: 'JetBrains Mono', fontSize: 11, lineHeight: 1.7, maxHeight: 240, overflowY: 'auto' }}>
              {YAML_SAMPLE.split('\n').map((line, i) => (
                <div key={i} style={{
                  color: line.startsWith('#') ? '#475569' : line.includes(':') && !line.startsWith(' ') ? '#60a5fa' :
                    line.includes(': true') || line.includes(': false') ? '#e2e8f0' : '#94a3b8'
                }}>
                  {line.replace(/: (true|false)/g, (_, v) => `: <span style="color:#34d399">${v}</span>`)}
                  {line}
                </div>
              ))}
            </div>
          </div>

          <div className="panel-card">
            <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text2)', textTransform: 'uppercase', letterSpacing: '0.8px', marginBottom: 12 }}>REST API Endpoints</div>
            {[
              ['POST', '/api/v1/scan/', 'Upload file and start scan'],
              ['GET',  '/api/v1/scan/{id}', 'Get scan result by ID'],
              ['GET',  '/api/v1/scan/{id}/progress', 'Real-time scan progress'],
              ['GET',  '/api/v1/findings/', 'Query all findings'],
              ['GET',  '/api/v1/findings/export/sarif', 'Export SARIF report'],
              ['GET',  '/api/v1/policy/{preset}', 'Get policy configuration'],
              ['GET',  '/api/v1/fraud/summary', 'Fraud intelligence summary'],
              ['GET',  '/api/v1/rules/', 'List all rule packs'],
            ].map(([method, path, desc]) => (
              <div key={path} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '7px 0', borderBottom: '1px solid var(--border)' }}>
                <span style={{
                  fontSize: 9, fontFamily: 'JetBrains Mono', fontWeight: 700, padding: '2px 6px', borderRadius: 3, flexShrink: 0,
                  background: method === 'POST' ? 'rgba(59,130,246,0.15)' : 'rgba(16,185,129,0.12)',
                  color: method === 'POST' ? '#3b82f6' : '#10b981',
                  border: `1px solid ${method === 'POST' ? 'rgba(59,130,246,0.3)' : 'rgba(16,185,129,0.25)'}`,
                }}>{method}</span>
                <span style={{ fontSize: 11, fontFamily: 'JetBrains Mono', color: 'var(--text2)', flex: 1 }}>{path}</span>
                <span style={{ fontSize: 10, color: 'var(--text3)' }}>{desc}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}

export default CLIPage
