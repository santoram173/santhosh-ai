import { useState, useCallback, useRef } from 'react'
import { useDropzone } from 'react-dropzone'
import { Upload, Zap, CheckCircle, Circle, Loader } from 'lucide-react'
import toast from 'react-hot-toast'

const ENGINES = [
  { id: 'file_discovery',    label: 'File Discovery',         desc: 'Collect and classify all target files' },
  { id: 'static_analyzer',   label: 'Static Analyzer',        desc: 'Multi-pass pattern matching & AST inspection' },
  { id: 'taint_flow',        label: 'Taint Flow Analyzer',    desc: 'Track source → transform → sink data paths' },
  { id: 'bash_analyzer',     label: 'Bash / Script Analyzer', desc: 'Detect dangerous shell patterns' },
  { id: 'secrets_scanner',   label: 'Secrets Scanner',        desc: 'API keys, tokens, credentials, private keys' },
  { id: 'bytecode',          label: 'Bytecode Integrity',     desc: 'Detect tampered or malicious compiled assets' },
  { id: 'fraud_intelligence',label: 'Fraud Intelligence',     desc: 'Behavioral anomaly & exfiltration detection' },
  { id: 'llm_enrichment',    label: 'LLM Enrichment',         desc: 'AI-powered false positive reduction & correlation' },
]

const MODES = [
  { id: 'balanced',    label: '⚡ Balanced',    desc: 'Recommended — accurate, fast, balanced noise', badge: 'DEFAULT' },
  { id: 'strict',      label: '🔒 Strict',      desc: 'Maximum coverage, all engines enabled',         badge: 'COMPREHENSIVE' },
  { id: 'permissive',  label: '💨 Permissive',  desc: 'Fast surface scan, minimal noise, CI/CD gates',  badge: 'FAST' },
]

export default function ScanPage() {
  const [mode, setMode] = useState('balanced')
  const [file, setFile] = useState(null)
  const [scanning, setScanning] = useState(false)
  const [progress, setProgress] = useState(0)
  const [stepIdx, setStepIdx] = useState(0)
  const [done, setDone] = useState(false)
  const intervalRef = useRef(null)

  const onDrop = useCallback(accepted => {
    if (accepted.length) { setFile(accepted[0]); setDone(false); setProgress(0) }
  }, [])

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop, multiple: false,
    accept: { 'application/zip': ['.zip'], 'text/x-python': ['.py'], 'application/javascript': ['.js'],
               'text/plain': ['.txt', '.sh', '.yaml', '.yml', '.json', '.env'] }
  })

  const startScan = () => {
    if (!file) { toast.error('Please upload a file or directory first'); return }
    setScanning(true); setDone(false); setProgress(0); setStepIdx(0)
    toast.success(`Starting ${mode} scan on ${file.name}…`)

    let p = 0, s = 0
    intervalRef.current = setInterval(() => {
      p += Math.random() * 3.5 + 0.5
      if (p >= 100) { p = 100; clearInterval(intervalRef.current); setScanning(false); setDone(true); toast.success('Scan complete! 47 findings detected.') }
      s = Math.min(ENGINES.length - 1, Math.floor(p / (100 / ENGINES.length)))
      setProgress(Math.round(p)); setStepIdx(s)
    }, 180)
  }

  return (
    <div className="animate-fade-in" style={{ maxWidth: 800 }}>
      <div style={{ marginBottom: 22 }}>
        <h1 style={{ fontSize: 20, fontWeight: 800 }}>New Scan</h1>
        <p style={{ fontSize: 12, color: 'var(--text2)', marginTop: 2 }}>Upload code, archives, or binaries for deep security analysis</p>
      </div>

      {/* Upload zone */}
      <div {...getRootProps()} style={{
        border: `2px dashed ${isDragActive ? 'rgba(59,130,246,0.6)' : 'rgba(99,179,237,0.18)'}`,
        borderRadius: 14, padding: '36px 24px', textAlign: 'center',
        cursor: 'pointer', transition: 'all 0.2s', marginBottom: 20,
        background: isDragActive ? 'rgba(59,130,246,0.06)' : 'rgba(59,130,246,0.02)',
      }}>
        <input {...getInputProps()} />
        <div style={{ fontSize: 32, marginBottom: 10 }}>{file ? '📄' : '📁'}</div>
        {file ? (
          <>
            <div style={{ fontSize: 15, fontWeight: 700, color: '#10b981' }}>✓ {file.name}</div>
            <div style={{ fontSize: 12, color: 'var(--text2)', marginTop: 4 }}>
              {(file.size / 1024).toFixed(1)} KB — ready to scan
            </div>
          </>
        ) : (
          <>
            <div style={{ fontSize: 15, fontWeight: 700, marginBottom: 6 }}>Drop files or codebase here</div>
            <div style={{ fontSize: 12, color: 'var(--text2)' }}>ZIP, Python, JavaScript, YAML, Bash, APK, DOCX and more</div>
            <button className="btn-primary" style={{ marginTop: 14 }}>Browse Files</button>
          </>
        )}
      </div>

      {/* Scan mode */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12, marginBottom: 20 }}>
        {MODES.map(m => (
          <div key={m.id} onClick={() => setMode(m.id)} style={{
            background: 'var(--panel)', border: `1px solid ${mode === m.id ? 'rgba(59,130,246,0.4)' : 'var(--border)'}`,
            borderRadius: 10, padding: '14px', cursor: 'pointer', transition: 'all 0.2s',
            background: mode === m.id ? 'rgba(59,130,246,0.08)' : 'var(--panel)',
          }}>
            <div style={{ fontSize: 13, fontWeight: 700, marginBottom: 4 }}>{m.label}</div>
            <div style={{ fontSize: 11, color: 'var(--text2)', marginBottom: 8 }}>{m.desc}</div>
            <span style={{ fontSize: 9, color: '#06b6d4', fontFamily: 'JetBrains Mono', background: 'rgba(6,182,212,0.1)', padding: '2px 6px', borderRadius: 4, border: '1px solid rgba(6,182,212,0.2)' }}>
              {m.badge}
            </span>
          </div>
        ))}
      </div>

      {/* Scan button */}
      {!scanning && !done && (
        <button className="btn-primary" style={{ width: '100%', justifyContent: 'center', padding: '12px', fontSize: 14 }} onClick={startScan}>
          <Zap size={16} /> Start Scan
        </button>
      )}

      {/* Progress */}
      {(scanning || done) && (
        <div className="panel-card animate-fade-in">
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10 }}>
            <div style={{ fontSize: 13, fontWeight: 700 }}>
              {done ? '✅ Scan Complete' : `Scanning ${file?.name}…`}
            </div>
            <div style={{ fontSize: 13, fontFamily: 'JetBrains Mono', color: done ? '#10b981' : 'var(--accent)', fontWeight: 700 }}>
              {progress}%
            </div>
          </div>
          <div className="progress-bar" style={{ marginBottom: 10 }}>
            <div className="progress-fill" style={{ width: `${progress}%`, background: done ? '#10b981' : undefined }} />
          </div>
          {!done && (
            <div style={{ fontSize: 11, color: 'var(--text2)', fontFamily: 'JetBrains Mono', marginBottom: 12 }}>
              Running: {ENGINES[stepIdx]?.label}…
            </div>
          )}

          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 7 }}>
            {ENGINES.map((e, i) => {
              const st = done ? 'done' : i < stepIdx ? 'done' : i === stepIdx ? 'running' : 'pending'
              return (
                <div key={e.id} style={{
                  display: 'flex', alignItems: 'center', gap: 5,
                  fontSize: 10, padding: '3px 9px', borderRadius: 5, fontFamily: 'JetBrains Mono',
                  background: st === 'done' ? 'rgba(16,185,129,0.1)' : st === 'running' ? 'rgba(59,130,246,0.1)' : 'rgba(255,255,255,0.03)',
                  border: `1px solid ${st === 'done' ? 'rgba(16,185,129,0.25)' : st === 'running' ? 'rgba(59,130,246,0.25)' : 'var(--border)'}`,
                  color: st === 'done' ? '#10b981' : st === 'running' ? '#3b82f6' : 'var(--text3)',
                  animation: st === 'running' ? 'pulse-dot 1s infinite' : 'none',
                }}>
                  {st === 'done' ? <CheckCircle size={10} /> : st === 'running' ? <Loader size={10} className="animate-spin" /> : <Circle size={10} />}
                  {e.label}
                </div>
              )
            })}
          </div>

          {done && (
            <div style={{ marginTop: 14, padding: '12px 14px', background: 'rgba(16,185,129,0.06)', border: '1px solid rgba(16,185,129,0.2)', borderRadius: 8 }}>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 10 }}>
                {[['Risk Score', '87/100', '#ef4444'], ['Critical', '12', '#ef4444'], ['High', '9', '#f97316'], ['Secrets', '23', '#ef4444']].map(([l, v, c]) => (
                  <div key={l}>
                    <div style={{ fontSize: 10, color: 'var(--text3)', marginBottom: 2 }}>{l}</div>
                    <div style={{ fontSize: 18, fontWeight: 800, fontFamily: 'JetBrains Mono', color: c }}>{v}</div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
