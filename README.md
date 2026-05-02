# 🛡️ Santhosh AI  Security & Fraud Intelligence Platform

<div align="center">

![Santhosh AI Banner](https://img.shields.io/badge/Santhosh_AI-v2.0.0-3b82f6?style=for-the-badge&logo=shield&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-10b981?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.10+-06b6d4?style=for-the-badge&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.111-8b5cf6?style=for-the-badge&logo=fastapi&logoColor=white)
![React](https://img.shields.io/badge/React-18-3b82f6?style=for-the-badge&logo=react&logoColor=white)

**Enterprise-grade AI-powered codebase security scanning, fraud detection, and threat intelligence.**

[🚀 Quick Start](#-quick-start) • [📖 Documentation](#-documentation) • [🔧 CLI Usage](#-cli-usage) • [🐳 Docker](#-docker-deployment) • [📊 Dashboard](#-dashboard)

</div>

---

## 🎯 What is Santhosh AI?

Santhosh AI is a production-ready **Security & Fraud Intelligence Platform** that scans codebases, automation skills, and AI agents for:

- 🔐 **Security vulnerabilities** — injection, RCE, broken auth, insecure deserialization
- 🕵️ **Secrets & credentials** — API keys, tokens, private keys, database passwords
- 🛡️ **Fraud patterns** — data exfiltration, behavioral anomalies, obfuscation
- 📦 **Supply chain risks** — malicious packages, typosquatting, dependency confusion
- 🤖 **Prompt injection** — LLM hijacking in documents, PDFs, and assets
- 📊 **Compliance** — OWASP Top 10, SARIF reporting, audit trails

---

## ✨ Core Capabilities

| Engine | Description |
|--------|-------------|
| **Static Analyzer** | Multi-pass AST + pattern analysis for Python, JS, TS, Java, Go |
| **Taint Flow Analyzer** | Source → transform → sink data path tracking |
| **Bash Analyzer** | Dangerous shell patterns, curl-pipe-shell, privilege escalation |
| **Secrets Scanner** | 84+ credential patterns: AWS, GCP, GitHub, OpenAI, private keys |
| **Fraud Intelligence** | Behavioral anomaly detection with ML hybrid scoring |
| **Supply Chain** | Known malicious packages, typosquatting, postInstall attacks |
| **Prompt Injection** | LLM instruction override patterns in documents and assets |
| **LLM Enrichment** | Claude-powered false-positive reduction and correlation |

---

## 🚀 Quick Start

### Option 1: Docker (Recommended)

```bash
git clone https://github.com/YOUR_USERNAME/santhosh-ai.git
cd santhosh-ai
docker compose up -d
```

Open **http://localhost:3000** for the dashboard, **http://localhost:8000/docs** for the API.

---

### Option 2: Local Development

**Backend:**
```bash
cd backend
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --reload
```

**Frontend:**
```bash
cd frontend
npm install
npm run dev
```

**CLI:**
```bash
pip install -e .
santhosh version
```

---

## 🔧 CLI Usage

```bash
# Scan a directory
santhosh scan ./myproject

# Scan with strict policy
santhosh scan ./myproject --policy strict

# Export SARIF report
santhosh scan ./myproject --output sarif

# Export JSON report
santhosh scan ./myproject --output json

# Generate a policy file
santhosh generate-policy --preset balanced

# Interactive policy TUI
santhosh configure-policy
```

**Exit codes:**
- `0` — No issues or only LOW findings
- `1` — HIGH findings detected
- `2` — CRITICAL findings detected (use for CI/CD gates)

---

## 📊 Dashboard

The React dashboard at **http://localhost:3000** includes:

| Page | Features |
|------|----------|
| **Dashboard** | Risk metrics, finding distribution, file heatmap, live activity feed |
| **Scan** | Drag-and-drop upload, policy selection, real-time engine progress |
| **Findings** | Filterable explorer, severity drilldown, SARIF/JSON export |
| **FraudIntel** | Behavioral radar chart, attack chain timeline, ML anomaly scores |
| **Policy Engine** | Per-rule toggles, preset switcher, YAML preview |
| **Rule Packs** | Pack management, custom upload, metadata browser |
| **CLI / API** | Terminal demo, YAML samples, REST API reference |

---

## 🐳 Docker Deployment

```bash
# Full stack
docker compose up -d

# Backend only
docker compose up backend redis -d

# Check status
docker compose ps

# View logs
docker compose logs -f backend
```

**Services:**
| Service | Port | Description |
|---------|------|-------------|
| `frontend` | 3000 | React dashboard |
| `backend` | 8000 | FastAPI + all engines |
| `redis` | 6379 | Task queue & caching |
| `nginx` | 80 | Reverse proxy |

---

## 🔌 REST API

Base URL: `http://localhost:8000/api/v1`

```bash
# Start a scan
curl -X POST /api/v1/scan/ \
  -F "file=@myproject.zip" \
  -F "policy=balanced"

# Check progress
curl /api/v1/scan/{scan_id}/progress

# Get results
curl /api/v1/scan/{scan_id}

# Export SARIF
curl /api/v1/findings/export/sarif > report.sarif

# Fraud summary
curl /api/v1/fraud/summary
```

Full interactive docs: **http://localhost:8000/docs**

---

## ⚙️ Policy Configuration

Three built-in presets:

| Preset | Use Case | Fail On |
|--------|----------|---------|
| `strict` | Compliance audits, security reviews | MEDIUM |
| `balanced` | General development (default) | HIGH |
| `permissive` | CI/CD gates, quick checks | CRITICAL |

**Custom policy:**
```yaml
# santhosh-policy.yaml
version: "2.0.0"
preset: "balanced"
engines:
  static_analyzer: true
  secrets_scanner: true
  fraud_intelligence: true
thresholds:
  fail_on: "HIGH"
  max_risk_score: 70
```

---

## 📦 Rule Packs

| Pack | Rules | Category |
|------|-------|----------|
| OWASP Top 10 | 127 | Web security |
| Secrets Sentinel | 84 | Credentials |
| FraudShield Pro | 63 | Fraud & behavioral |
| YARA Malware | 218 | Malware detection |
| AI Prompt Guard | 41 | LLM security |
| Supply Chain Intel | 56 | Dependency safety |

**Custom YARA rules:**
```yara
rule MyCustomRule {
    meta:
        id = "CUSTOM-001"
        severity = "HIGH"
    strings:
        $bad = "dangerous_pattern"
    condition:
        $bad
}
```

---

## 🧪 Running Tests

```bash
cd tests
pip install pytest
pytest test_engines.py -v
```

Test coverage includes:
- Static analyzer (eval, exec, shell injection, hardcoded credentials)
- Taint flow (SQL injection, template injection)
- Secrets scanner (AWS, GitHub, OpenAI, private keys)
- Prompt injection (instruction override, role hijacking)
- Fraud intelligence (exfiltration, obfuscation, insider signals)
- Supply chain (malicious npm packages, typosquatting)
- Risk scoring (bounds, weighting, fraud scoring)

---

## 🏗️ Architecture

```
santhosh-ai/
├── backend/                  # FastAPI backend
│   ├── main.py               # App entry point
│   ├── engines/
│   │   ├── analyzers.py      # Static, Taint, Secrets, Prompt engines
│   │   ├── fraud_intelligence.py  # Fraud & supply chain engines
│   │   └── orchestrator.py   # Scan coordination
│   ├── api/                  # FastAPI routers
│   ├── models/               # Pydantic data models
│   └── config/               # Settings
├── frontend/                 # React 18 + Tailwind dashboard
│   └── src/
│       ├── pages/            # Dashboard, Scan, Findings, FraudIntel...
│       └── components/       # Layout, shared UI
├── cli/
│   └── santhosh.py           # CLI tool
├── rules/
│   ├── yara/                 # YARA rule packs
│   └── python/               # Python rule modules
├── policies/                 # YAML policy presets
├── tests/                    # Pytest test suite
├── demo-data/                # Example vulnerable code
├── docker/                   # Docker & nginx config
└── docker-compose.yml
```

---

## 🔐 Security & Enterprise Features

- **RBAC** — Role-based access control (Admin, Analyst, Viewer)
- **Audit logs** — All scan activity timestamped and attributable
- **API key auth** — Bearer token authentication on all endpoints
- **Multi-tenant** — Isolated scan namespaces per organization
- **SARIF export** — Compatible with GitHub Advanced Security
- **Secrets redaction** — Evidence is always redacted in reports

---

## 🤝 Contributing

1. Fork the repo
2. Create a feature branch: `git checkout -b feat/my-new-engine`
3. Commit changes: `git commit -m 'feat: add bytecode integrity engine'`
4. Push: `git push origin feat/my-new-engine`
5. Open a Pull Request

Please run tests before submitting: `pytest tests/ -v`

---

## 📄 License

MIT © 2024 Santhosh AI Team

---

<div align="center">
  Built with ❤️ by the Santhosh AI Team · <a href="http://localhost:8000/docs">API Docs</a> · <a href="http://localhost:3000">Dashboard</a>
</div>
