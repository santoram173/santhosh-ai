# Changelog

All notable changes to Santhosh AI are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [2.0.0] — 2024-12-01

### Added
- 🚀 Full production-grade platform launch
- 8-engine analysis framework (Static, Taint, Bash, Bytecode, Secrets, Supply Chain, Prompt Injection, Fraud Intelligence)
- YAML-based policy engine with strict/balanced/permissive presets
- React 18 + Tailwind dashboard with dark cybersecurity aesthetic
- FraudIntel Mode with behavioral anomaly detection and ML hybrid scoring
- LLM enrichment phase powered by Claude (Phase 2 analysis)
- SARIF 2.1.0 export for GitHub Advanced Security integration
- CLI tool: `santhosh scan`, `generate-policy`, `configure-policy`
- Docker Compose full-stack deployment
- 6 modular rule packs (589 total rules)
- Comprehensive test suite (35+ test cases)
- Supply chain attack detection (typosquatting, malicious packages)
- Prompt injection detection for LLM-powered applications
- Risk scoring model with severity-weighted scoring
- Fraud score computed independently from security risk score
- RBAC foundation (Admin, Analyst, Viewer roles)
- Audit trail for all scan activity
- GitHub Actions CI/CD workflow
- Architecture and deployment documentation

### Engines
- **Static Analyzer**: 12 Python + 4 JavaScript + 5 Bash rules
- **Taint Flow**: 5 source-sink pairs tracked
- **Secrets Scanner**: 10 patterns (AWS, GCP, GitHub, OpenAI, private keys, DB URLs)
- **Prompt Injection**: 6 injection patterns
- **Fraud Intelligence**: Exfiltration, social engineering, insider threat, obfuscation
- **Supply Chain**: Known malicious package DB + typosquatting detection

## [1.0.0] — 2024-06-01 (Skill Scanner 1.0)

### Added
- Initial release of Skill Scanner
- Basic static analysis
- Simple secrets detection
- JSON output

---

*Santhosh AI is inspired by and named in honor of the project vision. Built with FastAPI, React, and Claude AI.*
