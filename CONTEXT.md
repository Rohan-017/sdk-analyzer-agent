# SDK Analyzer Agent — Full Session Context

This file consolidates the complete context from all sessions:
- **ses_2795** — Original build session (agent created from scratch)
- **ses_2793** — Analysis, evaluation and improvement session (this session)

Use this file to resume work in any future session by saying:
> "I have an SDK analyzer agent at `/home/jenkins/sdk-analyzer-agent/`. Read CONTEXT.md."

---

## 1. Origin & Requirements (ses_2795)

**Original user request:**
> "I want to create a sdk analyzer agent so it should accept the source code zip file as an input, it should analyze its cosp requirements with open source tools like fossology, it should also create a sbom for that and analyze improvements over that."

**Expanded requirements captured:**
- Accept source code ZIP/archive as input
- Perform COSP (compliance / open source policy) analysis
- Generate SBOM in SPDX and CycloneDX formats
- License scanning via FOSSology (or fallback)
- Vulnerability scanning via Grype / OSV.dev
- Code quality scanning via Semgrep (or fallback)
- Produce HTML dashboard + JSON report
- Work with zero external tools installed (all stages have fallbacks)
- REST API server mode (FastAPI)
- Docker / docker-compose support
- CI/CD gate (exit code 0=PASS, 1=FAIL)

---

## 2. Architecture Design

### Pipeline (6 stages, async)

```
INPUT: source_code.zip / .7z / .tar.gz
         │
         ▼
STAGE 1: Extraction & Detection
  - py7zr (7z), zipfile, tarfile
  - Language detection by extension
  - Build system detection (CMake, Make, npm, pip, etc.)
  - Package manifest discovery
         │
         ├──────────────────────────────────────┐
         ▼                                      ▼
STAGE 2: SBOM Generation            STAGE 3A: License Scan (FOSSology)
  - Syft (primary, not installed)     - FOSSology REST API (optional)
  - Python manifest fallback          - nomos CLI (optional)
  - C component detector (NEW)        - Python regex fallback (active)
  - PyPI license enrichment           - Smart sampling: full SDK dirs,
  - configure.ac parser               sample kernel tree
  - pkg-config .pc parser             
         │                            STAGE 3B: License Cross-validation
         │                              - ScanCode Toolkit (not installed)
         │                              - Python regex fallback (active)
         │
         ▼
STAGE 4: Vulnerability Analysis
  - Grype (primary, not installed)
  - OWASP Dependency-Check (not installed)
  - OSV.dev batch API (active) — PyPI/npm/Go components
  - NVD CPE virtualMatchString (active) — C/embedded components
  - NVD fallback for CVE-* IDs with UNKNOWN severity
         │
         ▼
STAGE 5: Code Quality
  - Semgrep (not installed)
  - Built-in 14-rule regex engine (active)
  - Skips: Documentation/, arch/, scripts/, tools/ (non-executable)
  - Prioritises: tclinux_phoenix/, rdk_hal/, wlan/ (SDK-specific)
         │
         ▼
STAGE 6: Report Generation
  - sdk_analysis_report.json (full)
  - sdk_analysis_report.html (dashboard)
  - sbom.spdx.json
  - sbom.cyclonedx.json
```

### Key design decisions
- Stages 2, 3A, 3B run in parallel via `asyncio.gather`
- Every stage has 2-3 fallback layers — runs with zero external tools
- File sampling caps prevent hour-long hangs on large SDKs:
  - License scan: 50,000 files max (priority: SDK dirs, then kernel sample)
  - Quality scan: 35,000+ SDK-specific files, skip documentation dirs
- C component CVE scanning uses NVD `virtualMatchString` CPE queries

---

## 3. Project Structure

```
/home/jenkins/sdk-analyzer-agent/
├── agent.py                    # Main orchestrator (CLI + Python API)
├── server.py                   # FastAPI REST server
├── Dockerfile                  # Production container
├── docker-compose.yml          # Full stack: FOSSology + PostgreSQL + analyzer
├── requirements.txt
├── README.md
├── CONTEXT.md                  # This file
├── stages/
│   ├── __init__.py
│   ├── extractor.py            # Archive extraction (.zip/.7z/.tar.gz) + detection
│   ├── sbom_generator.py       # SBOM generation + C component detection
│   ├── fossology_scanner.py    # License scanning (FOSSology/nomos/regex)
│   ├── scancode_runner.py      # License cross-validation (ScanCode/regex)
│   ├── vuln_analyzer.py        # CVE scanning (Grype/OWASP/OSV/NVD)
│   ├── quality_checker.py      # Code quality (Semgrep/builtin)
│   └── report_builder.py       # HTML + JSON report builder
├── config/
│   ├── license_policy.yml      # Allow / review / prohibit license rules
│   └── semgrep_rules.yml       # Custom Semgrep security/quality rules
├── templates/                  # Jinja2 HTML report templates
├── tests/
│   └── test_agent.py           # Integration test suite (5 tests, all pass)
└── output/                     # Default report output directory
    └── airoha_v7/              # Latest Airoha SDK analysis results
```

---

## 4. How to Run

### CLI (direct)
```bash
cd /home/jenkins/sdk-analyzer-agent
python agent.py /path/to/sdk.zip --output-dir ./output
python agent.py /path/to/sdk.7z  --output-dir ./output     # .7z supported
python agent.py /path/to/sdk.tar.gz --output-dir ./output  # tar.gz supported
```

### Python API
```python
import asyncio
from agent import SDKAnalyzerAgent

async def main():
    agent = SDKAnalyzerAgent(output_dir="./output")
    report = await agent.analyze("/path/to/sdk.zip")
    print(f"Risk: {report.risk_level} ({report.risk_score}/100)")
    print(f"Compliance: {report.compliance_status}")

asyncio.run(main())
```

### REST API server
```bash
python server.py
# POST http://localhost:8000/analyze  (multipart file upload)
# GET  http://localhost:8000/status/<analysis_id>
# GET  http://localhost:8000/report/<id>/html
# GET  http://localhost:8000/report/<id>         (JSON)
# GET  http://localhost:8000/report/<id>/sbom/spdx
# GET  http://localhost:8000/report/<id>/sbom/cyclonedx
# Swagger UI: http://localhost:8000/docs
```

### Docker (full stack with FOSSology)
```bash
docker-compose up -d
# FOSSology UI: http://localhost:8081  (login: fossy/fossy)
# Analyzer API: http://localhost:8000
```

### Run tests
```bash
cd /home/jenkins/sdk-analyzer-agent
python -m pytest tests/test_agent.py -v   # All 5 tests pass
```

---

## 5. Output Files

Reports are written to `--output-dir` (default: `./output/`):

| File | Format | Size (Airoha) | Contents |
|---|---|---|---|
| `sdk_analysis_report.html` | HTML | 25 KB | Visual dashboard — open in browser |
| `sdk_analysis_report.json` | JSON | ~1 MB | Full machine-readable report |
| `sbom.spdx.json` | SPDX 2.3 | 26 KB | Software Bill of Materials |
| `sbom.cyclonedx.json` | CycloneDX 1.4 | 18 KB | Software Bill of Materials |

### JSON report schema
```
sdk_analysis_report.json
  ├── sdk_name, generated_at, analysis_duration_seconds
  ├── total_source_files, total_size_bytes
  ├── detected_languages, detected_build_systems
  ├── sbom_components[]          ← name, version, type, licenses, purl
  ├── total_components
  ├── license_distribution{}     ← {spdx_id: file_count}
  ├── copyleft_files[]
  ├── files_without_license[]
  ├── license_scanner_used
  ├── top_vulnerabilities[]      ← cve_id, severity, cvss_score, component, description, fix_version
  ├── total_vulnerabilities
  ├── severity_counts{}
  ├── affected_components[]
  ├── vuln_scanner_used
  ├── quality_findings_count
  ├── quality_severity_counts{}
  ├── quality_category_counts{}
  ├── recommendations[]          ← priority, title, description, remediation, affected_files
  ├── risk_score                 ← 0-100
  ├── risk_level                 ← LOW / MEDIUM / HIGH / CRITICAL
  └── compliance_status          ← PASS / FAIL
```

---

## 6. Tools — What's Installed vs Fallbacks

| Tool | Purpose | Status | Fallback |
|---|---|---|---|
| **Syft** | SBOM generation | NOT installed | Python manifest parser + C component detector |
| **Grype** | CVE scanning | NOT installed | OSV.dev API + NVD CPE API |
| **FOSSology** | License scanning | NOT installed | Python SPDX regex scanner |
| **ScanCode** | License cross-validation | NOT installed | Python regex fallback |
| **Semgrep** | Code quality | NOT installed | Built-in 14-rule engine |
| **OWASP DC** | CVE scanning | NOT installed | OSV.dev API |
| **py7zr** | 7z extraction | Installed | — |
| **aiohttp** | Async HTTP | Installed | — |

### To install primary tools (recommended for production)
```bash
# Syft (SBOM — finds C, Go, Rust, Python, system packages)
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# Grype (CVE scan — uses local DB, fully offline after first download)
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
grype db update

# ScanCode (license scan — detects 700+ license types)
pip install scancode-toolkit

# Semgrep (code quality)
pip install semgrep
```

---

## 7. Data Privacy

| Stage | External calls? | What's sent | Offline alternative |
|---|---|---|---|
| Extraction | No | Nothing | Already offline |
| SBOM | No | Nothing | Already offline |
| License scan | No | Nothing | Already offline |
| **Vuln scan (OSV)** | **Yes** | Package name + version only | Install Grype |
| **Vuln scan (NVD)** | **Yes** | CPE string (name + version) | Install Grype |
| **PyPI enrichment** | **Yes** | Package name + version | Disable or use Syft |
| Quality scan | No | Nothing | Already offline |

**Source code never leaves the machine in any mode.**

---

## 8. Airoha SDK Analysis Results (Latest: airoha_v7)

**Input:** `/home/jenkins/airoha-src-rc2.4.1.7z` (392 MB, 154,258 files)
**Output:** `/home/jenkins/sdk-analyzer-agent/output/airoha_v7/`
**Duration:** ~354 seconds

### Summary
| Metric | Value |
|---|---|
| Risk Level | CRITICAL (100/100) |
| Compliance | FAIL |
| Total Components (SBOM) | 226 |
| Component types | PyPI: 83, C-embedded: 128, autoconf: 8, pkg-config: 7 |
| Languages | C, C/C++, Shell, Python, Perl, C++, JavaScript, C#, Java, Lua |
| Build Systems | CMake, Make, Python setuptools |
| Total Vulnerabilities | 228 |
| CRITICAL vulns | 2 |
| HIGH vulns | 18 |
| MEDIUM vulns | 39 |
| Copyleft files | 5,498 |
| Files without license | 17,818 |

### Key C/Embedded Components Found
| Component | Version | Type |
|---|---|---|
| Linux kernel | 5.4.55 | kernel |
| OpenSSL | 1.0.1p, 1.1.1b | c-embedded |
| BusyBox | 1.00, 1.26.2 | c-embedded |
| strongSwan | 5.9.11 | c-embedded |
| wpa_supplicant | 2.7 | c-embedded |
| Mbed TLS | 2.5.1, 2.18.0 | c-embedded |
| U-Boot | 2023.04 | c-embedded |
| iptables | 1.6.1 | c-embedded |
| iproute2 | 4.4.0, 5.10.0 | c-embedded |
| ppp | 2.4.7 | c-embedded |
| linuxptp | 3.1 | c-embedded |
| ARM Trusted Firmware | 2.1, 2.3 | c-embedded |
| OP-TEE OS | 3.21.0 | c-embedded |

### Critical/High Vulnerabilities
| CVE | CVSS | Component | Description |
|---|---|---|---|
| CVE-2018-1000517 | 9.8 CRITICAL | BusyBox 1.26.2 | wget RCE (pre-commit 8e2174e9) |
| CVE-2026-34872 | 9.1 CRITICAL | Mbed TLS 2.18.0 | PRNG seed misuse |
| CVE-2017-16544 | 8.8 HIGH | BusyBox 1.26.2 | Tab autocomplete RCE |
| CVE-2023-41913 | 9.8 | strongSwan 5.9.11 | Buffer overflow (unauthenticated RCE) |
| CVE-2018-1000500 | 8.1 HIGH | BusyBox 1.26.2 | Missing SSL cert validation |
| CVE-2023-0464 | 7.5 HIGH | OpenSSL 1.1.1b | DoS via certificate chain |
| OpenSSL 1.0.1p | multiple | 31 CVEs total | EOL since 2016, includes Heartbleed era |

### License Distribution (top 10)
| License | File Count |
|---|---|
| GPL-2.0+ | 23,846 |
| GPL-2.0 | 23,547 |
| Proprietary | 15,493 |
| GPL-2.0-only | 12,896 |
| BSD-3-Clause | 12,493 |
| GPL-2.0-or-later | 9,634 |
| BSD-2-Clause | 2,073 |
| Apache-2.0 | 1,793 |
| GPL-2.0 WITH Linux-syscall-note | 1,546 |
| Unlicense | 1,016 |

---

## 9. Improvements Applied (ses_2793)

All improvements were applied in iteration. The `airoha_v7` output reflects all of them.

| Fix | What Changed | File |
|---|---|---|
| #1 | C component detection: versioned dirs, kernel Makefile, configure.ac, pkg-config, CMake | `sbom_generator.py` |
| #2 | C/embedded CVE scanning via NVD CPE `virtualMatchString` | `vuln_analyzer.py` |
| #3 | Smart license scan: full SDK dirs + kernel sampling | `fossology_scanner.py` |
| #4 | Skip Documentation/, arch/, scripts/ in quality scanner | `quality_checker.py` |
| #5 | NVD fallback for CVE-* IDs with UNKNOWN severity | `vuln_analyzer.py` |
| #6 | Kernel CVE detection (linux-kernel component in SBOM) | `sbom_generator.py` |
| #7 | .7z archive support via py7zr | `extractor.py` |
| #8 | configure.ac autoconf component parsing | `sbom_generator.py` |
| #9 | SPDX license key normalisation (strip `*/`, parens) | `fossology_scanner.py`, `report_builder.py` |
| #10 | OSV CVSS enrichment (fetch full vuln records) | `vuln_analyzer.py` |
| #11 | PyPI license enrichment via PyPI JSON API | `sbom_generator.py` |
| #12 | SBOM component deduplication | `sbom_generator.py` |

### Before / After Metrics
| Metric | Before (v4) | After (v7) |
|---|---|---|
| SBOM components | 89 | 226 (+154%) |
| C components found | 0 | 143 |
| License files scanned | 20,000 (13%) | 50,000 (32%) |
| Total vulnerabilities | 64 | 228 (+256%) |
| CRITICAL vulns | 0 | 2 |
| HIGH vulns | 10 | 18 |
| Quality false positives | High (kernel docs flagged) | Low (docs skipped) |

---

## 10. Remaining Known Limitations

| Limitation | Impact | Fix |
|---|---|---|
| 166 vulns still UNKNOWN severity | NVD doesn't have CPE match for all | Install Grype (uses full NVD locally) |
| SBOM misses some C components | Versioned-dir heuristic not 100% | Install Syft |
| License scan at 32% coverage | Sampling cap | Install ScanCode |
| No binary analysis | Pre-compiled .o files invisible | Add binwalk/checksec stage |
| No kernel CVE feed | Linux 5.4.55 CVEs not checked | Add kernel.org CVE feed integration |
| Kernel not in SBOM | `linux-kernel` component found but CVE lookup returns 0 | NVD CPE for kernel uses `linux:linux_kernel` — needs verification |

---

## 11. Dependencies

```
# requirements.txt
aiohttp>=3.9
fastapi>=0.104
uvicorn>=0.24
python-multipart>=0.0.6
pydantic>=2.0
pytest>=7.4
pytest-asyncio>=0.21
httpx>=0.25
pyyaml>=6.0
py7zr>=0.22      # 7z archive support (added in this session)
```

Install:
```bash
pip install -r /home/jenkins/sdk-analyzer-agent/requirements.txt
pip install py7zr  # if not already installed
```

---

## 12. Session History

| Session | ID | Date | What happened |
|---|---|---|---|
| Original build | ses_2795 | 2026-04-13 | Agent designed and built from scratch, all 5 tests passing |
| Analysis + improvements | ses_2793 | 2026-04-13 | Ran on Airoha SDK, identified 8 gaps, applied all improvements, re-ran 4 times (v4→v7) |
