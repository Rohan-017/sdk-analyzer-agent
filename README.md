# SDK Analyzer Agent

Analyzes source-code ZIP files for SBOM, license compliance, vulnerability exposure, and code quality improvements.

## Pipeline

```
ZIP Input
  │
  ├─ Stage 1:  Extraction + language/build-system detection
  ├─ Stage 2:  SBOM generation (Syft → SPDX + CycloneDX)
  ├─ Stage 3A: License scan (FOSSology REST API / nomos / Python fallback)
  ├─ Stage 3B: License cross-validation (ScanCode / Python fallback)
  ├─ Stage 4:  Vulnerability analysis (Grype / OWASP DC / OSV.dev API)
  ├─ Stage 5:  Code quality + improvements (Semgrep / built-in rules)
  └─ Stage 6:  Report builder → JSON + HTML dashboard
```

## Quick Start

### CLI
```bash
pip install -r requirements.txt
python agent.py my_sdk.zip --output-dir ./output
```

### API Server
```bash
pip install -r requirements.txt
python server.py
# → http://localhost:8000/docs
```

### Docker Compose (full stack with FOSSology)
```bash
docker-compose up -d
# FOSSology UI  → http://localhost:8081
# Analyzer API  → http://localhost:8000/docs
```

## API Usage

```bash
# Upload ZIP for analysis
curl -X POST http://localhost:8000/analyze \
  -F "file=@my_sdk.zip"
# Returns: {"analysis_id": "...", "status": "queued"}

# Poll status
curl http://localhost:8000/status/<analysis_id>

# Get HTML report
curl http://localhost:8000/report/<analysis_id>/html > report.html

# Get JSON report
curl http://localhost:8000/report/<analysis_id> > report.json

# Download SBOM
curl http://localhost:8000/report/<analysis_id>/sbom/cyclonedx > sbom.json
```

## Environment Variables

| Variable            | Description                         | Default       |
|---------------------|-------------------------------------|---------------|
| `FOSSOLOGY_URL`     | FOSSology server URL                | (disabled)    |
| `FOSSOLOGY_TOKEN`   | FOSSology API bearer token          | (disabled)    |
| `OUTPUT_DIR`        | Report output directory             | `./output`    |
| `PORT`              | API server port                     | `8000`        |

## New: EPSS Exploit Prediction, Transitive Dependencies, Scan Diffing

- **EPSS scoring**: every CVE is enriched with a FIRST.org EPSS score/percentile
  (probability of real-world exploitation in the next 30 days). CVEs with
  EPSS ≥ 50% are flagged `actively_exploited_vulnerabilities` and weighted into
  the risk score independently of CVSS severity.
- **Direct vs. transitive dependencies**: SBOM components carry `is_direct` and
  `depth` fields, computed from the CycloneDX dependency graph (Syft) or parsed
  lockfiles (`package-lock.json`, `yarn.lock`, `poetry.lock`, `Pipfile.lock`,
  `Gemfile.lock`, `Cargo.lock`, `go.sum`) in fallback mode.
- **Scan diffing / baselines**:
  ```bash
  python agent.py my_sdk_v2.zip --baseline ./v1_output/sdk_analysis_report.json
  # → writes scan_diff.json: new/resolved vulns, added/removed components, risk trend
  # CI gate also fails (exit 1) if the diff introduces a new CRITICAL/HIGH CVE
  ```

## New: Interactive Dashboard — Charts, Trend/Diff View, Dark Mode

The HTML report (`sdk_analysis_report.html`) is a self-contained, offline-viewable
dashboard — all charts are drawn with a small vanilla-JS canvas engine embedded in
the file itself (no CDN / external chart library), so it still works air-gapped.

- **Charts**: risk-score gauge, vulnerability severity donut, SBOM component-type
  donut, top-10 license bar chart, quality-findings category donut, and an
  **EPSS-vs-CVSS scatter plot** that visually separates "actively exploited" CVEs
  (high EPSS) from merely high-severity ones so you can triage what matters first.
- **Risk trend line**: every run appends a snapshot to `output/risk_history.json`;
  once a second run exists for the same SDK, a trend line chart shows risk score
  over time automatically — no `--baseline` flag required.
- **Trend / Diff tab**: when `--baseline` is used, the dashboard gains a "Trend"
  nav tab rendering the verdict banner, a before/after risk bar chart, and
  side-by-side tables of new/resolved vulnerabilities and new/removed components
  (previously this data was only in `scan_diff.json`).
- **Sortable tables**: click any column header (SBOM, vulnerabilities) to sort
  ascending/descending.
- **Tabbed navigation + pagination**: the nav bar switches between real content
  tabs (Overview / SBOM / Vulnerabilities / Licenses / Quality / Recommendations)
  instead of just scrolling the same long page, and the SBOM table is paginated
  (25/50/100/All rows per page) so large component lists don't require endless
  scrolling. Printing/exporting still renders every tab at once.
- **Dark mode + print/export**: theme toggle persisted via `localStorage`, and a
  one-click "Export / Print" button (print-optimized CSS hides nav/controls) for
  generating a PDF via the browser's print dialog.

## Tool Fallback Chain

Each stage degrades gracefully when tools are not installed:

| Stage           | Primary         | Fallback 1     | Fallback 2          |
|-----------------|-----------------|----------------|---------------------|
| SBOM            | Syft            | —              | Python manifest scan |
| License scan    | FOSSology API   | nomos CLI      | Python regex scan    |
| License cross   | ScanCode CLI    | —              | Python regex scan    |
| Vulnerabilities | Grype           | OWASP DC       | OSV.dev REST API     |
| Quality         | Semgrep         | —              | Built-in rule engine |

## Output Files

```
output/
├── sdk_analysis_report.json    # Full machine-readable report (nested schema, see below)
├── sdk_analysis_report.html    # HTML dashboard (tabbed nav, charts, trend, dark mode)
├── sbom.spdx.json              # SPDX 2.3 SBOM
├── sbom.cyclonedx.json         # CycloneDX 1.4 SBOM
├── risk_history.json           # Risk score snapshot per run (last 30), powers trend chart
├── scan_diff.json              # Only written when --baseline is passed
├── grype_output.json           # Raw Grype findings
├── scancode_output.json        # Raw ScanCode findings
└── semgrep_output.json         # Raw Semgrep findings
```

Each run overwrites the files above in place — pass a different `--output-dir` yourself
if you want to keep multiple runs side by side.

### JSON report schema

`sdk_analysis_report.json` is organized into clearly named top-level sections
instead of one large flat object, so it's easy to consume programmatically or
just skim by eye:

```
{
  "schema_version": "2.0",
  "sdk_name": "...", "generated_at": "...", "analysis_duration_seconds": ...,
  "executive_summary": { "headline": "...", "risk_level", "risk_score",
                         "compliance_status", "totals": {...} },
  "metadata":        { source_files, size_mb, languages, build_systems },
  "sbom":            { spdx_path, cyclonedx_path, total_components, components, ... },
  "licenses":        { scanner_used, distribution, copyleft_files, files_without_license },
  "vulnerabilities": { scanner_used, total, severity_counts, top_findings, actively_exploited },
  "quality":         { scanner_used, total_findings, severity_counts, category_counts,
                       findings, recommendations },
  "risk":            { score, level, compliance_status }
}
```

`executive_summary` gives a one-glance, human-readable verdict for anyone
reading the JSON directly (CI logs, dashboards, chatops). `quality.findings`
is capped at 500 entries (worst severity first); `quality.total_findings`
always reflects the true, uncapped count.

## Running Tests

```bash
pip install pytest pytest-asyncio pyyaml
pytest tests/ -v
```
