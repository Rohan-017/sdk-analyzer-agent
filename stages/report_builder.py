"""
Stage 6: Report Aggregation and Generation
Produces a unified JSON report and an HTML dashboard.
"""

import datetime
import json
import logging
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import yaml as _yaml
    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False

from . import diff_engine

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Unified data model
# ---------------------------------------------------------------------------

@dataclass
class AnalysisReport:
    sdk_name: str
    generated_at: str
    analysis_duration_seconds: float

    # Extraction
    total_source_files: int = 0
    total_size_bytes: int = 0
    detected_languages: List[str] = field(default_factory=list)
    detected_build_systems: List[str] = field(default_factory=list)

    # SBOM
    sbom_spdx_path: str = ""
    sbom_cyclonedx_path: str = ""
    total_components: int = 0
    license_summary: Dict[str, int] = field(default_factory=dict)
    sbom_components: List[Dict[str, Any]] = field(default_factory=list)
    direct_components_count: int = 0
    transitive_components_count: int = 0

    # License compliance
    license_distribution: Dict[str, int] = field(default_factory=dict)
    copyleft_files: List[str] = field(default_factory=list)
    files_without_license: List[str] = field(default_factory=list)
    license_scanner_used: str = ""

    # Vulnerabilities
    total_vulnerabilities: int = 0
    severity_counts: Dict[str, int] = field(default_factory=dict)
    affected_components: List[str] = field(default_factory=list)
    top_vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    actively_exploited_vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    vuln_scanner_used: str = ""

    # Quality
    quality_findings_count: int = 0
    quality_severity_counts: Dict[str, int] = field(default_factory=dict)
    quality_category_counts: Dict[str, int] = field(default_factory=dict)
    quality_findings: List[Dict[str, Any]] = field(default_factory=list)
    recommendations: List[Dict[str, Any]] = field(default_factory=list)
    quality_scanner_used: str = ""

    # Overall risk
    risk_score: float = 0.0      # 0-100
    risk_level: str = "UNKNOWN"  # LOW / MEDIUM / HIGH / CRITICAL
    compliance_status: str = "UNKNOWN"


# ---------------------------------------------------------------------------
# Report builder
# ---------------------------------------------------------------------------

class ReportBuilder:

    SEVERITY_WEIGHTS = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 0.5, "UNKNOWN": 0.5}

    def __init__(self, output_dir: str, templates_dir: Optional[str] = None):
        self.output_dir    = Path(output_dir)
        self.templates_dir = Path(templates_dir) if templates_dir else Path(__file__).parent.parent / "templates"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._license_policy = self._load_license_policy()

    # ------------------------------------------------------------------
    # License policy loader
    # ------------------------------------------------------------------

    @staticmethod
    def _load_license_policy() -> Dict[str, Any]:
        """Load config/license_policy.yml. Returns empty dict on failure."""
        policy_path = Path(__file__).parent.parent / "config" / "license_policy.yml"
        if not policy_path.exists():
            return {}
        if not _YAML_AVAILABLE:
            logger.warning("pyyaml not installed — license_policy.yml will not be applied")
            return {}
        try:
            with open(policy_path) as f:
                return _yaml.safe_load(f) or {}
        except Exception as exc:
            logger.warning("Failed to load license_policy.yml: %s", exc)
            return {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def build(
        self,
        extraction_result,
        sbom_result,
        fossology_result,
        scancode_result,
        vuln_result,
        quality_result,
        duration_seconds: float,
        baseline_report: Optional[str] = None,
    ) -> AnalysisReport:

        report = AnalysisReport(
            sdk_name=extraction_result.sdk_name,
            generated_at=datetime.datetime.utcnow().isoformat() + "Z",
            analysis_duration_seconds=round(duration_seconds, 2),
        )

        self._fill_extraction(report, extraction_result)
        self._fill_sbom(report, sbom_result)
        self._fill_license(report, fossology_result, scancode_result)
        self._fill_vulnerabilities(report, vuln_result)
        self._fill_quality(report, quality_result)
        self._compute_risk(report)

        # Optional: diff against a baseline report from a previous scan. Computed
        # here (rather than by the caller) so the diff can be rendered directly
        # into the HTML dashboard's Trend tab, not just written as raw JSON.
        diff: Optional[Dict[str, Any]] = None
        if baseline_report:
            baseline = diff_engine.load_baseline(baseline_report)
            if baseline is not None:
                diff = diff_engine.build_diff(self._to_nested_dict(report), baseline)
                diff_path = str(self.output_dir / "scan_diff.json")
                diff_engine.write_diff(diff, diff_path)
                logger.info("Scan diff written: %s (%s)", diff_path, diff["verdict"])

        # Track risk score across runs of the same SDK so the dashboard can plot
        # a trend line even without an explicit --baseline comparison.
        risk_history = self._update_risk_history(report)

        # Write outputs
        json_path = str(self.output_dir / "sdk_analysis_report.json")
        html_path = str(self.output_dir / "sdk_analysis_report.html")

        self._write_json(report, json_path)
        self._write_html(report, html_path, diff=diff, risk_history=risk_history)

        logger.info("Reports written: %s, %s", json_path, html_path)
        return report

    # ------------------------------------------------------------------
    # Risk history (for trend chart)
    # ------------------------------------------------------------------

    def _update_risk_history(self, report: AnalysisReport, max_entries: int = 30) -> List[Dict[str, Any]]:
        """
        Append this run's risk snapshot to output_dir/risk_history.json and
        return the full (capped) history, oldest first, for trend charting.
        """
        history_path = self.output_dir / "risk_history.json"
        history: List[Dict[str, Any]] = []
        if history_path.exists():
            try:
                with open(history_path) as f:
                    history = json.load(f)
            except Exception as exc:
                logger.warning("Failed to read risk_history.json: %s", exc)
                history = []

        history.append({
            "sdk_name":              report.sdk_name,
            "generated_at":          report.generated_at,
            "risk_score":            report.risk_score,
            "risk_level":            report.risk_level,
            "compliance_status":     report.compliance_status,
            "total_vulnerabilities": report.total_vulnerabilities,
            "total_components":      report.total_components,
        })
        history = history[-max_entries:]

        try:
            with open(history_path, "w") as f:
                json.dump(history, f, indent=2)
        except Exception as exc:
            logger.warning("Failed to write risk_history.json: %s", exc)

        return history

    # ------------------------------------------------------------------
    # Fill helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _fill_extraction(report: AnalysisReport, ex) -> None:
        report.total_source_files    = ex.total_files
        report.total_size_bytes      = ex.total_size_bytes
        report.detected_languages    = ex.languages
        report.detected_build_systems = ex.build_systems

    @staticmethod
    def _fill_sbom(report: AnalysisReport, sbom) -> None:
        report.sbom_spdx_path      = sbom.spdx_path
        report.sbom_cyclonedx_path = sbom.cyclonedx_path
        report.total_components    = sbom.total_components
        report.license_summary     = sbom.license_summary
        # Serialize components list for report consumers
        report.sbom_components = [
            {
                "name":         c.name,
                "version":      c.version,
                "type":         c.package_type,
                "licenses":     c.licenses,
                "purl":         c.purl,
                "is_direct":    c.is_direct,
                "depth":        c.depth,
            }
            for c in sbom.components
        ]
        report.direct_components_count = sum(1 for c in sbom.components if c.is_direct)
        report.transitive_components_count = sum(1 for c in sbom.components if not c.is_direct)

    @staticmethod
    def _normalize_license_key(raw: str) -> str:
        """
        Collapse noisy SPDX variants into canonical identifiers.
        e.g. 'GPL-2.0 */' → 'GPL-2.0', '(GPL-2.0-only OR BSD-2-Clause) */' → 'GPL-2.0-only OR BSD-2-Clause'
        """
        import re as _re
        s = raw.strip()
        # Strip trailing C-comment close: */ with optional whitespace
        s = _re.sub(r'\s*\*/?\s*$', '', s)
        # Strip surrounding parens
        s = s.strip()
        if s.startswith('(') and s.endswith(')'):
            s = s[1:-1].strip()
        # Normalise tabs → space
        s = _re.sub(r'\t+', ' ', s)
        # Strip stray comment chars at start
        s = _re.sub(r'^/\*\s*', '', s)
        # Normalise "GPL-2.0 WITH Linux-syscall-note" → keep as-is (valid SPDX exception)
        return s.strip()

    @staticmethod
    def _fill_license(report: AnalysisReport, fossology, scancode) -> None:
        # Merge distributions from both scanners, normalising noisy keys
        raw_merged: Dict[str, int] = {}
        for dist in (fossology.license_distribution, scancode.license_distribution):
            for k, v in dist.items():
                raw_merged[k] = raw_merged.get(k, 0) + v

        # Normalise keys and re-aggregate
        normalised: Dict[str, int] = {}
        for raw_key, count in raw_merged.items():
            canonical = ReportBuilder._normalize_license_key(raw_key)
            if canonical:  # skip empty strings
                normalised[canonical] = normalised.get(canonical, 0) + count

        # Sort by count descending
        report.license_distribution   = dict(sorted(normalised.items(), key=lambda x: -x[1]))
        report.copyleft_files         = list(set(fossology.copyleft_files))
        report.files_without_license  = list(set(fossology.files_without_license))
        report.license_scanner_used   = f"{fossology.scanner_used} + {scancode.scanner_used}"

    @staticmethod
    def _fill_vulnerabilities(report: AnalysisReport, vuln) -> None:
        report.total_vulnerabilities = vuln.total_vulnerabilities
        report.severity_counts       = vuln.severity_counts
        report.affected_components   = vuln.affected_components
        report.vuln_scanner_used     = vuln.scanner_used

        # Top 20 vulns sorted by a combined CVSS + EPSS priority score, so an
        # actively-exploited MEDIUM CVE (high EPSS) ranks ahead of an
        # unexploited CRITICAL one on raw severity alone.
        def _priority(f) -> float:
            return f.cvss_score + (f.epss_score * 10.0)

        sorted_findings = sorted(vuln.findings, key=_priority, reverse=True)
        report.top_vulnerabilities = [
            {
                "cve_id":            f.cve_id,
                "severity":          f.severity,
                "cvss_score":        f.cvss_score,
                "epss_score":        round(f.epss_score, 5),
                "epss_percentile":   round(f.epss_percentile, 3),
                "component_name":    f.component_name,
                "component_version": f.component_version,
                "component":         f"{f.component_name}@{f.component_version}",
                "description":       f.description,
                "fix_version":       f.fix_version,
                "source":            f.source,
            }
            for f in sorted_findings[:20]
        ]
        # Actively-exploited-in-the-wild CVEs (EPSS >= 0.5) surfaced separately
        # so they can be triaged first regardless of CVSS severity bucket.
        report.actively_exploited_vulnerabilities = [
            v for v in report.top_vulnerabilities if v["epss_score"] >= 0.5
        ]

    @staticmethod
    def _fill_quality(report: AnalysisReport, quality) -> None:
        report.quality_findings_count  = quality.total_findings
        report.quality_severity_counts = quality.severity_counts
        report.quality_category_counts = quality.category_counts
        report.quality_scanner_used    = quality.scanner_used
        report.recommendations         = [
            {
                "priority":       r.priority,
                "category":       r.category,
                "title":          r.title,
                "description":    r.description,
                "remediation":    r.remediation,
                "affected_files": r.affected_files[:10],
            }
            for r in quality.recommendations
        ]
        # Individual findings, worst severity first, capped so the report
        # stays a reasonable size even on very large codebases (the full
        # count is still preserved in quality_findings_count above).
        _sev_rank = {"ERROR": 0, "WARNING": 1, "INFO": 2}
        sorted_findings = sorted(
            quality.findings, key=lambda f: _sev_rank.get(f.severity.upper(), 3)
        )
        report.quality_findings = [
            {
                "rule_id":        f.rule_id,
                "category":       f.category,
                "severity":       f.severity,
                "message":        f.message,
                "file_path":      f.file_path,
                "line_number":    f.line_number,
                "line_content":   f.line_content,
                "fix_suggestion": f.fix_suggestion,
                "confidence":         f.confidence,
                "confidence_reason":  f.confidence_reason,
                "confidence_source":  f.confidence_source,
            }
            for f in sorted_findings[:500]
        ]

    def _compute_risk(self, report: AnalysisReport) -> None:
        score = 0.0

        # Vulnerability contribution (max 60 pts)
        for sev, count in report.severity_counts.items():
            score += self.SEVERITY_WEIGHTS.get(sev, 0) * count
        score = min(score, 60.0)

        # Actively-exploited-in-the-wild bonus (max 15 pts) — EPSS >= 0.5 means
        # FIRST.org estimates >50% chance of real-world exploitation in 30 days,
        # so these are weighted independently of CVSS severity bucket.
        score += min(len(report.actively_exploited_vulnerabilities) * 3, 15.0)

        # Copyleft contribution (max 20 pts)
        if report.copyleft_files:
            score += min(len(report.copyleft_files) * 2, 20.0)

        # Missing license headers (max 10 pts)
        if report.files_without_license:
            score += min(len(report.files_without_license) * 0.5, 10.0)

        # Quality security issues (max 10 pts)
        score += min(report.quality_category_counts.get("security", 0) * 1, 10.0)

        score = min(round(score, 1), 100.0)
        report.risk_score = score

        if score >= 70:
            report.risk_level = "CRITICAL"
        elif score >= 40:
            report.risk_level = "HIGH"
        elif score >= 15:
            report.risk_level = "MEDIUM"
        else:
            report.risk_level = "LOW"

        # --- Compliance gate ---
        has_critical_vuln = report.severity_counts.get("CRITICAL", 0) > 0

        # Check detected licenses against license policy
        policy_fail = self._check_license_policy(report.license_distribution)

        report.compliance_status = "FAIL" if (has_critical_vuln or policy_fail) else "PASS"

        if policy_fail:
            logger.warning("Compliance FAIL: prohibited license(s) detected per license_policy.yml")

        # --- Generate vuln-driven recommendations if quality scanner found none ---
        if not report.recommendations:
            report.recommendations = self._generate_vuln_recommendations(report)

    @staticmethod
    def _generate_vuln_recommendations(report: "AnalysisReport") -> List[Dict[str, Any]]:
        """
        Generate actionable recommendations from vulnerability and license findings
        when the quality scanner produced no output.
        """
        recs: List[Dict[str, Any]] = []

        # --- EOL / severely outdated components ---
        EOL_COMPONENTS = {
            "openssl": {
                "fix": "Upgrade to OpenSSL 3.3.x (LTS). Versions 1.0.x are end-of-life since 2016.",
                "priority": "CRITICAL",
            },
            "busybox": {
                "fix": "Upgrade BusyBox to ≥1.36.1 to fix known wget/tab-completion RCE vulnerabilities.",
                "priority": "HIGH",
            },
            "linux-kernel": {
                "fix": "Review kernel version. Linux 5.4 LTS EOL is Dec 2025 — plan upgrade to 6.6 LTS.",
                "priority": "HIGH",
            },
        }

        affected_by_comp: Dict[str, List[str]] = {}
        for v in report.top_vulnerabilities:
            comp = v.get("component_name", "").lower()
            cve  = v.get("cve_id", "")
            affected_by_comp.setdefault(comp, []).append(cve)

        for comp_key, info in EOL_COMPONENTS.items():
            matched = [(c, cves) for c, cves in affected_by_comp.items() if comp_key in c]
            if matched:
                comp_name, cves = matched[0]
                recs.append({
                    "priority":       info["priority"],
                    "category":       "dependency",
                    "title":          f"Upgrade end-of-life component: {comp_name}",
                    "description":    (
                        f"{comp_name} has {len(cves)} known CVEs including "
                        f"{', '.join(cves[:3])}{'...' if len(cves) > 3 else ''}. "
                        "This component is end-of-life and no longer receives security patches."
                    ),
                    "remediation":    info["fix"],
                    "affected_files": [],
                })

        # --- Duplicate component versions ---
        from collections import defaultdict
        comp_versions: Dict[str, List[str]] = defaultdict(list)
        for c in report.sbom_components:
            name = c.get("name", "").lower()
            ver  = c.get("version", "") or ""
            if name and ver and ver != "UNKNOWN":
                comp_versions[name].append(ver)
        dupes = {n: sorted(set(vs)) for n, vs in comp_versions.items() if len(set(vs)) > 1}
        if dupes:
            dupe_list = ", ".join(f"{n} ({'/'.join(vs)})" for n, vs in list(dupes.items())[:5])
            recs.append({
                "priority":    "HIGH",
                "category":    "dependency",
                "title":       "Remove duplicate component versions",
                "description": (
                    f"Multiple versions of the same component detected: {dupe_list}. "
                    "Each version may have different CVE exposure, complicating patching."
                ),
                "remediation": "Consolidate to a single patched version per component. "
                               "Update all requirements files to pin the latest safe version.",
                "affected_files": [],
            })

        # --- Files without license headers ---
        if len(report.files_without_license) > 100:
            recs.append({
                "priority":    "MEDIUM",
                "category":    "license",
                "title":       f"Add SPDX license headers to {len(report.files_without_license):,} source files",
                "description": (
                    f"{len(report.files_without_license):,} source files have no license header. "
                    "This creates legal ambiguity for open-source compliance audits."
                ),
                "remediation": "Add 'SPDX-License-Identifier: <LICENSE>' to all proprietary source files. "
                               "Use a tool like 'reuse' (https://reuse.software) to automate this.",
                "affected_files": report.files_without_license[:10],
            })

        # --- High vuln count for non-EOL components ---
        high_vuln_comps = [
            (c, cves) for c, cves in affected_by_comp.items()
            if len(cves) >= 3 and not any(eol in c for eol in EOL_COMPONENTS)
        ]
        for comp, cves in sorted(high_vuln_comps, key=lambda x: -len(x[1]))[:3]:
            recs.append({
                "priority":    "HIGH",
                "category":    "dependency",
                "title":       f"Patch vulnerable component: {comp}",
                "description": (
                    f"{comp} has {len(cves)} vulnerabilities: {', '.join(cves[:4])}. "
                    "Check release notes for the latest patched version."
                ),
                "remediation": f"Upgrade {comp} to the latest stable release. "
                               "Run 'grype sbom:sbom.cyclonedx.json' after upgrading to verify.",
                "affected_files": [],
            })

        return sorted(recs, key=lambda r: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(r["priority"], 4))

    def _check_license_policy(self, license_distribution: Dict[str, int]) -> bool:
        """
        Returns True (= FAIL) if any detected license matches the prohibited list
        or any named rule with action=FAIL is triggered.
        Returns False if the policy is not loaded (safe default).
        """
        if not self._license_policy:
            return False

        prohibited: List[str] = self._license_policy.get("prohibited", [])
        detected_licenses = set(license_distribution.keys())

        # Direct prohibited match
        for lic in detected_licenses:
            if lic in prohibited:
                logger.warning("Prohibited license detected: %s", lic)
                return True

        # Named rules with action=FAIL
        for rule in self._license_policy.get("rules", []):
            if rule.get("action", "").upper() != "FAIL":
                continue
            for match_lic in rule.get("match", []):
                if match_lic in detected_licenses:
                    logger.warning("License policy rule '%s' triggered by: %s",
                                   rule.get("name", "?"), match_lic)
                    return True

        return False

    # ------------------------------------------------------------------
    # Writers
    # ------------------------------------------------------------------

    JSON_SCHEMA_VERSION = "2.0"

    @staticmethod
    def _executive_headline(r: AnalysisReport) -> str:
        critical = r.severity_counts.get("CRITICAL", 0)
        high = r.severity_counts.get("HIGH", 0)
        return (
            f"{r.sdk_name}: risk {r.risk_level} ({r.risk_score}/100), "
            f"compliance {r.compliance_status}. "
            f"{r.total_components} components, {r.total_vulnerabilities} vulnerabilities "
            f"({critical} critical, {high} high), {len(r.copyleft_files)} copyleft files, "
            f"{r.quality_findings_count} quality findings."
        )

    @classmethod
    def _to_nested_dict(cls, r: AnalysisReport) -> Dict[str, Any]:
        """
        Group the flat AnalysisReport into a professionally organized, nested
        JSON schema (metadata / sbom / licenses / vulnerabilities / quality /
        risk) instead of one large flat 30-key object. An `executive_summary`
        block up top gives a human-readable one-glance verdict for anyone
        consuming the JSON directly (dashboards, CI gates, other tooling).
        """
        critical = r.severity_counts.get("CRITICAL", 0)
        high = r.severity_counts.get("HIGH", 0)
        headline = cls._executive_headline(r)

        return {
            "schema_version": cls.JSON_SCHEMA_VERSION,
            "sdk_name": r.sdk_name,
            "generated_at": r.generated_at,
            "analysis_duration_seconds": r.analysis_duration_seconds,

            "executive_summary": {
                "headline": headline,
                "risk_level": r.risk_level,
                "risk_score": r.risk_score,
                "compliance_status": r.compliance_status,
                "totals": {
                    "source_files":               r.total_source_files,
                    "components":                 r.total_components,
                    "vulnerabilities":             r.total_vulnerabilities,
                    "critical_vulnerabilities":     critical,
                    "high_vulnerabilities":         high,
                    "actively_exploited_vulnerabilities": len(r.actively_exploited_vulnerabilities),
                    "copyleft_files":               len(r.copyleft_files),
                    "quality_findings":             r.quality_findings_count,
                    "recommendations":              len(r.recommendations),
                },
            },

            "metadata": {
                "source_files":    r.total_source_files,
                "size_bytes":      r.total_size_bytes,
                "size_mb":         round(r.total_size_bytes / 1024 / 1024, 2),
                "languages":       r.detected_languages,
                "build_systems":   r.detected_build_systems,
            },

            "sbom": {
                "spdx_path":                   r.sbom_spdx_path,
                "cyclonedx_path":               r.sbom_cyclonedx_path,
                "total_components":             r.total_components,
                "direct_components_count":      r.direct_components_count,
                "transitive_components_count":  r.transitive_components_count,
                "license_summary":              r.license_summary,
                "components":                   r.sbom_components,
            },

            "licenses": {
                "scanner_used":            r.license_scanner_used,
                "distribution":            r.license_distribution,
                "copyleft_files":          r.copyleft_files,
                "files_without_license":   r.files_without_license,
            },

            "vulnerabilities": {
                "scanner_used":                       r.vuln_scanner_used,
                "total":                               r.total_vulnerabilities,
                "severity_counts":                     r.severity_counts,
                "affected_components":                 r.affected_components,
                "actively_exploited":                  r.actively_exploited_vulnerabilities,
                "top_findings":                        r.top_vulnerabilities,
            },

            "quality": {
                "scanner_used":       r.quality_scanner_used,
                "total_findings":     r.quality_findings_count,
                "severity_counts":    r.quality_severity_counts,
                "category_counts":    r.quality_category_counts,
                "findings":           r.quality_findings,
                "recommendations":    sorted(
                    r.recommendations,
                    key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(
                        {"P1": "CRITICAL", "P2": "HIGH", "P3": "MEDIUM"}.get(
                            str(x.get("priority", "")).upper(), str(x.get("priority", "")).upper()
                        ), 4
                    ),
                ),
            },

            "risk": {
                "score":              r.risk_score,
                "level":              r.risk_level,
                "compliance_status":  r.compliance_status,
            },
        }

    @classmethod
    def _write_json(cls, report: AnalysisReport, path: str) -> None:
        with open(path, "w") as f:
            json.dump(cls._to_nested_dict(report), f, indent=2, default=str)

    def _write_html(
        self,
        report: AnalysisReport,
        path: str,
        diff: Optional[Dict[str, Any]] = None,
        risk_history: Optional[List[Dict[str, Any]]] = None,
    ) -> None:
        html = self._render_html(report, diff=diff, risk_history=risk_history or [])
        with open(path, "w") as f:
            f.write(html)

    # ------------------------------------------------------------------
    # HTML renderer (self-contained, no Jinja2 dependency)
    # ------------------------------------------------------------------

    def _render_html(
        self,
        r: AnalysisReport,
        diff: Optional[Dict[str, Any]] = None,
        risk_history: Optional[List[Dict[str, Any]]] = None,
    ) -> str:
        risk_history = risk_history or []
        risk_color = {"LOW": "#28a745", "MEDIUM": "#ffc107", "HIGH": "#fd7e14", "CRITICAL": "#dc3545"}.get(r.risk_level, "#6c757d")
        compliance_color = "#28a745" if r.compliance_status == "PASS" else "#dc3545"
        executive_headline = self._executive_headline(r)

        def sev_badge(sev: str) -> str:
            colors = {"CRITICAL": "#dc3545", "HIGH": "#fd7e14", "MEDIUM": "#ffc107", "LOW": "#28a745", "ERROR": "#dc3545", "WARNING": "#ffc107", "INFO": "#17a2b8"}
            c = colors.get(sev.upper(), "#6c757d")
            return f'<span style="background:{c};color:#fff;padding:2px 8px;border-radius:4px;font-size:0.8em">{sev}</span>'

        def type_badge(ptype: str) -> str:
            colors = {
                "c-embedded": "#6610f2", "pypi": "#3776ab", "autoconf": "#e67e22",
                "pkg-config": "#16a085", "npm": "#cb3837", "go": "#00add8",
            }
            c = colors.get(ptype.lower(), "#6c757d")
            return f'<span style="background:{c};color:#fff;padding:2px 7px;border-radius:4px;font-size:0.78em">{ptype}</span>'

        def epss_badge(score: float) -> str:
            if score >= 0.5:
                c, label = "#dc3545", "🔥 exploited"
            elif score >= 0.1:
                c, label = "#fd7e14", "watch"
            else:
                c, label = "#6c757d", ""
            pct = f"{score * 100:.1f}%"
            extra = f' <span style="color:{c};font-size:0.75em">{label}</span>' if label else ""
            return f"{pct}{extra}"

        def _truncate(text: str, limit: int = 120) -> str:
            text = text or ""
            return text if len(text) <= limit else text[:limit].rstrip() + "…"

        # Recommendations can carry two different priority vocabularies
        # depending on which stage generated them: quality_checker uses
        # P1/P2/P3, while the vulnerability-driven fallback in this file uses
        # CRITICAL/HIGH/MEDIUM/LOW. Normalize both to a single canonical label
        # + rank so sorting and badge coloring are consistent either way.
        _PRIORITY_NORMALIZE = {
            "P1": "CRITICAL", "P2": "HIGH", "P3": "MEDIUM",
            "CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW",
        }
        _priority_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

        def _norm_priority(raw: str) -> str:
            return _PRIORITY_NORMALIZE.get(str(raw).upper(), "MEDIUM")

        vuln_rows = "".join(
            f"<tr><td>{v['cve_id']}</td><td>{sev_badge(v['severity'])}</td>"
            f"<td>{v['cvss_score']}</td><td>{epss_badge(v.get('epss_score', 0.0))}</td><td>{v['component']}</td>"
            f"<td title=\"{(v['description'] or '').replace(chr(34), '&quot;')}\">{_truncate(v['description'])}</td>"
            f"<td>{v['fix_version'] or '—'}</td></tr>"
            for v in r.top_vulnerabilities
        ) or "<tr><td colspan='7' style='text-align:center'>No vulnerabilities found</td></tr>"

        # Recommendations sorted by (normalized) priority, most critical first.
        sorted_recommendations = sorted(
            r.recommendations,
            key=lambda rec: _priority_rank.get(_norm_priority(rec.get("priority", "")), 4),
        )
        rec_cards = "".join(
            f"""<div style="border:1px solid #dee2e6;border-radius:6px;padding:16px;margin-bottom:12px">
                <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
                  {sev_badge(_norm_priority(rec['priority']))}
                  <strong>{rec['title']}</strong>
                </div>
                <p style="margin:4px 0;color:#555">{rec['description']}</p>
                <p style="margin:4px 0"><strong>Remediation:</strong> {rec['remediation']}</p>
                {"<p style='margin:4px 0;font-size:0.85em;color:#888'>Affected files: " + ", ".join(rec['affected_files'][:5]) + ("..." if len(rec['affected_files']) > 5 else "") + "</p>" if rec['affected_files'] else ""}
              </div>"""
            for rec in sorted_recommendations
        ) or "<p>No recommendations generated.</p>"

        lic_rows = "".join(
            f"<tr><td>{lic}</td><td>{count}</td></tr>"
            for lic, count in sorted(r.license_distribution.items(), key=lambda x: -x[1])
        ) or "<tr><td colspan='2'>No license data</td></tr>"

        # ---- SBOM helpers ------------------------------------------------
        # Component type breakdown
        type_counts: Dict[str, int] = {}
        for c in r.sbom_components:
            t = c.get("type", "unknown")
            type_counts[t] = type_counts.get(t, 0) + 1

        type_breakdown_cards = "".join(
            f"""<div style="background:#f8f9fa;border:1px solid #dee2e6;border-radius:6px;
                            padding:14px 18px;display:flex;align-items:center;gap:12px">
                  {type_badge(t)}
                  <span style="font-size:1.4rem;font-weight:700">{n}</span>
                  <span style="color:#6c757d;font-size:0.85rem">components</span>
                </div>"""
            for t, n in sorted(type_counts.items(), key=lambda x: -x[1])
        )

        # Build vulnerable component set for cross-referencing
        vuln_components = {v["component_name"].lower() for v in r.top_vulnerabilities}

        # Full SBOM component table rows (all components, sorted by type then name)
        def _lic_tags(lics):
            if not lics:
                return '<span style="color:#aaa;font-size:0.8em">—</span>'
            return "".join(
                f'<span style="background:#e9f0ff;color:#2c5cbf;padding:1px 6px;border-radius:3px;'
                f'font-size:0.78em;margin:1px;display:inline-block">{l}</span>'
                for l in lics[:4]
            ) + (f'<span style="color:#aaa;font-size:0.78em"> +{len(lics)-4} more</span>' if len(lics) > 4 else "")

        def dep_badge(is_direct: bool) -> str:
            if is_direct:
                return '<span style="background:#e9ecef;color:#495057;padding:1px 6px;border-radius:3px;font-size:0.78em">direct</span>'
            return '<span style="background:#fff3cd;color:#856404;padding:1px 6px;border-radius:3px;font-size:0.78em">transitive</span>'

        sorted_components = sorted(r.sbom_components, key=lambda c: (c.get("type", ""), c.get("name", "").lower()))
        sbom_rows = "".join(
            f"""<tr class="sbom-row" data-type="{c.get('type','')}" data-name="{c.get('name','').lower()}">
                  <td>{c.get('name','—')}</td>
                  <td>{c.get('version','—') or '—'}</td>
                  <td>{type_badge(c.get('type','unknown'))}</td>
                  <td>{dep_badge(c.get('is_direct', True))}</td>
                  <td>{_lic_tags(c.get('licenses',[]))}</td>
                  <td>{"⚠" if c.get('name','').lower() in vuln_components else ""}</td>
                  <td style="font-size:0.78em;color:#888;word-break:break-all">{c.get('purl','') or '—'}</td>
                </tr>"""
            for c in sorted_components
        ) or "<tr><td colspan='7' style='text-align:center'>No components found</td></tr>"

        # License summary from SBOM components (distinct licenses used by components)
        sbom_lic_dist: Dict[str, int] = {}
        for c in r.sbom_components:
            for lic in c.get("licenses", []):
                if lic:
                    sbom_lic_dist[lic] = sbom_lic_dist.get(lic, 0) + 1

        sbom_lic_rows = "".join(
            f"<tr><td>{lic}</td><td>{cnt}</td></tr>"
            for lic, cnt in sorted(sbom_lic_dist.items(), key=lambda x: -x[1])
        ) or "<tr><td colspan='2' style='color:#aaa'>No component license data</td></tr>"

        # Bar chart data for component types (inline SVG)
        max_type_count = max(type_counts.values()) if type_counts else 1
        bar_chart_items = ""
        bar_colors = {"c-embedded": "#6610f2", "pypi": "#3776ab", "autoconf": "#e67e22",
                      "pkg-config": "#16a085", "npm": "#cb3837", "go": "#00add8"}
        for t, n in sorted(type_counts.items(), key=lambda x: -x[1]):
            pct = int(n / max_type_count * 180)
            color = bar_colors.get(t, "#6c757d")
            bar_chart_items += (
                f'<div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">'
                f'<span style="width:90px;font-size:0.82rem;text-align:right;color:#555">{t}</span>'
                f'<div style="width:{pct}px;height:20px;background:{color};border-radius:3px"></div>'
                f'<span style="font-size:0.82rem;font-weight:600">{n}</span>'
                f'</div>'
            )

        # Pre-compute expressions that would require backslashes inside f-strings
        lang_tags     = "".join(f'<span class="tag">{l}</span>' for l in r.detected_languages)
        build_tags    = "".join(f'<span class="tag">{b}</span>' for b in r.detected_build_systems) or "—"

        _sev_colors   = {"CRITICAL": "#dc3545", "HIGH": "#fd7e14", "MEDIUM": "#ffc107",
                         "LOW": "#28a745", "UNKNOWN": "#6c757d"}
        sev_pills     = "".join(
            '<div style="background:#f8f9fa;border:1px solid #dee2e6;border-radius:6px;'
            'padding:10px 18px;text-align:center">'
            f'<div style="font-size:1.4rem;font-weight:700;color:{_sev_colors.get(s, "#6c757d")}">{n}</div>'
            f'<div style="font-size:0.75rem;color:#6c757d">{s}</div></div>'
            for s, n in r.severity_counts.items()
        )

        _qsev_max = max(r.quality_severity_counts.values()) if r.quality_severity_counts else 1
        quality_sev_bars = "".join(
            f'<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">'
            f'<span style="width:70px;font-size:0.82rem">{s}</span>'
            f'<div style="height:18px;width:{int(n/_qsev_max*180)}px;background:#fd7e14;border-radius:3px"></div>'
            f'<span style="font-size:0.82rem;font-weight:600;margin-left:4px">{n}</span></div>'
            for s, n in sorted(r.quality_severity_counts.items(), key=lambda x: -x[1])
        )
        _qcat_max = max(r.quality_category_counts.values()) if r.quality_category_counts else 1
        quality_cat_bars = "".join(
            f'<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">'
            f'<span style="width:70px;font-size:0.82rem">{c}</span>'
            f'<div style="height:18px;width:{int(n/_qcat_max*180)}px;background:#6610f2;border-radius:3px"></div>'
            f'<span style="font-size:0.82rem;font-weight:600;margin-left:4px">{n}</span></div>'
            for c, n in sorted(r.quality_category_counts.items(), key=lambda x: -x[1])
        )

        # Quality findings table (individual issues, worst severity first) —
        # previously only aggregate counts were shown; the actual findings
        # (file, line, message, fix suggestion) are now browsable/searchable.
        def _quality_sev_badge(sev: str) -> str:
            colors = {"ERROR": "#dc3545", "WARNING": "#fd7e14", "INFO": "#17a2b8"}
            c = colors.get(sev.upper(), "#6c757d")
            return f'<span style="background:{c};color:#fff;padding:2px 8px;border-radius:4px;font-size:0.8em">{sev}</span>'

        def _confidence_badge(f: dict) -> str:
            conf = f.get("confidence", "UNCONFIRMED")
            if not conf or conf == "UNCONFIRMED":
                return '<span style="color:#adb5bd;font-size:0.78em">—</span>'
            colors = {"HIGH": "#dc3545", "LOW": "#6c757d"}
            labels = {"HIGH": "Likely real", "LOW": "Likely test fixture"}
            c = colors.get(conf, "#6c757d")
            label = labels.get(conf, conf)
            source = f.get("confidence_source", "")
            source_label = "AI (local)" if source == "ai-local" else "heuristic" if source else ""
            reason = (f.get("confidence_reason") or "").replace('"', "&quot;")
            title = f"{reason} [{source_label}]" if source_label else reason
            return (f'<span title="{title}" style="background:{c};color:#fff;padding:2px 8px;'
                    f'border-radius:4px;font-size:0.78em;cursor:help">{label}</span>')

        quality_finding_rows = "".join(
            f"""<tr class="quality-row" data-severity="{f.get('severity','')}" data-category="{f.get('category','')}">
                  <td>{_quality_sev_badge(f.get('severity','INFO'))}</td>
                  <td>{f.get('category','—')}</td>
                  <td style="font-size:0.82em">{f.get('rule_id','—')}</td>
                  <td>{f.get('message','—')}</td>
                  <td style="font-size:0.8em;word-break:break-all">{f.get('file_path','—')}:{f.get('line_number','') or ''}</td>
                  <td>{_confidence_badge(f)}</td>
                </tr>"""
            for f in r.quality_findings
        ) or "<tr><td colspan='6' style='text-align:center;color:#aaa'>No individual findings recorded</td></tr>"

        quality_shown_note = (
            f"Showing {len(r.quality_findings):,} of {r.quality_findings_count:,} total findings "
            "(capped for report size — full counts above reflect the entire scan)."
            if r.quality_findings_count > len(r.quality_findings)
            else f"Showing all {len(r.quality_findings):,} findings."
        )

        copyleft_list = (
            "<ul style='font-size:0.85em;padding-left:18px'>"
            + "".join(f"<li>{f}</li>" for f in r.copyleft_files[:20])
            + ("..." if len(r.copyleft_files) > 20 else "")
            + "</ul>"
        ) if r.copyleft_files else "<p style='color:#28a745'>No copyleft files detected.</p>"

        vuln_color = "#dc3545" if r.severity_counts.get("CRITICAL", 0) > 0 else "#212529"
        copyleft_color = "#fd7e14" if r.copyleft_files else "#28a745"
        quality_scanner = getattr(r, "quality_scanner_used", "built-in")

        # Filter buttons JS list
        type_filter_btns = (
            '<button onclick="filterSBOM(\'all\')" class="sbom-filter-btn active" data-filter="all"'
            ' style="margin:2px;padding:4px 10px;border:1px solid #dee2e6;border-radius:4px;'
            'background:#1a1a2e;color:#fff;cursor:pointer;font-size:0.82rem">All</button>'
        ) + "".join(
            f'<button onclick="filterSBOM(\'{t}\')" class="sbom-filter-btn" data-filter="{t}"'
            f' style="margin:2px;padding:4px 10px;border:1px solid #dee2e6;border-radius:4px;'
            f'background:#fff;color:#333;cursor:pointer;font-size:0.82rem">{t} ({n})</button>'
            for t, n in sorted(type_counts.items(), key=lambda x: -x[1])
        )

        # ------------------------------------------------------------------
        # Chart data blob (consumed by vanilla-JS canvas charts below — no
        # external charting library / CDN, so the report stays fully
        # self-contained and viewable offline / air-gapped).
        # ------------------------------------------------------------------
        chart_data = {
            "riskScore": r.risk_score,
            "riskLevel": r.risk_level,
            "severityCounts": r.severity_counts,
            "typeCounts": type_counts,
            "licenseDistribution": dict(sorted(r.license_distribution.items(), key=lambda x: -x[1])[:10]),
            "qualitySeverityCounts": r.quality_severity_counts,
            "qualityCategoryCounts": r.quality_category_counts,
            "epssPoints": [
                {
                    "id": v["cve_id"],
                    "cvss": v["cvss_score"],
                    "epss": round(v.get("epss_score", 0.0) * 100, 2),
                    "severity": v["severity"],
                    "component": v["component"],
                }
                for v in r.top_vulnerabilities
            ],
            "riskHistory": [
                {
                    "generatedAt": h.get("generated_at", ""),
                    "riskScore": h.get("risk_score", 0),
                    "riskLevel": h.get("risk_level", ""),
                }
                for h in risk_history
            ],
            "diff": diff,
        }
        chart_data_json = json.dumps(chart_data, default=str).replace("</", "<\\/")

        # ------------------------------------------------------------------
        # Trend / Diff section — only rendered when a --baseline was supplied
        # ------------------------------------------------------------------
        diff_nav_link = ""
        diff_section = ""
        if diff:
            diff_nav_link = '<a href="#trend" data-tab="trend">Trend</a>'
            verdict = diff.get("verdict", "")
            verdict_color = "#dc3545" if verdict.startswith("REGRESSION") or verdict.startswith("WORSE") else (
                "#28a745" if verdict.startswith("IMPROVED") else "#6c757d"
            )

            def _diff_comp_rows(comps):
                return "".join(
                    f"<tr><td>{c.get('name','—')}</td><td>{c.get('version','—') or '—'}</td>"
                    f"<td>{type_badge(c.get('type','unknown'))}</td></tr>"
                    for c in comps
                ) or "<tr><td colspan='3' style='text-align:center;color:#aaa'>None</td></tr>"

            def _diff_vuln_rows(vulns):
                return "".join(
                    f"<tr><td>{v.get('cve_id','—')}</td><td>{sev_badge(v.get('severity','UNKNOWN'))}</td>"
                    f"<td>{v.get('component','—')}</td></tr>"
                    for v in vulns
                ) or "<tr><td colspan='3' style='text-align:center;color:#aaa'>None</td></tr>"

            diff_section = f"""
  <div id="trend" class="section tabpage">
    <h2>Scan Trend &amp; Baseline Diff</h2>
    <div style="background:#f8f9fa;border-left:4px solid {verdict_color};border-radius:4px;
                padding:12px 16px;margin-bottom:20px;font-weight:600;color:{verdict_color}">
      {verdict}
    </div>
    <p style="font-size:0.85rem;color:#6c757d;margin-bottom:16px">
      Baseline: <strong>{diff.get('baseline_sdk_name','—')}</strong> ({diff.get('baseline_generated_at','—')})
      &nbsp;→&nbsp; Current: <strong>{diff.get('current_sdk_name','—')}</strong> ({diff.get('current_generated_at','—')})
    </p>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:24px">
      <div>
        <h3 style="font-size:0.95rem;margin-bottom:12px;color:#555">Risk Score: Before vs After</h3>
        <canvas id="chartDiffRisk" height="140"></canvas>
      </div>
      <div class="grid" style="grid-template-columns:repeat(2,1fr);margin-bottom:0">
        <div class="card"><h3>New Vulns</h3><div class="value" style="color:#dc3545">{diff.get('new_vulnerabilities_count',0)}</div></div>
        <div class="card"><h3>Resolved Vulns</h3><div class="value" style="color:#28a745">{diff.get('resolved_vulnerabilities_count',0)}</div></div>
        <div class="card"><h3>New Components</h3><div class="value">{diff.get('new_components_count',0)}</div></div>
        <div class="card"><h3>Removed Components</h3><div class="value">{diff.get('removed_components_count',0)}</div></div>
      </div>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px">
      <div>
        <h3 style="font-size:0.95rem;margin-bottom:8px">New Vulnerabilities ({diff.get('new_vulnerabilities_count',0)})</h3>
        <table><tr><th>CVE</th><th>Severity</th><th>Component</th></tr>
          {_diff_vuln_rows(diff.get('new_vulnerabilities', []))}
        </table>
      </div>
      <div>
        <h3 style="font-size:0.95rem;margin-bottom:8px">Resolved Vulnerabilities ({diff.get('resolved_vulnerabilities_count',0)})</h3>
        <table><tr><th>CVE</th><th>Severity</th><th>Component</th></tr>
          {_diff_vuln_rows(diff.get('resolved_vulnerabilities', []))}
        </table>
      </div>
      <div>
        <h3 style="font-size:0.95rem;margin-bottom:8px">New Components ({diff.get('new_components_count',0)})</h3>
        <table><tr><th>Name</th><th>Version</th><th>Type</th></tr>
          {_diff_comp_rows(diff.get('new_components', []))}
        </table>
      </div>
      <div>
        <h3 style="font-size:0.95rem;margin-bottom:8px">Removed Components ({diff.get('removed_components_count',0)})</h3>
        <table><tr><th>Name</th><th>Version</th><th>Type</th></tr>
          {_diff_comp_rows(diff.get('removed_components', []))}
        </table>
      </div>
    </div>
  </div>"""

        risk_trend_card = ""
        if len(risk_history) > 1:
            risk_trend_card = """
    <div class="section" style="margin-top:0">
      <h3 style="font-size:0.95rem;margin-bottom:12px;color:#555">Risk Score Trend (this SDK, across runs)</h3>
      <canvas id="chartRiskTrend" height="90"></canvas>
    </div>"""

        # ------------------------------------------------------------------
        # Chart-rendering JS engine (plain string, not an f-string, so none of
        # its braces need doubling — it's spliced verbatim into the template).
        # ------------------------------------------------------------------
        chart_js = r"""
// ==================== Lightweight canvas chart engine ====================
// No external library / CDN — keeps the report fully self-contained and
// viewable offline on air-gapped machines.
const CHART_DATA = JSON.parse(document.getElementById('reportChartData').textContent);

const PALETTE = ['#4a9eff','#6610f2','#e67e22','#16a085','#cb3837','#00add8',
                  '#fd7e14','#28a745','#dc3545','#ffc107','#6c757d','#20c997'];
const SEV_COLORS = {CRITICAL:'#dc3545', HIGH:'#fd7e14', MEDIUM:'#ffc107', LOW:'#28a745', UNKNOWN:'#6c757d'};

function isDark() { return document.documentElement.getAttribute('data-theme') === 'dark'; }
function fg() { return isDark() ? '#e6e6e6' : '#212529'; }
function gridColor() { return isDark() ? '#333a4d' : '#eee'; }

function hiDPICanvas(canvas) {
  const ctx = canvas.getContext('2d');
  const rect = canvas.getBoundingClientRect();
  const cssW = rect.width || canvas.clientWidth || 400;
  const cssH = canvas.height || 150;
  const dpr = window.devicePixelRatio || 1;
  canvas.width = cssW * dpr;
  canvas.height = cssH * dpr;
  canvas.style.width = cssW + 'px';
  canvas.style.height = cssH + 'px';
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  return { ctx, w: cssW, h: cssH };
}

function drawDonut(canvasId, dataObj, legendId) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) return;
  const entries = Object.entries(dataObj || {}).filter(([,v]) => v > 0);
  const { ctx, w, h } = hiDPICanvas(canvas);
  ctx.clearRect(0, 0, w, h);
  if (!entries.length) {
    ctx.fillStyle = '#aaa'; ctx.font = '13px sans-serif'; ctx.textAlign = 'center';
    ctx.fillText('No data', w / 2, h / 2);
    return;
  }
  const total = entries.reduce((s, [, v]) => s + v, 0);
  const cx = w / 2, cy = h / 2, rOuter = Math.min(w, h) / 2 - 6, rInner = rOuter * 0.55;
  let start = -Math.PI / 2;
  entries.forEach(([key, val], i) => {
    const angle = (val / total) * Math.PI * 2;
    const color = SEV_COLORS[key] || PALETTE[i % PALETTE.length];
    ctx.beginPath();
    ctx.moveTo(cx, cy);
    ctx.arc(cx, cy, rOuter, start, start + angle);
    ctx.closePath();
    ctx.fillStyle = color;
    ctx.fill();
    start += angle;
  });
  ctx.globalCompositeOperation = 'destination-out';
  ctx.beginPath(); ctx.arc(cx, cy, rInner, 0, Math.PI * 2); ctx.fill();
  ctx.globalCompositeOperation = 'source-over';
  ctx.fillStyle = fg(); ctx.font = 'bold 16px sans-serif'; ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
  ctx.fillText(String(total), cx, cy);
  if (legendId) {
    const legend = document.getElementById(legendId);
    if (legend) {
      legend.innerHTML = entries.map(([key, val], i) => {
        const color = SEV_COLORS[key] || PALETTE[i % PALETTE.length];
        return '<span><span class="dot" style="background:' + color + '"></span>' + key + ': ' + val + '</span>';
      }).join('');
    }
  }
}

function drawBar(canvasId, dataObj, color) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) return;
  const entries = Object.entries(dataObj || {});
  const { ctx, w, h } = hiDPICanvas(canvas);
  ctx.clearRect(0, 0, w, h);
  if (!entries.length) {
    ctx.fillStyle = '#aaa'; ctx.font = '13px sans-serif'; ctx.textAlign = 'center';
    ctx.fillText('No data', w / 2, h / 2);
    return;
  }
  const max = Math.max(...entries.map(([, v]) => v), 1);
  const labelW = 110, padRight = 40, rowH = Math.min(26, (h - 10) / entries.length);
  ctx.font = '11px sans-serif'; ctx.textBaseline = 'middle';
  entries.forEach(([label, val], i) => {
    const y = 6 + i * rowH + rowH / 2;
    ctx.fillStyle = fg(); ctx.textAlign = 'right';
    const shortLabel = label.length > 16 ? label.slice(0, 15) + '…' : label;
    ctx.fillText(shortLabel, labelW - 8, y);
    const barMaxW = w - labelW - padRight;
    const barW = (val / max) * barMaxW;
    ctx.fillStyle = color || '#4a9eff';
    ctx.fillRect(labelW, y - rowH * 0.32, Math.max(barW, 2), rowH * 0.64);
    ctx.fillStyle = fg(); ctx.textAlign = 'left';
    ctx.fillText(String(val), labelW + barW + 6, y);
  });
}

function drawGauge(canvasId, value, max, label) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) return;
  const { ctx, w, h } = hiDPICanvas(canvas);
  ctx.clearRect(0, 0, w, h);
  const cx = w / 2, cy = h - 10, r = Math.min(w / 2 - 10, h - 20);
  const pct = Math.max(0, Math.min(1, value / max));
  const startAngle = Math.PI, endAngle = 0;
  ctx.lineWidth = 16; ctx.lineCap = 'round';
  ctx.beginPath(); ctx.arc(cx, cy, r, startAngle, endAngle, false);
  ctx.strokeStyle = gridColor(); ctx.stroke();
  const color = value >= 70 ? '#dc3545' : value >= 40 ? '#fd7e14' : value >= 15 ? '#ffc107' : '#28a745';
  ctx.beginPath(); ctx.arc(cx, cy, r, startAngle, startAngle - pct * Math.PI, true);
  ctx.strokeStyle = color; ctx.stroke();
  ctx.fillStyle = fg(); ctx.textAlign = 'center';
  ctx.font = 'bold 24px sans-serif';
  ctx.fillText(String(value), cx, cy - r * 0.35);
  ctx.font = '11px sans-serif'; ctx.fillStyle = '#888';
  ctx.fillText(label || ('/ ' + max), cx, cy - r * 0.35 + 18);
}

function drawScatter(canvasId, points) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) return;
  const { ctx, w, h } = hiDPICanvas(canvas);
  ctx.clearRect(0, 0, w, h);
  const padL = 40, padB = 26, padT = 10, padR = 10;
  const plotW = w - padL - padR, plotH = h - padT - padB;
  ctx.strokeStyle = gridColor(); ctx.fillStyle = fg(); ctx.font = '10px sans-serif';
  ctx.beginPath(); ctx.moveTo(padL, padT); ctx.lineTo(padL, padT + plotH); ctx.lineTo(padL + plotW, padT + plotH); ctx.stroke();
  ctx.textAlign = 'center';
  ctx.fillText('CVSS →', padL + plotW / 2, h - 4);
  ctx.save(); ctx.translate(10, padT + plotH / 2); ctx.rotate(-Math.PI / 2);
  ctx.fillText('EPSS % ↑', 0, 0); ctx.restore();
  if (!points || !points.length) {
    ctx.textAlign = 'center'; ctx.fillStyle = '#aaa';
    ctx.fillText('No vulnerability data', padL + plotW / 2, padT + plotH / 2);
    return;
  }
  points.forEach(p => {
    const x = padL + (Math.min(p.cvss, 10) / 10) * plotW;
    const y = padT + plotH - (Math.min(p.epss, 100) / 100) * plotH;
    ctx.beginPath();
    ctx.arc(x, y, 5, 0, Math.PI * 2);
    ctx.fillStyle = SEV_COLORS[p.severity] || '#6c757d';
    ctx.globalAlpha = 0.75;
    ctx.fill();
    ctx.globalAlpha = 1;
  });
}

function drawLine(canvasId, points, valueKey, labelKey) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) return;
  const { ctx, w, h } = hiDPICanvas(canvas);
  ctx.clearRect(0, 0, w, h);
  if (!points || points.length < 2) return;
  const padL = 30, padB = 20, padT = 10, padR = 10;
  const plotW = w - padL - padR, plotH = h - padT - padB;
  const values = points.map(p => p[valueKey]);
  const max = Math.max(...values, 10), min = 0;
  ctx.strokeStyle = gridColor();
  ctx.beginPath(); ctx.moveTo(padL, padT); ctx.lineTo(padL, padT + plotH); ctx.lineTo(padL + plotW, padT + plotH); ctx.stroke();
  ctx.beginPath();
  points.forEach((p, i) => {
    const x = padL + (i / (points.length - 1)) * plotW;
    const y = padT + plotH - ((p[valueKey] - min) / (max - min || 1)) * plotH;
    if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
  });
  ctx.strokeStyle = '#4a9eff'; ctx.lineWidth = 2; ctx.stroke();
  points.forEach((p, i) => {
    const x = padL + (i / (points.length - 1)) * plotW;
    const y = padT + plotH - ((p[valueKey] - min) / (max - min || 1)) * plotH;
    ctx.beginPath(); ctx.arc(x, y, 3.5, 0, Math.PI * 2);
    ctx.fillStyle = SEV_COLORS[p.riskLevel] || '#4a9eff'; ctx.fill();
  });
  ctx.fillStyle = fg(); ctx.font = '10px sans-serif'; ctx.textAlign = 'center';
  ctx.fillText(String(points[0][valueKey]), padL, padT + plotH + 12);
  ctx.fillText(String(points[points.length - 1][valueKey]), padL + plotW, padT + plotH + 12);
}

function renderAllCharts() {
  drawGauge('chartRiskGauge', CHART_DATA.riskScore, 100, CHART_DATA.riskLevel);
  drawDonut('chartSeverityDonut', CHART_DATA.severityCounts, 'legendSeverityDonut');
  drawDonut('chartTypeDonut', CHART_DATA.typeCounts, 'legendTypeDonut');
  drawDonut('chartQualityDonut', CHART_DATA.qualityCategoryCounts, 'legendQualityDonut');
  drawBar('chartLicenseBar', CHART_DATA.licenseDistribution, '#4a9eff');
  drawBar('chartVulnSeverityBar', CHART_DATA.severityCounts, '#dc3545');
  drawScatter('chartEpssCvss', CHART_DATA.epssPoints);
  if (CHART_DATA.riskHistory && CHART_DATA.riskHistory.length > 1) {
    drawLine('chartRiskTrend', CHART_DATA.riskHistory, 'riskScore', 'generatedAt');
  }
  if (CHART_DATA.diff) {
    drawBar('chartDiffRisk', {
      Before: CHART_DATA.diff.risk_score_before,
      After: CHART_DATA.diff.risk_score_after,
    }, '#fd7e14');
  }
}
window.addEventListener('load', renderAllCharts);
window.addEventListener('resize', () => { clearTimeout(window._chartResizeT); window._chartResizeT = setTimeout(renderAllCharts, 200); });

// ==================== Theme toggle ====================
function toggleTheme() {
  const dark = document.documentElement.getAttribute('data-theme') === 'dark';
  document.documentElement.setAttribute('data-theme', dark ? 'light' : 'dark');
  document.getElementById('themeToggleBtn').textContent = dark ? '🌙 Dark mode' : '☀️ Light mode';
  localStorage.setItem('sdkAnalyzerTheme', dark ? 'light' : 'dark');
  renderAllCharts();
}
(function initTheme() {
  const saved = localStorage.getItem('sdkAnalyzerTheme');
  if (saved === 'dark') {
    document.documentElement.setAttribute('data-theme', 'dark');
    window.addEventListener('DOMContentLoaded', () => {
      const btn = document.getElementById('themeToggleBtn');
      if (btn) btn.textContent = '☀️ Light mode';
    });
  }
})();

// ==================== Sortable tables ====================
function sortTable(tableId, colIndex, th) {
  const table = document.getElementById(tableId);
  if (!table) return;
  const tbody = table.tBodies[0];
  const rows = Array.from(tbody.rows);
  const asc = th.dataset.sortDir !== 'asc';
  Array.from(th.parentNode.children).forEach(h => delete h.dataset.sortDir);
  th.dataset.sortDir = asc ? 'asc' : 'desc';
  rows.sort((a, b) => {
    const av = a.cells[colIndex].innerText.trim();
    const bv = b.cells[colIndex].innerText.trim();
    const an = parseFloat(av), bn = parseFloat(bv);
    let cmp;
    if (!isNaN(an) && !isNaN(bn) && /^[\d.\s%-]+$/.test(av) && /^[\d.\s%-]+$/.test(bv)) {
      cmp = an - bn;
    } else {
      cmp = av.localeCompare(bv);
    }
    return asc ? cmp : -cmp;
  });
  rows.forEach(row => tbody.appendChild(row));
}
"""

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>SDK Analysis Report — {r.sdk_name}</title>
  <style>
    *{{box-sizing:border-box;margin:0;padding:0}}
    :root{{--bg:#f8f9fa;--fg:#212529;--card-bg:#fff;--border:#dee2e6;--muted:#6c757d;--header-bg:#1a1a2e;--nav-bg:#16213e}}
    [data-theme="dark"]{{--bg:#12141c;--fg:#e6e6e6;--card-bg:#1c1f2b;--border:#333a4d;--muted:#9aa3b2;--header-bg:#0c0e14;--nav-bg:#0c0e14}}
    body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:var(--bg);color:var(--fg);line-height:1.5}}
    .header{{background:var(--header-bg);color:#fff;padding:24px 32px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px}}
    .header h1{{font-size:1.8rem}}
    .header p{{color:#aaa;font-size:0.9rem}}
    .header-actions button{{background:#2a2f45;color:#fff;border:1px solid #3d4460;border-radius:6px;
                             padding:6px 14px;font-size:0.82rem;cursor:pointer;margin-left:8px}}
    .header-actions button:hover{{background:#3d4460}}
    .nav{{background:var(--nav-bg);padding:0 32px;display:flex;gap:4px;flex-wrap:wrap}}
    .nav a{{color:#ccc;text-decoration:none;padding:10px 14px;font-size:0.88rem;display:inline-block}}
    .nav a:hover,.nav a.active{{color:#fff;border-bottom:3px solid #4a9eff}}
    .container{{max-width:1200px;margin:0 auto;padding:24px 32px}}
    .grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:16px;margin-bottom:24px}}
    .card{{background:var(--card-bg);border:1px solid var(--border);border-radius:8px;padding:20px}}
    .card h3{{font-size:0.85rem;color:var(--muted);text-transform:uppercase;letter-spacing:.05em;margin-bottom:6px}}
    .card .value{{font-size:2rem;font-weight:700}}
    .section{{background:var(--card-bg);border:1px solid var(--border);border-radius:8px;padding:20px;margin-bottom:24px}}
    .section h2{{font-size:1.15rem;margin-bottom:16px;padding-bottom:8px;border-bottom:2px solid var(--border)}}
    .tabpage{{display:none}}
    .tabpage.active{{display:block}}
    .pagination{{display:flex;align-items:center;gap:10px;margin-top:12px;font-size:0.85rem;flex-wrap:wrap}}
    .pagination button{{background:var(--card-bg);border:1px solid var(--border);color:var(--fg);padding:5px 12px;border-radius:5px;cursor:pointer}}
    .pagination button:disabled{{opacity:0.4;cursor:default}}
    .pagination button:not(:disabled):hover{{background:#4a9eff;color:#fff;border-color:#4a9eff}}
    .pagination select{{padding:4px 8px;border-radius:5px;border:1px solid var(--border);background:var(--card-bg);color:var(--fg)}}
    table{{width:100%;border-collapse:collapse;font-size:0.9rem}}
    th{{background:var(--bg);text-align:left;padding:8px 12px;border-bottom:2px solid var(--border);font-weight:600}}
    th.sortable{{cursor:pointer;user-select:none}}
    th.sortable:hover{{color:#4a9eff}}
    th.sortable::after{{content:' ⇅';color:var(--muted);font-size:0.8em}}
    td{{padding:8px 12px;border-bottom:1px solid var(--border);vertical-align:middle}}
    tr:hover td{{background:var(--bg)}}
    .tag{{display:inline-block;background:#e9ecef;color:#495057;padding:2px 8px;border-radius:4px;font-size:0.8em;margin:2px}}
    .footer{{text-align:center;color:#aaa;font-size:0.8rem;padding:16px}}
    .sbom-search{{width:100%;padding:8px 12px;border:1px solid var(--border);border-radius:6px;font-size:0.9rem;margin-bottom:10px;background:var(--card-bg);color:var(--fg)}}
    .vuln-flag{{color:#dc3545;font-size:1.1rem;font-weight:700;cursor:help}}
    .type-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:10px;margin-bottom:20px}}
    .chart-row{{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:20px}}
    .chart-legend{{font-size:0.78rem;color:var(--muted);margin-top:8px;display:flex;flex-wrap:wrap;gap:10px}}
    .chart-legend span.dot{{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:4px}}
    @media print {{ .nav, .header-actions, .sbom-search, .sbom-filter-btn, .pagination {{ display:none !important; }} .tabpage {{ display:block !important; }} }}
    @media (max-width: 700px) {{ .chart-row {{ grid-template-columns:1fr; }} }}
  </style>
</head>
<body>
<script type="application/json" id="reportChartData">{chart_data_json}</script>
<div class="header">
  <div>
    <h1>SDK Analysis Report</h1>
    <p>{r.sdk_name} &nbsp;|&nbsp; Generated: {r.generated_at} &nbsp;|&nbsp; Duration: {r.analysis_duration_seconds}s</p>
  </div>
  <div class="header-actions">
    <button onclick="toggleTheme()" id="themeToggleBtn">🌙 Dark mode</button>
    <button onclick="window.print()">🖨 Export / Print</button>
  </div>
</div>

<div class="nav" id="mainNav">
  <a href="#overview" data-tab="overview" class="active">Overview</a>
  <a href="#sbom" data-tab="sbom">SBOM</a>
  <a href="#vulnerabilities" data-tab="vulnerabilities">Vulnerabilities</a>
  <a href="#licenses" data-tab="licenses">Licenses</a>
  <a href="#quality" data-tab="quality">Quality</a>
  <a href="#recommendations" data-tab="recommendations">Recommendations</a>
  {diff_nav_link}
</div>

<div class="container">

  <div id="overview" class="tabpage active">

  <!-- Executive Summary -->
  <div class="section" style="margin-top:24px;border-left:4px solid {risk_color};background:var(--card-bg)">
    <h2 style="border:none;margin-bottom:8px;padding-bottom:0">Executive Summary</h2>
    <p style="font-size:0.95rem;color:var(--fg);line-height:1.6">{executive_headline}</p>
  </div>

  <!-- Summary Cards -->
  <div id="summary" class="grid" style="margin-top:0">
    <div class="card">
      <h3>Overall Risk</h3>
      <div class="value" style="color:{risk_color}">{r.risk_level}</div>
      <small style="color:var(--muted)">Score: {r.risk_score}/100</small>
    </div>
    <div class="card">
      <h3>Compliance</h3>
      <div class="value" style="color:{compliance_color}">{r.compliance_status}</div>
    </div>
    <div class="card">
      <h3>SBOM Components</h3>
      <div class="value">{r.total_components}</div>
      <small style="color:var(--muted)">{r.total_source_files:,} source files</small>
    </div>
    <div class="card">
      <h3>Vulnerabilities</h3>
      <div class="value" style="color:{vuln_color}">{r.total_vulnerabilities}</div>
      <small style="color:#dc3545">{r.severity_counts.get('CRITICAL',0)} Critical</small>
      &nbsp;<small style="color:#fd7e14">{r.severity_counts.get('HIGH',0)} High</small>
    </div>
    <div class="card">
      <h3>Copyleft Files</h3>
      <div class="value" style="color:{copyleft_color}">{len(r.copyleft_files):,}</div>
    </div>
    <div class="card">
      <h3>Quality Findings</h3>
      <div class="value">{r.quality_findings_count:,}</div>
      <small style="color:var(--muted)">{len(r.recommendations)} recommendations</small>
    </div>
  </div>

  <!-- Risk gauge + severity/type donuts -->
  <div class="section" style="margin-top:0">
    <div class="chart-row" style="margin-bottom:0">
      <div>
        <h3 style="font-size:0.95rem;margin-bottom:12px;color:#555">Risk Score Gauge</h3>
        <canvas id="chartRiskGauge" height="150"></canvas>
      </div>
      <div>
        <h3 style="font-size:0.95rem;margin-bottom:12px;color:#555">Vulnerability Severity</h3>
        <canvas id="chartSeverityDonut" height="150"></canvas>
        <div class="chart-legend" id="legendSeverityDonut"></div>
      </div>
    </div>
  </div>
  {risk_trend_card}

  <!-- SDK Metadata -->
  <div id="metadata" class="section">
    <h2>SDK Metadata</h2>
    <table>
      <tr><th>Property</th><th>Value</th></tr>
      <tr><td>SDK Name</td><td>{r.sdk_name}</td></tr>
      <tr><td>Source Files</td><td>{r.total_source_files:,}</td></tr>
      <tr><td>Total Size</td><td>{round(r.total_size_bytes/1024/1024, 2):,} MB</td></tr>
      <tr><td>Languages</td><td>{lang_tags}</td></tr>
      <tr><td>Build Systems</td><td>{build_tags}</td></tr>
      <tr><td>SBOM (SPDX)</td><td><code>{r.sbom_spdx_path}</code></td></tr>
      <tr><td>SBOM (CycloneDX)</td><td><code>{r.sbom_cyclonedx_path}</code></td></tr>
    </table>
  </div>

  </div><!-- /#overview -->

  <!-- ================================================================ -->
  <!-- SBOM Section                                                      -->
  <!-- ================================================================ -->
  <div id="sbom" class="section tabpage">
    <h2>Software Bill of Materials (SBOM)</h2>

    <!-- Type breakdown bar chart + count cards -->
    <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:20px;margin-bottom:20px">
      <div>
        <h3 style="font-size:0.95rem;margin-bottom:12px;color:#555">Component Breakdown by Type</h3>
        {bar_chart_items}
      </div>
      <div>
        <h3 style="font-size:0.95rem;margin-bottom:12px;color:#555">Type Distribution</h3>
        <canvas id="chartTypeDonut" height="150"></canvas>
        <div class="chart-legend" id="legendTypeDonut"></div>
      </div>
      <div>
        <h3 style="font-size:0.95rem;margin-bottom:12px;color:#555">Component License Summary</h3>
        <table>
          <tr><th>License</th><th>Components</th></tr>
          {sbom_lic_rows}
        </table>
      </div>
    </div>

    <!-- Stats row -->
    <div style="background:#f0f4ff;border:1px solid #d0deff;border-radius:6px;padding:12px 16px;
                margin-bottom:16px;font-size:0.88rem;color:#334">
      <strong>{r.total_components}</strong> total components detected across
      <strong>{len(type_counts)}</strong> package types &nbsp;|&nbsp;
      SPDX path: <code style="font-size:0.82rem">{r.sbom_spdx_path}</code> &nbsp;|&nbsp;
      CycloneDX path: <code style="font-size:0.82rem">{r.sbom_cyclonedx_path}</code>
    </div>

    <!-- Filter + search controls -->
    <div style="margin-bottom:10px;display:flex;flex-wrap:wrap;align-items:center;gap:8px">
      <span style="font-size:0.85rem;color:#555;font-weight:600">Filter:</span>
      {type_filter_btns}
    </div>
    <input class="sbom-search" id="sbomSearch" type="text"
           placeholder="Search by name, version, or license..." oninput="searchSBOM(this.value)">

    <!-- Full component table -->
    <div style="overflow-x:auto">
      <table id="sbomTable">
        <thead>
          <tr>
            <th class="sortable" onclick="sortTable('sbomTable',0,this)">Name</th>
            <th class="sortable" onclick="sortTable('sbomTable',1,this)">Version</th>
            <th class="sortable" onclick="sortTable('sbomTable',2,this)">Type</th>
            <th class="sortable" onclick="sortTable('sbomTable',3,this)" title="Direct = declared by project manifest, Transitive = pulled in by another dependency">Dependency</th>
            <th>Licenses</th>
            <th title="Has known CVE">CVE</th>
            <th>PURL</th>
          </tr>
        </thead>
        <tbody id="sbomBody">
          {sbom_rows}
        </tbody>
      </table>
    </div>
    <p style="font-size:0.82rem;color:#888;margin-top:8px" id="sbomCount">
      Showing {r.total_components} of {r.total_components} components
      ({r.direct_components_count} direct, {r.transitive_components_count} transitive)
    </p>
    <div class="pagination">
      <button id="sbomPrevBtn" onclick="sbomPage(-1)">← Prev</button>
      <span id="sbomPageLabel">Page 1</span>
      <button id="sbomNextBtn" onclick="sbomPage(1)">Next →</button>
      <label style="margin-left:12px">Rows per page:
        <select id="sbomPageSize" onchange="window._sbomPage=0; window._sbomPageSize=parseInt(this.value); applySBOMFilters();">
          <option value="25">25</option>
          <option value="50" selected>50</option>
          <option value="100">100</option>
          <option value="99999">All</option>
        </select>
      </label>
    </div>
  </div>

  <!-- Vulnerabilities -->
  <div id="vulnerabilities" class="section tabpage">
    <h2>Vulnerability Findings (Top 20 by CVSS + EPSS priority)</h2>
    <p style="font-size:0.85rem;color:#6c757d;margin-bottom:12px">Scanner: {r.vuln_scanner_used} | EPSS: FIRST.org exploit prediction ({len(r.actively_exploited_vulnerabilities)} actively exploited, EPSS ≥ 50%)</p>

    <!-- Severity summary pills -->
    <div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:16px">
      {sev_pills}
    </div>

    <div class="chart-row">
      <div>
        <h3 style="font-size:0.95rem;margin-bottom:8px;color:#555">EPSS (exploit probability) vs CVSS Severity</h3>
        <canvas id="chartEpssCvss" height="220"></canvas>
        <p style="font-size:0.75rem;color:var(--muted);margin-top:4px">
          Top-right quadrant = high severity + likely to be exploited in the wild — triage these first.
        </p>
      </div>
      <div>
        <h3 style="font-size:0.95rem;margin-bottom:8px;color:#555">Findings by Severity</h3>
        <canvas id="chartVulnSeverityBar" height="220"></canvas>
      </div>
    </div>

    <table id="vulnTable">
      <tr>
        <th class="sortable" onclick="sortTable('vulnTable',0,this)">CVE / ID</th>
        <th class="sortable" onclick="sortTable('vulnTable',1,this)">Severity</th>
        <th class="sortable" onclick="sortTable('vulnTable',2,this)">CVSS</th>
        <th class="sortable" onclick="sortTable('vulnTable',3,this)">EPSS</th>
        <th class="sortable" onclick="sortTable('vulnTable',4,this)">Component</th>
        <th>Description</th><th>Fix Version</th>
      </tr>
      {vuln_rows}
    </table>
  </div>

  <!-- License Compliance -->
  <div id="licenses" class="section tabpage">
    <h2>License Compliance</h2>
    <p style="font-size:0.85rem;color:#6c757d;margin-bottom:12px">Scanner: {r.license_scanner_used}</p>
    <div class="chart-row">
      <div>
        <h3 style="font-size:0.95rem;margin-bottom:8px">Top Licenses by File Count</h3>
        <canvas id="chartLicenseBar" height="200"></canvas>
      </div>
      <div>
        <h3 style="font-size:0.95rem;margin-bottom:8px">Copyleft Risk Files ({len(r.copyleft_files):,})</h3>
        {copyleft_list}
      </div>
    </div>
    <div style="display:grid;grid-template-columns:1fr;gap:16px">
      <div>
        <h3 style="font-size:0.95rem;margin-bottom:8px">License Distribution (source files)</h3>
        <table>
          <tr><th>License</th><th>Files</th></tr>
          {lic_rows}
        </table>
      </div>
    </div>
  </div>

  <!-- Code Quality -->
  <div id="quality" class="section tabpage">
    <h2>Code Quality Analysis</h2>
    <p style="font-size:0.85rem;color:#6c757d;margin-bottom:12px">Scanner: {quality_scanner}</p>
    <div class="chart-row" style="grid-template-columns:1fr 1fr 1fr">
      <div>
        <h3 style="font-size:0.95rem;margin-bottom:8px">By Severity</h3>
        {quality_sev_bars}
      </div>
      <div>
        <h3 style="font-size:0.95rem;margin-bottom:8px">By Category</h3>
        {quality_cat_bars}
      </div>
      <div>
        <h3 style="font-size:0.95rem;margin-bottom:8px">Category Distribution</h3>
        <canvas id="chartQualityDonut" height="150"></canvas>
        <div class="chart-legend" id="legendQualityDonut"></div>
      </div>
    </div>

    <h3 style="font-size:1rem;margin:20px 0 8px">Findings</h3>
    <p style="font-size:0.82rem;color:var(--muted);margin-bottom:10px">{quality_shown_note}</p>
    <input class="sbom-search" id="qualitySearch" type="text"
           placeholder="Search by message, rule, file..." oninput="searchQuality(this.value)">
    <div style="overflow-x:auto">
      <table id="qualityTable">
        <thead>
          <tr>
            <th class="sortable" onclick="sortTable('qualityTable',0,this)">Severity</th>
            <th class="sortable" onclick="sortTable('qualityTable',1,this)">Category</th>
            <th>Rule</th>
            <th>Message</th>
            <th>Location</th>
            <th title="Confidence this is a real issue vs. a test fixture/sample (secret findings only)">Confidence</th>
          </tr>
        </thead>
        <tbody id="qualityBody">
          {quality_finding_rows}
        </tbody>
      </table>
    </div>
    <div class="pagination">
      <button id="qualityPrevBtn" onclick="qualityPage(-1)">← Prev</button>
      <span id="qualityPageLabel">Page 1</span>
      <button id="qualityNextBtn" onclick="qualityPage(1)">Next →</button>
    </div>
  </div>

  <!-- Improvement Recommendations -->
  <div id="recommendations" class="section tabpage">
    <h2>Improvement Recommendations</h2>
    <p style="font-size:0.85rem;color:#6c757d;margin-bottom:12px">Sorted by priority — CRITICAL and HIGH items first.</p>
    {rec_cards}
  </div>
  {diff_section}

</div>

<div class="footer">
  Generated by SDK Analyzer Agent &nbsp;|&nbsp; {r.generated_at}
</div>

<script>
// ---- SBOM filter & search ----
function filterSBOM(type) {{
  document.querySelectorAll('.sbom-filter-btn').forEach(b => {{
    b.style.background = b.dataset.filter === type ? '#1a1a2e' : '#fff';
    b.style.color      = b.dataset.filter === type ? '#fff'    : '#333';
  }});
  window._sbomFilter = type;
  applySBOMFilters();
}}

function searchSBOM(q) {{
  window._sbomQuery = q.toLowerCase();
  window._sbomPage = 0;
  applySBOMFilters();
}}

function sbomPage(delta) {{
  window._sbomPage = Math.max(0, (window._sbomPage || 0) + delta);
  applySBOMFilters();
}}

function applySBOMFilters() {{
  const filter   = window._sbomFilter   || 'all';
  const query    = window._sbomQuery    || '';
  const pageSize = window._sbomPageSize || 50;
  let page       = window._sbomPage     || 0;

  // First pass: determine which rows match the filter/search (independent of pagination).
  const allRows = Array.from(document.querySelectorAll('#sbomBody tr.sbom-row'));
  const matched = allRows.filter(row => {{
    const matchType = filter === 'all' || row.dataset.type === filter;
    const matchQ    = !query || row.dataset.name.includes(query) ||
                      row.innerText.toLowerCase().includes(query);
    return matchType && matchQ;
  }});

  const pageCount = Math.max(1, Math.ceil(matched.length / pageSize));
  page = Math.min(page, pageCount - 1);
  window._sbomPage = page;
  const start = page * pageSize, end = start + pageSize;

  allRows.forEach(row => {{ row.style.display = 'none'; }});
  matched.slice(start, end).forEach(row => {{ row.style.display = ''; }});

  document.getElementById('sbomPageLabel').textContent =
    'Page ' + (page + 1) + ' of ' + pageCount;
  document.getElementById('sbomPrevBtn').disabled = page <= 0;
  document.getElementById('sbomNextBtn').disabled = page >= pageCount - 1;

  const total_all = allRows.length;
  const shownStart = matched.length ? start + 1 : 0;
  const shownEnd = Math.min(end, matched.length);
  document.getElementById('sbomCount').textContent =
    'Showing ' + shownStart + '-' + shownEnd + ' of ' + matched.length + ' matching components' +
    (matched.length !== total_all ? ' (filtered from ' + total_all + ' total)' : '');
}}

// ---- Quality findings search & pagination (same pattern as SBOM above) ----
function searchQuality(q) {{
  window._qualityQuery = q.toLowerCase();
  window._qualityPage = 0;
  applyQualityFilters();
}}

function qualityPage(delta) {{
  window._qualityPage = Math.max(0, (window._qualityPage || 0) + delta);
  applyQualityFilters();
}}

function applyQualityFilters() {{
  const query    = window._qualityQuery    || '';
  const pageSize = 50;
  let page       = window._qualityPage     || 0;

  const allRows = Array.from(document.querySelectorAll('#qualityBody tr.quality-row'));
  const matched = allRows.filter(row => !query || row.innerText.toLowerCase().includes(query));

  const pageCount = Math.max(1, Math.ceil(matched.length / pageSize));
  page = Math.min(page, pageCount - 1);
  window._qualityPage = page;
  const start = page * pageSize, end = start + pageSize;

  allRows.forEach(row => {{ row.style.display = 'none'; }});
  matched.slice(start, end).forEach(row => {{ row.style.display = ''; }});

  document.getElementById('qualityPageLabel').textContent =
    'Page ' + (page + 1) + ' of ' + pageCount + ' (' + matched.length + ' findings)';
  document.getElementById('qualityPrevBtn').disabled = page <= 0;
  document.getElementById('qualityNextBtn').disabled = page >= pageCount - 1;
}}
applyQualityFilters();

// ---- Tab navigation: only one section visible at a time (avoids one giant
// scrolling page) — still a single self-contained HTML file, no separate pages.
function showTab(name) {{
  document.querySelectorAll('.tabpage').forEach(el => {{
    el.classList.toggle('active', el.id === name);
  }});
  document.querySelectorAll('#mainNav a').forEach(a => {{
    a.classList.toggle('active', a.dataset.tab === name);
  }});
  window.location.hash = name;
  window.scrollTo({{top: 0, behavior: 'instant'}});
  // Canvases inside a display:none tab report zero width, so charts drawn
  // while hidden come out blank/misersized — redraw once the tab is visible.
  if (typeof renderAllCharts === 'function') renderAllCharts();
}}

document.querySelectorAll('#mainNav a').forEach(a => {{
  a.addEventListener('click', e => {{
    e.preventDefault();
    showTab(a.dataset.tab);
  }});
}});

// Deep-link support: open directly to a tab via #sbom, #vulnerabilities, etc.
(function initTab() {{
  const hash = window.location.hash.replace('#', '');
  const valid = hash && document.getElementById(hash) && document.getElementById(hash).classList.contains('tabpage');
  showTab(valid ? hash : 'overview');
}})();

// Apply default pagination to the SBOM table on first load.
window._sbomPageSize = 50;
window._sbomPage = 0;
applySBOMFilters();
</script>
<script>
{chart_js}
</script>
</body>
</html>"""
