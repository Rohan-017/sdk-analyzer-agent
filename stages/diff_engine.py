"""
Scan Diffing
============
Compares the current analysis report against a previous baseline report
(a `sdk_analysis_report.json` from an earlier run) so users can see what
changed between two scans of the same SDK — new/resolved vulnerabilities,
added/removed SBOM components, and risk trend. This mirrors the "baseline"
feature in commercial SCA tools that lets teams gate CI on *newly introduced*
issues rather than re-litigating the entire backlog every run.
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


def _normalize(report: Dict[str, Any]) -> Dict[str, Any]:
    """
    Return a flat access view of a report dict, regardless of whether it was
    written in the current nested schema (schema_version 2.0: sdk_name,
    vulnerabilities.top_findings, sbom.components, licenses.distribution, ...)
    or an older flat schema (top_vulnerabilities, sbom_components,
    license_distribution, ... all at the top level). This keeps diffing
    against old baseline reports working after the schema change.
    """
    if "schema_version" in report:
        vulns = report.get("vulnerabilities", {})
        sbom = report.get("sbom", {})
        licenses = report.get("licenses", {})
        risk = report.get("risk", {})
        return {
            "sdk_name":              report.get("sdk_name"),
            "generated_at":          report.get("generated_at"),
            "risk_score":            risk.get("score", 0.0),
            "risk_level":            risk.get("level"),
            "compliance_status":     risk.get("compliance_status"),
            "top_vulnerabilities":   vulns.get("top_findings", []),
            "sbom_components":       sbom.get("components", []),
            "license_distribution":  licenses.get("distribution", {}),
        }
    # Legacy flat schema — already in the expected shape.
    return report


def load_baseline(path: str) -> Optional[Dict[str, Any]]:
    """Load a previous sdk_analysis_report.json. Returns None if unavailable/invalid."""
    p = Path(path)
    if not p.exists():
        logger.warning("Baseline report not found: %s", path)
        return None
    try:
        with open(p) as f:
            return json.load(f)
    except Exception as exc:
        logger.warning("Failed to parse baseline report %s: %s", path, exc)
        return None


def build_diff(current: Dict[str, Any], baseline: Dict[str, Any]) -> Dict[str, Any]:
    """
    Compute a diff between the current report dict and a baseline report dict
    (both are the JSON-serializable dict form of AnalysisReport, in either the
    current nested schema or an older flat one).
    """
    current = _normalize(current)
    baseline = _normalize(baseline)

    cur_vulns = {v["cve_id"]: v for v in current.get("top_vulnerabilities", []) if v.get("cve_id")}
    base_vulns = {v["cve_id"]: v for v in baseline.get("top_vulnerabilities", []) if v.get("cve_id")}

    new_vulnerabilities = [cur_vulns[cid] for cid in cur_vulns if cid not in base_vulns]
    resolved_vulnerabilities = [base_vulns[cid] for cid in base_vulns if cid not in cur_vulns]
    persisting_vulnerabilities = [cur_vulns[cid] for cid in cur_vulns if cid in base_vulns]

    cur_comps = {
        (c["name"], c.get("version", "")): c for c in current.get("sbom_components", [])
    }
    base_comps = {
        (c["name"], c.get("version", "")): c for c in baseline.get("sbom_components", [])
    }
    new_components = [cur_comps[k] for k in cur_comps if k not in base_comps]
    removed_components = [base_comps[k] for k in base_comps if k not in cur_comps]

    cur_licenses = set(current.get("license_distribution", {}).keys())
    base_licenses = set(baseline.get("license_distribution", {}).keys())
    new_licenses = sorted(cur_licenses - base_licenses)
    removed_licenses = sorted(base_licenses - cur_licenses)

    risk_delta = round(current.get("risk_score", 0.0) - baseline.get("risk_score", 0.0), 1)

    diff = {
        "baseline_sdk_name": baseline.get("sdk_name"),
        "baseline_generated_at": baseline.get("generated_at"),
        "current_sdk_name": current.get("sdk_name"),
        "current_generated_at": current.get("generated_at"),

        "risk_score_before": baseline.get("risk_score", 0.0),
        "risk_score_after": current.get("risk_score", 0.0),
        "risk_score_delta": risk_delta,
        "risk_level_before": baseline.get("risk_level"),
        "risk_level_after": current.get("risk_level"),
        "compliance_status_before": baseline.get("compliance_status"),
        "compliance_status_after": current.get("compliance_status"),

        "new_vulnerabilities": new_vulnerabilities,
        "new_vulnerabilities_count": len(new_vulnerabilities),
        "resolved_vulnerabilities": resolved_vulnerabilities,
        "resolved_vulnerabilities_count": len(resolved_vulnerabilities),
        "persisting_vulnerabilities_count": len(persisting_vulnerabilities),

        "new_components": new_components,
        "new_components_count": len(new_components),
        "removed_components": removed_components,
        "removed_components_count": len(removed_components),

        "new_licenses": new_licenses,
        "removed_licenses": removed_licenses,

        "verdict": _verdict(new_vulnerabilities, risk_delta, current, baseline),
    }
    return diff


def _verdict(new_vulnerabilities: List[Dict[str, Any]], risk_delta: float,
             current: Dict[str, Any], baseline: Dict[str, Any]) -> str:
    """One-line human verdict summarizing the diff, useful for CI PR comments."""
    new_critical_high = sum(
        1 for v in new_vulnerabilities if v.get("severity") in ("CRITICAL", "HIGH")
    )
    if new_critical_high:
        return f"REGRESSION: {new_critical_high} new CRITICAL/HIGH vulnerabilit{'y' if new_critical_high==1 else 'ies'} introduced"
    if risk_delta > 0:
        return f"WORSE: risk score increased by {risk_delta} points"
    if risk_delta < 0:
        return f"IMPROVED: risk score decreased by {abs(risk_delta)} points"
    return "NO CHANGE: risk score unchanged"


def write_diff(diff: Dict[str, Any], output_path: str) -> None:
    with open(output_path, "w") as f:
        json.dump(diff, f, indent=2)
    logger.info("Scan diff written: %s", output_path)
