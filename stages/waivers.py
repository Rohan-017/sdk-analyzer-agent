"""
Waiver/suppression file support for quality & secret findings.

Problem this solves
--------------------
Once a human reviews a finding and decides it's not actionable (a secret
that's already been rotated, a false positive confirmed by security review,
etc.), there was previously no way to record that decision — the finding
would reappear as a fresh FAIL on every subsequent scan, which makes the
tool unusable as a recurring CI gate (nobody can tell a newly-introduced
risk apart from an already-reviewed one in the noise).

This module loads a small YAML waiver list and marks matching findings as
`waived` rather than deleting them — they stay visible in the report for
audit purposes (who waived what, and why) but no longer count toward the
risk score or the "active findings" total, so the gate only fires on
genuinely new/unreviewed issues.

File format (see config/waivers.yml for a template):

    waivers:
      - path: "config/production/old_key.pem"   # glob, relative to SDK root
        rule_id: "gitleaks-private-key"          # exact or prefix match; omit to match any rule
        reason: "Rotated 2024-01-15, ticket JIRA-4521"
        approved_by: "security-team"
"""

import fnmatch
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import List

try:
    import yaml as _yaml
    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False

logger = logging.getLogger(__name__)

DEFAULT_WAIVERS_PATH = Path(__file__).parent.parent / "config" / "waivers.yml"


@dataclass
class WaiverEntry:
    path_glob: str
    rule_id: str = ""          # empty = matches any rule
    reason: str = ""
    approved_by: str = ""


def _relativize(file_path: str, src_root: str) -> str:
    if not src_root:
        return file_path
    try:
        rel = os.path.relpath(file_path, src_root)
    except ValueError:
        return file_path
    return file_path if rel.startswith("..") else rel


def load_waivers(path: str = "") -> List[WaiverEntry]:
    """
    Loads waivers from `path`, or $SDK_ANALYZER_WAIVERS_FILE, or the bundled
    config/waivers.yml if none of those are set/present. Returns an empty
    list (never raises) if yaml isn't installed or the file is missing/empty
    — waivers are an optional convenience, not a hard dependency.
    """
    candidate = path or os.environ.get("SDK_ANALYZER_WAIVERS_FILE", "") or str(DEFAULT_WAIVERS_PATH)
    candidate_path = Path(candidate)
    if not _YAML_AVAILABLE:
        logger.warning("pyyaml not installed — waivers file will not be applied")
        return []
    if not candidate_path.exists():
        return []
    try:
        with open(candidate_path) as f:
            data = _yaml.safe_load(f) or {}
    except Exception as exc:  # noqa: BLE001 — a malformed waivers file must never crash a scan
        logger.warning("Failed to load waivers file %s: %s", candidate_path, exc)
        return []

    entries: List[WaiverEntry] = []
    for item in data.get("waivers", []) or []:
        path_glob = str(item.get("path", "")).strip()
        if not path_glob:
            continue
        entries.append(WaiverEntry(
            path_glob=path_glob,
            rule_id=str(item.get("rule_id", "")).strip(),
            reason=str(item.get("reason", "")).strip() or "No reason given",
            approved_by=str(item.get("approved_by", "")).strip(),
        ))
    return entries


def apply_waivers(findings: List, waivers: List[WaiverEntry], src_root: str = "") -> int:
    """
    Mutates findings in place, setting `waived`/`waiver_reason` on matches.
    Returns the number of findings waived.
    """
    if not waivers:
        return 0
    waived_count = 0
    for f in findings:
        rel_path = _relativize(f.file_path, src_root)
        for w in waivers:
            if w.rule_id and not f.rule_id.startswith(w.rule_id):
                continue
            if not fnmatch.fnmatch(rel_path, w.path_glob):
                continue
            f.waived = True
            reason = w.reason
            if w.approved_by:
                reason = f"{reason} (approved by {w.approved_by})"
            f.waiver_reason = reason
            waived_count += 1
            break
    return waived_count
