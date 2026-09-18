"""
Confidence triage for secret/security findings.

Problem this solves
--------------------
Dedicated secret scanners (gitleaks) and hardcoded-credential rules have a
known false-positive mode: they flag real-looking PEM keys / API-key-shaped
strings that are actually bundled test fixtures, sample certs, or vendored
third-party test data (e.g. "testprof/test_dsa.key" inside libtomcrypt).
Reported directly as ERROR-severity with no distinction, this drowns out the
genuinely actionable findings.

This module adds a `confidence` classification to each secret-ish finding:
  - Tier 1 (always on, no dependency): a deterministic path/filename
    heuristic — fast, reproducible, zero network/tooling requirement.
  - Tier 2 (opt-in, requires a local Ollama install): a small local LLM
    re-checks ambiguous cases with a short chain-of-thought prompt. Runs
    fully offline against localhost:11434 — no finding content (especially
    no actual secret value) is ever sent anywhere over the network, and the
    whole tier is skipped gracefully if Ollama isn't reachable, exactly like
    every other optional tool in this pipeline (Semgrep/gitleaks/Trivy/etc.).
"""

import json
import logging
import os
import re
import urllib.error
import urllib.request
from typing import Dict, List, Tuple

logger = logging.getLogger(__name__)

# Rule IDs this triage applies to — secret-detection and hardcoded-credential
# findings, where the "is this a real secret or test data" question matters.
# Deliberately narrow scope: other rule categories (SQL injection, eval(),
# weak hashes, etc.) don't have this same ambiguity and are left untouched.
TRIAGE_RULE_PREFIXES = ("gitleaks-", "hardcoded-password")

# Path/filename substrings that strongly suggest test/sample/vendored data
# rather than production secrets. Case-insensitive.
TEST_PATH_INDICATORS = [
    "test", "tests", "testprof", "testdata", "test-data",
    "sample", "samples", "example", "examples",
    "fixture", "fixtures", "mock", "mocks", "dummy",
    "demo", "vendor", "third_party", "thirdparty", "3rdparty",
]

_TEST_PATH_RE = re.compile(
    r"(?:^|[\\/_.-])(" + "|".join(re.escape(w) for w in TEST_PATH_INDICATORS) + r")(?:[\\/_.-]|$)",
    re.IGNORECASE,
)


def _matches_triage_scope(rule_id: str) -> bool:
    return any(rule_id.startswith(p) for p in TRIAGE_RULE_PREFIXES)


def _heuristic_classify(file_path: str) -> Tuple[str, str]:
    """
    Tier 1: deterministic path-based heuristic.
    Returns (confidence, reason).
    """
    matches = sorted(set(m.group(1).lower() for m in _TEST_PATH_RE.finditer(file_path)))
    if matches:
        return "LOW", f"Path contains test/sample indicator(s): {', '.join(matches)}"
    return "UNCONFIRMED", "No test/sample path indicator found (heuristic only — not confirmed real)"


def _relativize(file_path: str, src_root: str) -> str:
    """
    Strip the extraction-root prefix (and the SDK's own top-level extracted
    folder name) before running path heuristics. Without this, the heuristic
    would match against the temp working directory (e.g. "/tmp/sdk_work/...")
    or the archive's own top-level name (e.g. an SDK literally named
    "airoha_test_build_2024.zip" extracts to a folder containing "test",
    which would incorrectly downgrade every single file in the whole scan).
    Only genuine sub-path segments below the SDK root should count.
    """
    if not src_root:
        return file_path
    try:
        rel = os.path.relpath(file_path, src_root)
    except ValueError:
        return file_path  # different drives on Windows, etc. — fall back to full path
    if rel.startswith(".."):
        return file_path  # file_path wasn't actually under src_root — use as-is
    return rel


def apply_heuristic_triage(findings: List, src_root: str = "") -> int:
    """
    Tier 1 — always runs, no external dependency. Mutates findings in place.
    `src_root` (the SDK's extracted source directory) is stripped from each
    file path before matching, so temp/working-directory names and the SDK
    archive's own top-level folder name can't pollute the heuristic (see
    `_relativize`). Returns the number of findings tagged.
    """
    tagged = 0
    for f in findings:
        if not _matches_triage_scope(f.rule_id):
            continue
        rel_path = _relativize(f.file_path, src_root)
        confidence, reason = _heuristic_classify(rel_path)
        f.confidence = confidence
        f.confidence_reason = reason
        f.confidence_source = "heuristic"
        tagged += 1
    return tagged


# ---------------------------------------------------------------------------
# Tier 2 — optional local LLM re-check via Ollama
# ---------------------------------------------------------------------------

class AITriageEngine:
    """
    Talks to a local Ollama instance (default http://localhost:11434) to
    re-classify secret findings that the Tier-1 heuristic could not confirm
    either way. Fully offline: only the file path, rule ID, and category are
    sent to the model — never the actual secret value (already redacted
    upstream) and never file contents beyond the path.

    Controlled entirely by environment variables so it is opt-in and safe by
    default:
      SDK_ANALYZER_ENABLE_AI_TRIAGE=1   turn this tier on (default: off)
      SDK_ANALYZER_AI_MODEL             Ollama model tag (default: qwen2.5:3b)
      SDK_ANALYZER_AI_HOST              Ollama API base URL (default: http://localhost:11434)
      SDK_ANALYZER_AI_MAX_CALLS         cap on distinct LLM calls per run (default: 150)
                                        — bounds worst-case runtime on very
                                        large codebases with many findings.
    """

    def __init__(self):
        self.enabled = os.environ.get("SDK_ANALYZER_ENABLE_AI_TRIAGE", "0") == "1"
        self.model = os.environ.get("SDK_ANALYZER_AI_MODEL", "qwen2.5:3b")
        self.host = os.environ.get("SDK_ANALYZER_AI_HOST", "http://localhost:11434").rstrip("/")
        self.max_calls = int(os.environ.get("SDK_ANALYZER_AI_MAX_CALLS", "150"))
        self._available = None  # lazy-checked

    def available(self) -> bool:
        if not self.enabled:
            return False
        if self._available is not None:
            return self._available
        try:
            req = urllib.request.Request(f"{self.host}/api/tags")
            with urllib.request.urlopen(req, timeout=2) as resp:
                data = json.loads(resp.read().decode())
            models = [m.get("name", "") for m in data.get("models", [])]
            self._available = any(self.model in m for m in models)
            if not self._available:
                logger.info(
                    "AI triage requested but model '%s' not found in Ollama (available: %s) — skipping",
                    self.model, models,
                )
        except (urllib.error.URLError, OSError, TimeoutError, ValueError):
            logger.info("AI triage requested but Ollama is not reachable at %s — skipping", self.host)
            self._available = False
        return self._available

    def _classify_one(self, file_path: str, rule_id: str) -> Tuple[str, str, float]:
        """
        Returns (confidence, reason, elapsed_seconds). Raises on any
        transport/parse failure — caller catches and falls back to heuristic.

        NOTE: this is only ever called for findings where the deterministic
        Tier-1 regex heuristic already found ZERO test-path indicators (see
        `apply_heuristic_triage` — only UNCONFIRMED findings reach here).
        Earlier prompt versions re-asked the model to enumerate test
        indicators from scratch, and a 3B local model proved unreliable at
        that exact-substring-matching sub-task: it hallucinated indicator
        words (e.g. "dummy") that were not actually present in the path.
        Small LLMs are worse than a regex at literal string matching, so we
        state the already-verified fact ("no test keywords found") and ask
        the model to do the part it's actually suited for: holistic judgment
        about whether the surrounding path structure looks like a real
        deployment/production location.
        """
        prompt = (
            f"A security scanner ({rule_id}) flagged a possible secret/credential "
            f"in this file path: {file_path}\n\n"
            "A keyword check already confirmed this path contains NONE of the "
            "common test/sample/mock/vendor/fixture markers. Do not re-derive "
            "or invent any such markers — treat that check as already done.\n\n"
            "Your job: judge from the path structure alone whether this looks "
            "like a real production/deployment location (e.g. contains words "
            "like \"production\", \"release\", \"prod\", \"deploy\", \"live\", "
            "\"config\", or a plausible service/hostname) versus an ambiguous "
            "or generic path with no such signal.\n\n"
            'Respond with ONLY this JSON format: {"production_signal_found": true or false, '
            '"classification": "REAL or UNCERTAIN", "confidence": 0-100, "reason": "short reason "'
            '"referencing only words that literally appear in the given path"}'
        )
        body = json.dumps({
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0.1},
        }).encode()
        req = urllib.request.Request(
            f"{self.host}/api/generate", data=body,
            headers={"Content-Type": "application/json"}, method="POST",
        )
        with urllib.request.urlopen(req, timeout=45) as resp:
            outer = json.loads(resp.read().decode())
        raw = outer.get("response", "").strip()
        # Model sometimes wraps JSON in prose/code fences despite instructions —
        # extract the first {...} block defensively.
        match = re.search(r"\{.*\}", raw, re.DOTALL)
        if not match:
            raise ValueError(f"no JSON found in model response: {raw[:200]}")
        parsed = json.loads(match.group(0))
        classification = str(parsed.get("classification", "")).upper()
        confidence_pct = float(parsed.get("confidence", 0))
        reason = str(parsed.get("reason", "")) or "AI classification (no reason given)"

        # Defensive check: don't just trust the model's claim — verify the
        # reason it gives actually references a word that is a genuine
        # substring of the path. This is the same lesson learned from the
        # old prompt's hallucinated "dummy"/"fixture" indicators: a small
        # local model's free-text claims about path content are not
        # trustworthy without a cheap deterministic cross-check.
        path_lower = file_path.lower()
        reason_words = re.findall(r"[a-z0-9_]{3,}", reason.lower())
        reason_grounded = any(w in path_lower for w in reason_words)

        if parsed.get("production_signal_found") and "REAL" in classification and reason_grounded:
            return "MEDIUM", f"{reason} (AI judged production-context signal present; verified against path)", confidence_pct
        if parsed.get("production_signal_found") and "REAL" in classification and not reason_grounded:
            # Model claimed a signal but couldn't ground its reasoning in an
            # actual path substring — treat as an unreliable/hallucinated
            # claim and fall back to UNCONFIRMED rather than trusting it.
            return "UNCONFIRMED", "AI claim could not be grounded in the actual path text — treated as unreliable", confidence_pct
        return "UNCONFIRMED", f"{reason} (no clear production-context signal found by AI)", confidence_pct

    def triage(self, findings: List, src_root: str = "") -> int:
        """
        Refines confidence for findings the heuristic left UNCONFIRMED,
        grouped by (file_path, rule_id) to minimize LLM calls — many
        findings in the same file (e.g. multiple hits in one .dtsi) share
        an identical classification. Mutates findings in place.
        `src_root` is stripped from each path before it's sent to the model,
        for the same reason it's stripped for the heuristic tier (see
        `_relativize`): the temp extraction directory / SDK archive's own
        top-level folder name must never influence the classification.
        Returns the number of unique (path, rule) groups actually queried.
        """
        if not self.available():
            return 0

        groups: Dict[Tuple[str, str], List] = {}
        for f in findings:
            if not _matches_triage_scope(f.rule_id):
                continue
            if f.confidence != "UNCONFIRMED":
                continue  # heuristic already confidently tagged this one
            rel_path = _relativize(f.file_path, src_root)
            groups.setdefault((rel_path, f.rule_id), []).append(f)

        if not groups:
            return 0

        queried = 0
        for (file_path, rule_id), group_findings in groups.items():
            if queried >= self.max_calls:
                logger.info(
                    "AI triage call budget (%d) reached — %d remaining finding groups left as heuristic-only",
                    self.max_calls, len(groups) - queried,
                )
                break
            try:
                confidence, reason, _pct = self._classify_one(file_path, rule_id)
                for f in group_findings:
                    f.confidence = confidence
                    f.confidence_reason = reason
                    f.confidence_source = "ai-local"
            except Exception as exc:  # noqa: BLE001 — any failure just skips this group
                logger.debug("AI triage failed for %s (%s): %s", file_path, rule_id, exc)
            queried += 1

        logger.info("AI triage: classified %d/%d finding groups via local model '%s'",
                     min(queried, len(groups)), len(groups), self.model)
        return queried
