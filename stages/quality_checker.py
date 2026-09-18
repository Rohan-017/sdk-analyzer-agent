"""
Stage 5: Code Quality & Improvement Analysis
Uses Semgrep for static analysis security/quality patterns.
Falls back to a built-in rule engine when Semgrep is not installed.
"""

import asyncio
import json
import logging
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from stages.confidence_triage import AITriageEngine, apply_heuristic_triage
from stages.path_filters import semgrep_exclude_args, gitleaks_allowlist_config
from stages.waivers import apply_waivers, load_waivers

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Built-in rule patterns (fallback)
# ---------------------------------------------------------------------------

@dataclass
class BuiltinRule:
    rule_id: str
    category: str           # security / quality / license / dependency
    severity: str           # ERROR / WARNING / INFO
    message: str
    languages: List[str]
    pattern: re.Pattern


BUILTIN_RULES: List[BuiltinRule] = [
    # --- Security ---
    BuiltinRule("hardcoded-password",   "security", "ERROR",
                "Possible hardcoded password or secret",
                ["all"],
                re.compile(r'(?i)(password|passwd|secret|api_key|apikey|token)\s*=\s*["\'][^"\']{4,}["\']')),
    BuiltinRule("hardcoded-ip",         "security", "WARNING",
                "Hardcoded IP address detected",
                ["all"],
                re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')),
    BuiltinRule("sql-injection-risk",   "security", "ERROR",
                "Potential SQL injection: string concatenation in query",
                ["python", "java", "php", "javascript"],
                re.compile(r'(?i)(execute|query|cursor\.execute)\s*\(\s*[f"\']+.*\+.*\)')),
    BuiltinRule("eval-usage",           "security", "ERROR",
                "Use of eval() is dangerous",
                ["python", "javascript"],
                re.compile(r'\beval\s*\(')),
    BuiltinRule("os-command-injection", "security", "ERROR",
                "Potential OS command injection via shell=True or os.system",
                ["python"],
                re.compile(r'(?:subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True|os\.system\s*\()')),
    BuiltinRule("insecure-hash-md5",    "security", "WARNING",
                "Use of MD5 is cryptographically weak",
                ["all"],
                re.compile(r'\bmd5\b', re.IGNORECASE)),
    BuiltinRule("insecure-hash-sha1",   "security", "WARNING",
                "Use of SHA1 is cryptographically weak",
                ["all"],
                re.compile(r'\bsha1\b', re.IGNORECASE)),
    BuiltinRule("http-not-https",       "security", "WARNING",
                "Plain HTTP URL detected — prefer HTTPS",
                ["all"],
                re.compile(r'http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)')),
    # --- Quality ---
    BuiltinRule("todo-fixme",           "quality",  "INFO",
                "TODO/FIXME comment found",
                ["all"],
                re.compile(r'(?i)\b(TODO|FIXME|HACK|XXX)\b')),
    BuiltinRule("long-line",            "quality",  "INFO",
                "Line exceeds 120 characters",
                ["all"],
                re.compile(r'.{121,}')),
    BuiltinRule("print-debug",          "quality",  "INFO",
                "Debug print statement left in code",
                ["python"],
                re.compile(r'\bprint\s*\(')),
    BuiltinRule("console-log",          "quality",  "INFO",
                "console.log() left in production code",
                ["javascript", "typescript"],
                re.compile(r'\bconsole\.log\s*\(')),
    BuiltinRule("empty-catch",          "quality",  "WARNING",
                "Empty catch block swallows exceptions",
                ["java", "c#", "javascript", "typescript"],
                re.compile(r'catch\s*\([^)]*\)\s*\{\s*\}')),
    # --- Licensing ---
    BuiltinRule("no-license-header",    "license",  "WARNING",
                "Source file appears to have no license header",
                ["all"],
                re.compile(r'^(?!.*(?:license|copyright|spdx))', re.IGNORECASE | re.DOTALL)),
]

EXT_LANGUAGE_MAP = {
    ".py": "python", ".js": "javascript", ".ts": "typescript",
    ".jsx": "javascript", ".tsx": "typescript", ".java": "java",
    ".cs": "c#", ".c": "c", ".cpp": "c++", ".h": "c",
    ".go": "go", ".rs": "rust", ".rb": "ruby", ".php": "php",
    ".sh": "shell",
}


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class QualityFinding:
    rule_id: str
    category: str
    severity: str
    message: str
    file_path: str
    line_number: int
    line_content: str = ""
    fix_suggestion: str = ""
    # Confidence that this finding is a genuine issue rather than a test
    # fixture / dummy / vendored sample (relevant mainly for secret-detection
    # findings, which have a known false-positive risk on test keys). Values:
    # "UNCONFIRMED" (default — no triage applied), "LOW" (looks like a test
    # fixture), "HIGH" (looks like a real, actionable finding).
    confidence: str = "UNCONFIRMED"
    confidence_reason: str = ""
    confidence_source: str = ""   # "heuristic" or "ai-local"
    # Waiver support (see stages/waivers.py) — a reviewed finding is kept
    # visible for audit but excluded from severity/category counts (and
    # therefore the risk score) once waived.
    waived: bool = False
    waiver_reason: str = ""


@dataclass
class ImprovementRecommendation:
    category: str           # security / quality / license / dependency
    priority: str           # P1 / P2 / P3
    title: str
    description: str
    affected_files: List[str] = field(default_factory=list)
    remediation: str = ""


@dataclass
class QualityResult:
    findings: List[QualityFinding] = field(default_factory=list)
    recommendations: List[ImprovementRecommendation] = field(default_factory=list)
    category_counts: Dict[str, int] = field(default_factory=dict)
    severity_counts: Dict[str, int] = field(default_factory=dict)
    total_findings: int = 0
    scanner_used: str = "unknown"
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Stage implementation
# ---------------------------------------------------------------------------

class QualityChecker:

    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._semgrep_available  = self._check_semgrep()
        self._gitleaks_available = self._check_gitleaks()
        self._ai_triage = AITriageEngine()
        self._waivers = load_waivers()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def scan(self, src_dir: str) -> QualityResult:
        if self._semgrep_available:
            result = await self._run_semgrep(src_dir)
        else:
            logger.info("semgrep not found — using built-in rule engine")
            result = self._builtin_scan(src_dir)

        # Secret detection is a distinct, higher-precision concern than
        # Semgrep's generic hardcoded-credential rules — dedicated scanners
        # like gitleaks carry a much larger, continuously-updated library of
        # provider-specific token/key formats (AWS, GitHub, Slack, private
        # keys, etc.) and are the industry standard for this specific job.
        # Run it unconditionally alongside Semgrep/builtin rather than as a
        # replacement, and merge its findings into the same result so they
        # flow through the existing report/HTML pipeline.
        if self._gitleaks_available:
            secret_findings = await self._run_gitleaks(src_dir)
            if secret_findings:
                result.findings.extend(secret_findings)
                result.total_findings = len(result.findings)
                for f in secret_findings:
                    result.category_counts[f.category] = result.category_counts.get(f.category, 0) + 1
                    result.severity_counts[f.severity] = result.severity_counts.get(f.severity, 0) + 1
                result.scanner_used = f"{result.scanner_used}+gitleaks"
        else:
            logger.info("gitleaks not found — secret detection limited to Semgrep/builtin rules")

        # ------------------------------------------------------------------
        # Confidence triage for secret/credential findings — distinguishes
        # real risks from bundled test fixtures (see confidence_triage.py).
        # Tier 1 (heuristic) always runs; Tier 2 (local AI via Ollama) only
        # runs if explicitly enabled and reachable, and only refines cases
        # the heuristic couldn't confidently resolve.
        # ------------------------------------------------------------------
        tagged = apply_heuristic_triage(result.findings, src_root=src_dir)
        if tagged:
            logger.info("Confidence triage: tagged %d secret/credential findings (path heuristic)", tagged)
        ai_queried = self._ai_triage.triage(result.findings, src_root=src_dir)
        if ai_queried:
            logger.info("Confidence triage: refined %d finding group(s) via local AI model", ai_queried)

        # ------------------------------------------------------------------
        # Waivers — previously-reviewed findings (see stages/waivers.py).
        # Waived findings stay in the report for audit visibility but are
        # excluded from severity/category counts so they don't drive the
        # risk score or "active findings" total on every future scan.
        # ------------------------------------------------------------------
        waived = apply_waivers(result.findings, self._waivers, src_root=src_dir)
        if waived:
            logger.info("Waivers: %d finding(s) suppressed by config/waivers.yml", waived)
            result.category_counts = {}
            result.severity_counts = {}
            for f in result.findings:
                if f.waived:
                    continue
                result.category_counts[f.category] = result.category_counts.get(f.category, 0) + 1
                result.severity_counts[f.severity] = result.severity_counts.get(f.severity, 0) + 1

        result.recommendations = self._generate_recommendations(
            [f for f in result.findings if not f.waived]
        )
        return result

    # ------------------------------------------------------------------
    # gitleaks (dedicated secret scanner)
    # ------------------------------------------------------------------

    @staticmethod
    def _check_gitleaks() -> bool:
        try:
            return subprocess.run(["which", "gitleaks"], capture_output=True).returncode == 0
        except FileNotFoundError:
            return False

    async def _run_gitleaks(self, src_dir: str) -> List[QualityFinding]:
        output_json = str(self.output_dir / "gitleaks_output.json")
        # Skip vendored/third-party/test-fixture directories entirely rather
        # than scanning them and relying on confidence_triage.py to relabel
        # the results afterwards — faster, and keeps the raw finding count
        # itself meaningful (see stages/path_filters.py for rationale).
        allowlist_config = str(self.output_dir / "gitleaks_allowlist.toml")
        with open(allowlist_config, "w") as f:
            f.write(gitleaks_allowlist_config())
        cmd = [
            "gitleaks", "detect",
            "--source", src_dir,
            "--no-git",             # scan working tree, not git history
            "--no-banner",
            "--config", allowlist_config,
            "-f", "json",
            "-r", output_json,
            "--exit-code", "0",     # never fail the process on findings
        ]
        logger.info("Running gitleaks secret scan (src: %s)", src_dir.rsplit("/", 1)[-1])
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            await asyncio.wait_for(proc.communicate(), timeout=180)
        except asyncio.TimeoutError:
            proc.kill()
            logger.warning("gitleaks timed out — skipping secret scan for this run")
            return []

        path = Path(output_json)
        if not path.exists():
            return []
        try:
            with open(path) as f:
                raw = f.read().strip()
            leaks = json.loads(raw) if raw else []
        except (json.JSONDecodeError, OSError):
            logger.warning("Failed to parse gitleaks output")
            return []

        findings: List[QualityFinding] = []
        for leak in leaks:
            findings.append(QualityFinding(
                rule_id=f"gitleaks-{leak.get('RuleID', 'secret')}",
                category="security",
                severity="ERROR",
                message=f"Potential secret leaked: {leak.get('Description', leak.get('RuleID', 'unknown'))}",
                file_path=leak.get("File", ""),
                line_number=leak.get("StartLine", 0),
                line_content="[redacted]",  # never surface the actual secret value in reports
                fix_suggestion="Remove the credential from source, rotate it immediately, and load secrets from a vault/env var instead.",
            ))
        return findings

    # ------------------------------------------------------------------
    # Semgrep
    # ------------------------------------------------------------------

    @staticmethod
    def _check_semgrep() -> bool:
        try:
            return subprocess.run(["which", "semgrep"], capture_output=True).returncode == 0
        except FileNotFoundError:
            return False

    # Path to the project's custom Semgrep rule set
    _SEMGREP_CUSTOM_RULES = Path(__file__).parent.parent / "config" / "semgrep_rules.yml"

    async def _run_semgrep(self, src_dir: str) -> QualityResult:
        output_json = str(self.output_dir / "semgrep_output.json")

        # Privacy/air-gap default: Semgrep's "auto" config phones home to the
        # Semgrep Registry to select rules for the detected languages, and
        # sends anonymized usage telemetry unless explicitly disabled. For a
        # tool whose whole purpose is scanning potentially proprietary source
        # code, we default to fully offline operation — only our bundled
        # local rules run, and telemetry is always disabled regardless of
        # mode. Set SDK_ANALYZER_ALLOW_NETWORK_RULES=1 to opt back into the
        # broader (network-dependent) "auto" registry ruleset.
        allow_network_rules = os.environ.get("SDK_ANALYZER_ALLOW_NETWORK_RULES", "") == "1"
        cmd = [
            "semgrep",
            "--json",
            "--output", output_json,
            "--quiet",
            "--timeout", "120",
        ]
        # Skip vendored/third-party/generated/test-fixture dirs entirely —
        # see stages/path_filters.py for rationale (same exclusion list
        # shared with gitleaks and the built-in/license scanners).
        cmd += semgrep_exclude_args()
        if allow_network_rules:
            cmd += ["--config", "auto"]
            logger.info("SDK_ANALYZER_ALLOW_NETWORK_RULES=1 — using Semgrep Registry 'auto' config")
        if self._SEMGREP_CUSTOM_RULES.exists():
            cmd += ["--config", str(self._SEMGREP_CUSTOM_RULES)]
            logger.info("Loading custom Semgrep rules from %s", self._SEMGREP_CUSTOM_RULES)
        elif not allow_network_rules:
            logger.warning("No local Semgrep rules found and network rules disabled — falling back to built-in scanner")
            return self._builtin_scan(src_dir)
        cmd.append(src_dir)
        logger.info("Running Semgrep (src: %s)", src_dir.rsplit("/", 1)[-1])
        env = {**os.environ, "SEMGREP_SEND_METRICS": "off"}
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
        try:
            await asyncio.wait_for(proc.communicate(), timeout=300)
        except asyncio.TimeoutError:
            proc.kill()
            logger.warning("Semgrep timed out — falling back to built-in rule engine")
            return self._builtin_scan(src_dir)

        result = self._parse_semgrep_output(output_json)
        # If Semgrep returned no findings (possible for pure C SDKs with auto config),
        # supplement with the built-in scanner which has explicit C rules
        if result.total_findings == 0 and not result.error:
            logger.info("Semgrep found 0 results — supplementing with built-in C/security scanner")
            builtin = self._builtin_scan(src_dir)
            if builtin.total_findings > 0:
                return builtin
        return result

    def _parse_semgrep_output(self, json_path: str) -> QualityResult:
        if not Path(json_path).exists():
            return QualityResult(error="semgrep output not found", scanner_used="semgrep")

        with open(json_path) as f:
            data = json.load(f)

        findings: List[QualityFinding] = []
        for result in data.get("results", []):
            severity = result.get("extra", {}).get("severity", "INFO").upper()
            findings.append(QualityFinding(
                rule_id=result.get("check_id", ""),
                category=self._infer_category(result.get("check_id", "")),
                severity=severity,
                message=result.get("extra", {}).get("message", ""),
                file_path=result.get("path", ""),
                line_number=result.get("start", {}).get("line", 0),
                line_content=result.get("extra", {}).get("lines", "").strip(),
                fix_suggestion=result.get("extra", {}).get("fix", ""),
            ))

        return self._build_result(findings, scanner="semgrep")

    @staticmethod
    def _infer_category(rule_id: str) -> str:
        rule_id_lower = rule_id.lower()
        if any(k in rule_id_lower for k in ("security", "injection", "xss", "sqli", "auth")):
            return "security"
        if any(k in rule_id_lower for k in ("license", "copyright", "spdx")):
            return "license"
        return "quality"

    # ------------------------------------------------------------------
    # Built-in scanner
    # ------------------------------------------------------------------

    # Non-executable dirs: contain reference text / docs / arch specs,
    # test vectors, generated code or benchmark harnesses that produce
    # high false-positive rates when scanned for security issues.
    NON_EXECUTABLE_DIRS = {
        # Documentation / reference
        "Documentation", "documentation", "docs", "doc", "doxygen_conf",
        # Kernel build infrastructure
        "arch",           # kernel arch-specific (mostly asm/headers)
        "scripts",        # kernel build scripts
        "tools",          # kernel developer tools
        # Test / benchmark / demo code
        "samples",        # code samples / examples
        "examples",
        "tests", "test",  # unit/integration tests (separate concern)
        "testing",
        "testprof",       # libtomcrypt test vectors
        "test-vectors",
        "notes",          # libtomcrypt notes / reference docs
        "demos",          # GMP demos
        "tune",           # GMP tuning harness
        "mini-gmp",       # GMP compatibility shim
        # Generated / third-party build artefacts
        "__pycache__",
        "node_modules",
        ".venv", "venv",
        ".github",
        # Vendored / third-party dependencies — not code the SDK team wrote
        # or can fix; scanning it just inflates finding counts with issues
        # nobody here is responsible for.
        "vendor", "vendored", "third_party", "third-party", "3rdparty", "3rd_party",
        "bower_components",
        # Build/generated output
        "dist", "build", "out", "generated", "gen",
        # Compression / archiving utilities bundled as build tools
        "lzma432", "lzma465",
        "squashfs4.2", "squashfs4.3", "squashfs-tools",
        # Stress-test utilities
        "stress-ng",
    }

    # SDK-specific dirs that ARE executable and should always be scanned
    PRIORITY_QUALITY_DIRS = {
        "tclinux_phoenix",
        "rdk_hal",
        "wlan",
        "app_bsp",
        "public_exclusive",
    }

    def _builtin_scan(self, src_dir: str, max_files: int = 15000) -> QualityResult:
        """
        Run built-in quality rules with context-aware filtering:
        - Skips Documentation/, arch/, tools/, scripts/ (reference text, not code)
        - Prioritises SDK-specific dirs (tclinux_phoenix, rdk_hal, wlan)
        - Caps at max_files per-dir proportionally
        """
        findings: List[QualityFinding] = []
        root = Path(src_dir)

        # Collect priority (SDK-specific) and general files separately
        priority_files:  List[Path] = []
        general_files:   List[Path] = []

        for path in root.rglob("*"):
            if not path.is_file():
                continue
            parts = path.parts
            # Skip non-executable dirs
            if any(part in self.NON_EXECUTABLE_DIRS for part in parts):
                continue
            ext = path.suffix.lower()
            lang = EXT_LANGUAGE_MAP.get(ext, "")
            if not lang and ext not in {".json", ".yaml", ".yml", ".toml"}:
                continue
            if any(part in self.PRIORITY_QUALITY_DIRS for part in parts):
                priority_files.append(path)
            else:
                general_files.append(path)

        # Always scan all priority files; sample general files
        remaining = max_files - len(priority_files)
        sampled_general: List[Path] = []
        if remaining > 0 and general_files:
            import random
            random.seed(42)
            sampled_general = random.sample(general_files, min(remaining, len(general_files)))

        candidate_files = priority_files + sampled_general

        logger.info(
            "Quality scan: %d SDK-specific + %d general-sample = %d files "
            "(skipped %d non-executable files)",
            len(priority_files), len(sampled_general), len(candidate_files),
            len(general_files) - len(sampled_general),
        )

        # Cap individual rule findings to avoid massive output
        rule_hit_counts: Dict[str, int] = {}
        MAX_PER_RULE = 200

        for path in candidate_files:
            ext = path.suffix.lower()
            lang = EXT_LANGUAGE_MAP.get(ext, "")

            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
            except OSError:
                continue

            rel_path = str(path.relative_to(root))
            first_block = "".join(lines[:20]).lower()

            for rule in BUILTIN_RULES:
                if rule_hit_counts.get(rule.rule_id, 0) >= MAX_PER_RULE:
                    continue
                if "all" not in rule.languages and lang not in rule.languages:
                    continue

                # Special handling for no-license-header: check once per file
                if rule.rule_id == "no-license-header":
                    if not re.search(r"(?i)(license|copyright|spdx)", first_block):
                        if ext in EXT_LANGUAGE_MAP:  # only source files
                            findings.append(QualityFinding(
                                rule_id=rule.rule_id,
                                category=rule.category,
                                severity=rule.severity,
                                message=rule.message,
                                file_path=rel_path,
                                line_number=1,
                            ))
                            rule_hit_counts[rule.rule_id] = rule_hit_counts.get(rule.rule_id, 0) + 1
                    continue

                for lineno, line in enumerate(lines, start=1):
                    if rule_hit_counts.get(rule.rule_id, 0) >= MAX_PER_RULE:
                        break
                    if rule.pattern.search(line):
                        findings.append(QualityFinding(
                            rule_id=rule.rule_id,
                            category=rule.category,
                            severity=rule.severity,
                            message=rule.message,
                            file_path=rel_path,
                            line_number=lineno,
                            line_content=line.rstrip()[:120],
                        ))
                        rule_hit_counts[rule.rule_id] = rule_hit_counts.get(rule.rule_id, 0) + 1

        return self._build_result(findings, scanner="builtin")

    # ------------------------------------------------------------------
    # Recommendations engine
    # ------------------------------------------------------------------

    @staticmethod
    def _generate_recommendations(findings: List[QualityFinding]) -> List[ImprovementRecommendation]:
        recs: Dict[str, ImprovementRecommendation] = {}

        rule_remediations: Dict[str, Tuple[str, str, str, str]] = {
            # rule_id → (priority, title, description, remediation)
            "hardcoded-password": (
                "P1", "Remove hardcoded credentials",
                "Hardcoded passwords and secrets are a critical security risk. They can be extracted from source code.",
                "Use environment variables, a secrets manager (HashiCorp Vault, AWS Secrets Manager), or a config file excluded from VCS.",
            ),
            "sql-injection-risk": (
                "P1", "Fix SQL injection vulnerabilities",
                "String concatenation in SQL queries allows attackers to manipulate database operations.",
                "Use parameterized queries or prepared statements.",
            ),
            "eval-usage": (
                "P1", "Replace eval() calls",
                "eval() executes arbitrary code and is a severe security risk.",
                "Replace with safe alternatives like JSON.parse(), ast.literal_eval(), or explicit parsing.",
            ),
            "os-command-injection": (
                "P1", "Fix OS command injection risks",
                "Using shell=True or os.system() with user-controlled input allows command injection.",
                "Use subprocess.run() with a list of arguments and shell=False.",
            ),
            "insecure-hash-md5": (
                "P2", "Replace MD5 with a secure hash algorithm",
                "MD5 is cryptographically broken and unsuitable for security purposes.",
                "Use SHA-256 or SHA-3 via the hashlib library.",
            ),
            "insecure-hash-sha1": (
                "P2", "Replace SHA1 with a secure hash algorithm",
                "SHA1 is deprecated for security use cases.",
                "Use SHA-256 or SHA-3.",
            ),
            "http-not-https": (
                "P2", "Replace HTTP URLs with HTTPS",
                "Plain HTTP transmits data in cleartext, making it vulnerable to interception.",
                "Update all URLs to use HTTPS.",
            ),
            "no-license-header": (
                "P2", "Add SPDX license headers to source files",
                "Source files without license headers create legal ambiguity.",
                "Add SPDX-License-Identifier comments to all source files.",
            ),
            "hardcoded-ip": (
                "P3", "Remove hardcoded IP addresses",
                "Hardcoded IPs reduce portability and create maintenance overhead.",
                "Use configuration files, environment variables, or DNS names.",
            ),
            "todo-fixme": (
                "P3", "Resolve TODO/FIXME comments",
                "Unresolved TODO/FIXME comments may indicate incomplete or broken functionality.",
                "Create tracking issues and resolve them before release.",
            ),
        }

        affected_by_rule: Dict[str, List[str]] = {}
        for f in findings:
            affected_by_rule.setdefault(f.rule_id, []).append(f.file_path)

        for rule_id, files in affected_by_rule.items():
            if rule_id in rule_remediations:
                priority, title, desc, rem = rule_remediations[rule_id]
                rec = ImprovementRecommendation(
                    category="security" if priority == "P1" else "quality",
                    priority=priority,
                    title=title,
                    description=desc,
                    affected_files=sorted(set(files))[:20],
                    remediation=rem,
                )
                recs[rule_id] = rec

        # Sort by priority
        return sorted(recs.values(), key=lambda r: r.priority)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_result(findings: List[QualityFinding], scanner: str) -> QualityResult:
        cat_counts: Dict[str, int] = {}
        sev_counts: Dict[str, int] = {}
        for f in findings:
            cat_counts[f.category] = cat_counts.get(f.category, 0) + 1
            sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
        return QualityResult(
            findings=findings,
            category_counts=cat_counts,
            severity_counts=sev_counts,
            total_findings=len(findings),
            scanner_used=scanner,
        )
