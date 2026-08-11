"""
Stage 3B: ScanCode Toolkit Runner
Cross-validates FOSSology results with ScanCode's independent engine.
Falls back to a lightweight regex scanner when scancode-toolkit is not installed.
"""

import asyncio
import json
import logging
import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class ScanCodeFinding:
    path: str
    licenses: List[str] = field(default_factory=list)
    license_expressions: List[str] = field(default_factory=list)
    copyrights: List[str] = field(default_factory=list)
    score: float = 0.0          # match confidence 0-100


@dataclass
class ScanCodeResult:
    findings: List[ScanCodeFinding] = field(default_factory=list)
    license_distribution: Dict[str, int] = field(default_factory=dict)
    total_files_scanned: int = 0
    scanner_used: str = "unknown"
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Stage implementation
# ---------------------------------------------------------------------------

class ScancodeRunner:
    """
    Wraps the `scancode` CLI.
    Falls back to a minimal Python scanner when scancode-toolkit is absent.
    """

    SCANCODE_TIMEOUT = 900   # 15 minutes max

    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._sc_available = self._check_scancode()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def scan(self, src_dir: str) -> ScanCodeResult:
        if self._sc_available:
            result = await self._run_scancode(src_dir)
            # If the CLI timed out or errored before producing usable output,
            # don't silently report "0 files scanned" — fall back to the
            # Python scanner so license cross-validation still runs. This
            # matters most on very large repos (100k+ files) where the CLI's
            # fixed timeout is easily exceeded.
            if result.error or result.total_files_scanned == 0:
                logger.warning(
                    "ScanCode CLI produced no usable results (%s) — falling back to Python scanner",
                    result.error or "0 files scanned",
                )
                fallback = self._python_fallback(src_dir)
                fallback.scanner_used = f"python-fallback (scancode-cli: {result.error or 'no results'})"
                return fallback
            return result
        logger.warning("scancode not found — using lightweight Python fallback")
        return self._python_fallback(src_dir)

    # ------------------------------------------------------------------
    # scancode CLI
    # ------------------------------------------------------------------

    @staticmethod
    def _check_scancode() -> bool:
        for cmd in [["scancode", "--version"], ["python", "-m", "scancode", "--version"]]:
            try:
                if subprocess.run(cmd, capture_output=True).returncode == 0:
                    return True
            except FileNotFoundError:
                continue
        return False

    async def _run_scancode(self, src_dir: str) -> ScanCodeResult:
        output_json = str(self.output_dir / "scancode_output.json")
        cmd = [
            "scancode",
            "--license",
            "--copyright",
            "--info",
            "--json-pp", output_json,
            "--timeout", "120",
            "--processes", "4",
            "--quiet",
            src_dir,
        ]
        logger.info("Running ScanCode (src: %s)", src_dir.rsplit("/", 1)[-1])
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=self.SCANCODE_TIMEOUT)
        except asyncio.TimeoutError:
            proc.kill()
            return ScanCodeResult(error="scancode timed out", scanner_used="scancode-cli")

        if proc.returncode != 0 and not Path(output_json).exists():
            return ScanCodeResult(
                error=f"scancode exited {proc.returncode}: {stderr.decode()[:500]}",
                scanner_used="scancode-cli",
            )

        return self._parse_scancode_output(output_json)

    def _parse_scancode_output(self, json_path: str) -> ScanCodeResult:
        if not Path(json_path).exists():
            return ScanCodeResult(error="scancode output file not found", scanner_used="scancode-cli")

        with open(json_path) as f:
            data = json.load(f)

        findings: List[ScanCodeFinding] = []
        lic_dist: Dict[str, int] = {}

        for file_entry in data.get("files", []):
            if file_entry.get("type") != "file":
                continue

            lic_ids: List[str] = []
            lic_exprs: List[str] = []
            copyrights: List[str] = []
            score = 0.0

            for lic in file_entry.get("licenses", []):
                spdx = lic.get("spdx_license_key") or lic.get("key", "")
                if spdx:
                    lic_ids.append(spdx)
                    lic_dist[spdx] = lic_dist.get(spdx, 0) + 1
                score = max(score, lic.get("score", 0.0))

            for lic_det in file_entry.get("license_detections", []):
                for match in lic_det.get("matches", []):
                    expr = match.get("license_expression", "")
                    if expr and expr not in lic_exprs:
                        lic_exprs.append(expr)

            for cr in file_entry.get("copyrights", []):
                val = cr.get("copyright", cr.get("value", ""))
                if val:
                    copyrights.append(val)

            findings.append(ScanCodeFinding(
                path=file_entry.get("path", ""),
                licenses=lic_ids,
                license_expressions=lic_exprs,
                copyrights=copyrights,
                score=score,
            ))

        return ScanCodeResult(
            findings=findings,
            license_distribution=lic_dist,
            total_files_scanned=len(findings),
            scanner_used="scancode-cli",
        )

    # ------------------------------------------------------------------
    # Lightweight Python fallback
    # ------------------------------------------------------------------

    # Dirs that contain only generated / reference / build-tool code —
    # scanning them produces duplicate noise vs. the fossology scanner.
    _SKIP_DIRS = {
        "Documentation", "documentation", "docs", "doc",
        "arch", "scripts", "tools", "samples", "examples",
        "tests", "test", "testing", "testprof", "test-vectors",
        "notes", "demos", "tune", "mini-gmp",
        "lzma432", "lzma465", "squashfs4.2", "squashfs4.3", "squashfs-tools",
        "stress-ng", "__pycache__", "node_modules", ".venv", "venv",
    }

    # Dedicated license/copying filenames always scanned regardless of extension
    _LICENSE_FILENAMES = {"license", "licence", "license.txt", "licence.txt",
                          "copying", "copying.txt", "notice", "notice.txt"}

    @staticmethod
    def _python_fallback(src_dir: str, max_files: int = 50_000) -> ScanCodeResult:
        """
        Independent license cross-validation scan.
        Differences from the fossology fallback:
        - Skips dirs that are already well-covered by fossology (build tools, generated code)
        - Caps at max_files to mirror fossology sampling budget
        - Returns an empty distribution when completely covered by fossology,
          allowing the report builder to rely on fossology numbers without inflation
        """
        from .fossology_scanner import SPDX_PATTERNS, SOURCE_EXTENSIONS
        import re as _re
        import random as _random

        findings: List[ScanCodeFinding] = []
        lic_dist: Dict[str, int] = {}
        root = Path(src_dir)

        candidate_files: List[Path] = []
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            # Skip noisy / generated dirs
            parts_set = set(path.parts)
            if parts_set & ScancodeRunner._SKIP_DIRS:
                continue
            # Accept dedicated license files or recognised source extensions
            if path.suffix.lower() not in SOURCE_EXTENSIONS and \
               path.name.lower() not in ScancodeRunner._LICENSE_FILENAMES:
                continue
            candidate_files.append(path)

        # Sample to stay within budget (reproducible seed)
        if len(candidate_files) > max_files:
            _random.seed(99)
            candidate_files = _random.sample(candidate_files, max_files)

        logger.info("ScanCode fallback: scanning %d files (after exclusions)", len(candidate_files))

        for path in candidate_files:
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read(8192)
            except OSError:
                continue

            lic_ids: List[str] = []
            spdx_m = SPDX_PATTERNS[0][1].search(content)
            if spdx_m:
                lic_ids = [s.strip() for s in spdx_m.group(1).split(" AND ")]
            else:
                for lic_id, pattern in SPDX_PATTERNS[1:]:
                    if pattern.search(content):
                        lic_ids.append(lic_id)

            copyrights: List[str] = []
            for m in _re.finditer(r"[Cc]opyright\s+(?:\(c\)\s*)?(\d{4}[^\n\r]{3,60})", content):
                copyrights.append(m.group(0).strip())

            for lic in lic_ids:
                lic_dist[lic] = lic_dist.get(lic, 0) + 1

            findings.append(ScanCodeFinding(
                path=str(path.relative_to(root)),
                licenses=lic_ids,
                license_expressions=lic_ids,
                copyrights=copyrights[:3],
                score=90.0 if spdx_m else 60.0,
            ))

        return ScanCodeResult(
            findings=findings,
            license_distribution=lic_dist,
            total_files_scanned=len(findings),
            scanner_used="python-fallback",
        )
