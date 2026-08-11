"""
Stage 3A: FOSSology License Scanner
Uses FOSSology REST API when a server is available,
falls back to the `nomos` CLI (part of fossology-utils) or
a pure-Python regex-based scanner when neither is present.
"""

import asyncio
import hashlib
import json
import logging
import os
import re
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import aiohttp

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# License SPDX identifier patterns (used by the pure-Python fallback)
# ---------------------------------------------------------------------------

# Characters / tokens to strip from raw SPDX captures
_SPDX_CLEANUP_RE = re.compile(r'\s*\*/?\s*$|^\s*\(|\)\s*$')

def _clean_spdx(raw: str) -> str:
    """
    Strip trailing C comment markers ( */ ), leading ( and trailing )
    from a raw SPDX-License-Identifier capture value.
    Also handles tab-separated dual-license strings.
    """
    raw = raw.strip()
    # Remove trailing C comment: " */" or "*/"
    raw = re.sub(r'\s*\*\/\s*$', '', raw)
    # Remove wrapping parens if they span the whole string
    if raw.startswith('(') and raw.endswith(')'):
        raw = raw[1:-1].strip()
    # Normalise tabs to space
    raw = re.sub(r'\t', ' ', raw)
    return raw.strip()


SPDX_PATTERNS: List[Tuple[str, re.Pattern]] = [
    # Explicit SPDX tag
    ("SPDX",        re.compile(r"SPDX-License-Identifier:\s*([^\n\r]+)", re.IGNORECASE)),
    ("MIT",         re.compile(r"\bMIT\s+License\b", re.IGNORECASE)),
    ("Apache-2.0",  re.compile(r"Apache\s+License[,\s]*Version\s*2\.0", re.IGNORECASE)),
    ("GPL-2.0",     re.compile(r"GNU\s+General\s+Public\s+License[,\s]*[Vv]ersion\s*2", re.IGNORECASE)),
    ("GPL-3.0",     re.compile(r"GNU\s+General\s+Public\s+License[,\s]*[Vv]ersion\s*3", re.IGNORECASE)),
    ("LGPL-2.0",    re.compile(r"GNU\s+Lesser\s+General\s+Public\s+License[,\s]*[Vv]ersion\s*2(?:\.0)?(?!\.[1-9])", re.IGNORECASE)),
    ("LGPL-2.1",    re.compile(r"GNU\s+Lesser\s+General\s+Public\s+License[,\s]*[Vv]ersion\s*2\.1", re.IGNORECASE)),
    ("LGPL-3.0",    re.compile(r"GNU\s+Lesser\s+General\s+Public\s+License[,\s]*[Vv]ersion\s*3", re.IGNORECASE)),
    ("AGPL-3.0",    re.compile(r"GNU\s+Affero\s+General\s+Public\s+License", re.IGNORECASE)),
    ("BSD-2-Clause",re.compile(r"BSD\s+2[-\s]Clause", re.IGNORECASE)),
    ("BSD-3-Clause",re.compile(r"BSD\s+3[-\s]Clause|Redistribution\s+and\s+use\s+in\s+source\s+and\s+binary\s+forms", re.IGNORECASE)),
    ("ISC",         re.compile(r"\bISC\s+License\b", re.IGNORECASE)),
    ("MPL-2.0",     re.compile(r"Mozilla\s+Public\s+License[,\s]*[Vv]ersion\s*2", re.IGNORECASE)),
    ("EPL-2.0",     re.compile(r"Eclipse\s+Public\s+License[,\s]*[Vv]ersion?\s*2", re.IGNORECASE)),
    ("CDDL-1.0",    re.compile(r"Common\s+Development\s+and\s+Distribution\s+License", re.IGNORECASE)),
    ("Unlicense",   re.compile(r"\bUnlicense\b", re.IGNORECASE)),
    ("CC0-1.0",     re.compile(r"Creative\s+Commons\s+Zero|CC0", re.IGNORECASE)),
    ("Proprietary", re.compile(r"All\s+[Rr]ights\s+[Rr]eserved|Proprietary|Confidential", re.IGNORECASE)),
]

COPYLEFT_LICENSES = {"GPL-2.0", "GPL-3.0", "LGPL-2.0", "LGPL-2.1", "LGPL-3.0", "AGPL-3.0", "MPL-2.0", "CDDL-1.0", "EPL-2.0"}
SOURCE_EXTENSIONS = {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".py", ".js", ".ts", ".java",
                     ".kt", ".go", ".rs", ".rb", ".php", ".cs", ".swift", ".sh", ".bash", ".m"}


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class FileLicenseFinding:
    file_path: str
    licenses: List[str] = field(default_factory=list)
    copyrights: List[str] = field(default_factory=list)
    is_copyleft: bool = False
    has_license_header: bool = False
    scanner: str = "unknown"


@dataclass
class FossologyResult:
    findings: List[FileLicenseFinding] = field(default_factory=list)
    license_distribution: Dict[str, int] = field(default_factory=dict)
    copyleft_files: List[str] = field(default_factory=list)
    files_without_license: List[str] = field(default_factory=list)
    total_files_scanned: int = 0
    scanner_used: str = "unknown"
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Stage implementation
# ---------------------------------------------------------------------------

class FossologyScanner:
    """
    Priority order:
    1. FOSSology REST API (if FOSSOLOGY_URL env var is set and server is reachable)
    2. `nomos` CLI (fossology-utils package)
    3. Pure-Python regex fallback
    """

    def __init__(
        self,
        fossology_url: Optional[str] = None,
        fossology_token: Optional[str] = None,
    ):
        self.fossology_url   = fossology_url   or os.getenv("FOSSOLOGY_URL", "")
        self.fossology_token = fossology_token or os.getenv("FOSSOLOGY_TOKEN", "")
        self._nomos_available = self._check_nomos()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def scan(self, src_dir: str) -> FossologyResult:
        if self.fossology_url:
            try:
                return await self._scan_via_rest_api(src_dir)
            except Exception as exc:
                logger.warning("FOSSology REST API scan failed (%s), trying fallback", exc)

        if self._nomos_available:
            return await self._scan_via_nomos(src_dir)

        logger.info("Using pure-Python regex license scanner")
        return self._scan_python_fallback(src_dir)

    # ------------------------------------------------------------------
    # FOSSology REST API
    # ------------------------------------------------------------------

    async def _scan_via_rest_api(self, src_dir: str) -> FossologyResult:
        logger.info("Scanning via FOSSology REST API at %s", self.fossology_url)
        token = self.fossology_token.strip()
        # FOSSology's /tokens endpoint returns the value already prefixed with
        # "Bearer ", so avoid double-prefixing if the caller passed that through.
        auth_value = token if token.lower().startswith("bearer ") else f"Bearer {token}"
        headers = {"Authorization": auth_value}

        async with aiohttp.ClientSession(headers=headers) as session:
            # 1. Create a tar archive of src_dir and upload it
            with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as tmp:
                tmp_path = tmp.name
            subprocess.run(["tar", "czf", tmp_path, "-C", src_dir, "."], check=True)

            upload_id = await self._fossology_upload(session, tmp_path)
            os.unlink(tmp_path)

            # 2. Schedule scans. FOSSology needs a brief moment to register a
            # freshly-uploaded file before it will accept jobs against it —
            # retry with backoff instead of failing on the first race.
            job_id = await self._fossology_schedule_jobs_with_retry(session, upload_id)

            # 3. Poll until done
            await self._fossology_wait_job(session, job_id)

            # 4. Fetch results
            findings = await self._fossology_fetch_licenses(session, upload_id)

        return self._build_result(findings, scanner="fossology-rest")

    async def _fossology_upload(self, session: aiohttp.ClientSession, tar_path: str) -> int:
        with open(tar_path, "rb") as f:
            form = aiohttp.FormData()
            form.add_field("fileInput", f, filename="sdk_source.tar.gz", content_type="application/gzip")
            async with session.post(
                f"{self.fossology_url}/api/v1/uploads",
                data=form,
                # FOSSology's REST API requires both folderId and uploadType
                # headers on the multipart upload, or it rejects the request
                # with "Require uploadType" (400).
                headers={"folderId": "1", "uploadType": "file"},
            ) as resp:
                data = await resp.json()
                if resp.status not in (200, 201) or "message" not in data:
                    raise RuntimeError(f"FOSSology upload failed: {data}")
                return int(data["message"])

    async def _fossology_schedule_jobs_with_retry(
        self, session: aiohttp.ClientSession, upload_id: int,
        attempts: int = 6, base_delay: float = 2.0,
    ) -> int:
        last_exc: Optional[Exception] = None
        for attempt in range(attempts):
            try:
                return await self._fossology_schedule_jobs(session, upload_id)
            except RuntimeError as exc:
                last_exc = exc
                if "does not have upload id" not in str(exc):
                    raise
                await asyncio.sleep(base_delay * (attempt + 1))
        raise last_exc  # type: ignore[misc]

    async def _fossology_schedule_jobs(self, session: aiohttp.ClientSession, upload_id: int) -> int:
        url = f"{self.fossology_url}/api/v1/jobs"
        payload = {
            "analysis": {"bucket": True, "copyright_email_author": True,
                         "ecc": True, "keyword": True, "monk": True,
                         "mime": True, "monk": True, "nomos": True,
                         "package": True},
            "decider": {"nomos_monk": True, "bulk_reused": True,
                        "new_scanner": True, "ojo_decider": True},
            "reuse": {"reuse_upload": 0, "reuse_group": 0,
                      "reuse_main": False, "reuse_enhanced": False},
        }
        async with session.post(
            url,
            json=payload,
            # FOSSology's REST API requires folderId/uploadId as headers,
            # not query params — sending them as params yields "Folder id
            # and upload id should be integers!" even though the values
            # are valid integers.
            headers={"folderId": "1", "uploadId": str(upload_id)},
        ) as resp:
            data = await resp.json()
            if resp.status not in (200, 201) or "message" not in data:
                raise RuntimeError(f"FOSSology job scheduling failed: {data}")
            return int(data["message"])

    async def _fossology_wait_job(self, session: aiohttp.ClientSession, job_id: int, timeout: int = 600) -> None:
        url = f"{self.fossology_url}/api/v1/jobs/{job_id}"
        deadline = time.time() + timeout
        while time.time() < deadline:
            async with session.get(url) as resp:
                data = await resp.json()
            status = data.get("status", "")
            if status == "Completed":
                return
            if status in ("Failed", "Error"):
                raise RuntimeError(f"FOSSology job {job_id} failed: {status}")
            logger.debug("FOSSology job %d status: %s — waiting…", job_id, status)
            await asyncio.sleep(10)
        raise TimeoutError(f"FOSSology job {job_id} did not complete in {timeout}s")

    async def _fossology_fetch_licenses(
        self, session: aiohttp.ClientSession, upload_id: int
    ) -> List[FileLicenseFinding]:
        # The `agent` query param is mandatory — FOSSology returns
        # "agent parameter missing from query." (400) without it.
        url = f"{self.fossology_url}/api/v1/uploads/{upload_id}/licenses"
        async with session.get(url, params={"agent": "nomos"}) as resp:
            data = await resp.json()

        if isinstance(data, dict) and data.get("code"):
            raise RuntimeError(f"FOSSology license fetch failed: {data}")

        findings = []
        # Strip the temporary tar wrapper directories FOSSology creates on
        # upload (e.g. "sdk_source.tar.gz/sdk_source.tar/foo.py" -> "foo.py")
        # and skip the synthetic entries for the archive containers
        # themselves (no license/copyright data of their own).
        archive_prefix_re = re.compile(r"^[^/]+\.tar\.gz/[^/]+\.tar/")
        for item in data:
            # Real response shape:
            # {"filePath": ..., "findings": {"scanner": [...], "conclusion": ..., "copyright": ...}}
            raw_path = item.get("filePath", "")
            if archive_prefix_re.fullmatch(raw_path) or raw_path.endswith((".tar", ".tar.gz")):
                continue
            file_path = archive_prefix_re.sub("", raw_path)
            file_findings = item.get("findings", {}) or {}
            lic_names = file_findings.get("scanner") or []
            copyright_val = file_findings.get("copyright")
            copyrights = (
                copyright_val if isinstance(copyright_val, list)
                else [copyright_val] if copyright_val else []
            )
            f = FileLicenseFinding(
                file_path=file_path,
                licenses=lic_names,
                copyrights=copyrights,
                is_copyleft=any(l in COPYLEFT_LICENSES for l in lic_names),
                has_license_header=bool(lic_names),
                scanner="fossology-rest",
            )
            findings.append(f)
        return findings

    # ------------------------------------------------------------------
    # nomos CLI
    # ------------------------------------------------------------------

    @staticmethod
    def _check_nomos() -> bool:
        try:
            return subprocess.run(["which", "nomos"], capture_output=True).returncode == 0
        except FileNotFoundError:
            return False

    async def _scan_via_nomos(self, src_dir: str) -> FossologyResult:
        logger.info("Scanning via nomos CLI")
        findings: List[FileLicenseFinding] = []

        proc = await asyncio.create_subprocess_exec(
            "nomos", "-l", src_dir,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await proc.communicate()

        for line in stdout.decode(errors="replace").splitlines():
            # nomos output: "File path   license1,license2"
            parts = line.rsplit(None, 1)
            if len(parts) == 2:
                path, lics_str = parts
                lics = [l.strip() for l in lics_str.split(",") if l.strip() and l.strip() != "No_license_found"]
                findings.append(FileLicenseFinding(
                    file_path=path.strip(),
                    licenses=lics,
                    is_copyleft=any(l in COPYLEFT_LICENSES for l in lics),
                    has_license_header=bool(lics),
                    scanner="nomos",
                ))

        return self._build_result(findings, scanner="nomos")

    # ------------------------------------------------------------------
    # Pure-Python fallback
    # ------------------------------------------------------------------

    # Directories that are well-characterised upstream and can be sampled
    # rather than fully scanned (generic Linux kernel tree, arch-specific docs)
    SAMPLE_ONLY_DIRS = {
        "ecnt_linux",   # generic Linux kernel — already well-characterised
        "arch",
        "Documentation",
        "documentation",
    }

    # SDK-specific dirs that should always be scanned fully
    PRIORITY_DIRS = {
        "tclinux_phoenix",
        "rdk_hal",
        "wlan",
        "app_bsp",
        "public",
        "public_exclusive",
        "private",
    }

    def _scan_python_fallback(self, src_dir: str, max_files: int = 50000) -> FossologyResult:
        """
        Scan source files for license headers with smart coverage:
        - Always scan: LICENSE/COPYING files (all of them)
        - Always scan fully: SDK-specific dirs (tclinux_phoenix, rdk_hal, wlan)
        - Sample only: generic kernel tree (ecnt_linux) to stay tractable
        - Cap at max_files total
        """
        findings: List[FileLicenseFinding] = []
        root = Path(src_dir)

        # Priority 1: dedicated license/copying files — always scan ALL
        LICENSE_NAMES = {
            "license", "licence", "license.txt", "licence.txt",
            "license.md", "copying", "copying.txt", "notice",
            "copyright", "authors",
        }
        license_files: List[Path] = []
        for path in root.rglob("*"):
            if path.is_file() and path.name.lower() in LICENSE_NAMES:
                license_files.append(path)

        # Priority 2: collect source files, split by priority vs sample-only
        skip_dirs = {".git", "__pycache__", "node_modules", ".venv", "venv",
                     "build", "dist"}
        priority_files: List[Path] = []
        sample_pool:    List[Path] = []

        for path in root.rglob("*"):
            if not path.is_file():
                continue
            parts_set = set(path.parts)
            if parts_set & skip_dirs:
                continue
            if path.suffix.lower() not in SOURCE_EXTENSIONS:
                continue
            # Determine if this file is in a sample-only subtree
            in_sample_only = any(part in self.SAMPLE_ONLY_DIRS for part in path.parts)
            if in_sample_only:
                sample_pool.append(path)
            else:
                priority_files.append(path)

        # Always scan all priority files; sample from the generic kernel tree
        remaining = max_files - len(license_files) - len(priority_files)
        sampled_files: List[Path] = []
        if remaining > 0 and sample_pool:
            import random
            random.seed(42)
            sampled_files = random.sample(sample_pool, min(remaining, len(sample_pool)))

        files_to_scan = license_files + priority_files + sampled_files
        logger.info(
            "License scan: %d license-files + %d SDK-specific + %d kernel-sample = %d total "
            "(of %d total source files)",
            len(license_files), len(priority_files), len(sampled_files),
            len(files_to_scan), len(priority_files) + len(sample_pool),
        )

        for path in files_to_scan:
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read(8192)
            except OSError:
                continue

            found_licenses: List[str] = []
            copyrights: List[str] = []

            # SPDX-License-Identifier takes priority
            spdx_m = SPDX_PATTERNS[0][1].search(content)
            if spdx_m:
                raw_expr = _clean_spdx(spdx_m.group(1))
                found_licenses = [_clean_spdx(s) for s in re.split(r'\s+(?:AND|OR|and|or)\s+', raw_expr)]
                found_licenses = [l for l in found_licenses if l]
            else:
                for lic_id, pattern in SPDX_PATTERNS[1:]:
                    if pattern.search(content):
                        found_licenses.append(lic_id)

            # Copyright extraction
            for m in re.finditer(r"[Cc]opyright\s+(?:\(c\)\s*)?(\d{4}(?:[–\-]\d{2,4})?\s+[^\n\r]{3,80})", content):
                copyrights.append(m.group(0).strip())

            rel_path = str(path.relative_to(root))
            findings.append(FileLicenseFinding(
                file_path=rel_path,
                licenses=found_licenses,
                copyrights=copyrights[:5],
                is_copyleft=any(l in COPYLEFT_LICENSES for l in found_licenses),
                has_license_header=bool(found_licenses),
                scanner="python-regex",
            ))

        return self._build_result(findings, scanner="python-regex")

    # ------------------------------------------------------------------
    # Result builder
    # ------------------------------------------------------------------

    @staticmethod
    def _build_result(findings: List[FileLicenseFinding], scanner: str) -> FossologyResult:
        lic_dist: Dict[str, int] = {}
        copyleft_files: List[str] = []
        no_license_files: List[str] = []

        for f in findings:
            if not f.has_license_header or not f.licenses:
                no_license_files.append(f.file_path)
            for lic in f.licenses:
                lic_dist[lic] = lic_dist.get(lic, 0) + 1
            if f.is_copyleft:
                copyleft_files.append(f.file_path)

        return FossologyResult(
            findings=findings,
            license_distribution=lic_dist,
            copyleft_files=copyleft_files,
            files_without_license=no_license_files,
            total_files_scanned=len(findings),
            scanner_used=scanner,
        )
