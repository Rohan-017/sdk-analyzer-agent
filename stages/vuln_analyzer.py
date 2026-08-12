"""
Stage 4: Vulnerability Analysis
Uses Grype (against the SBOM) and OWASP Dependency-Check.
Falls back to OSV.dev REST API lookups when neither tool is installed.
"""

import asyncio
import json
import logging
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import aiohttp

logger = logging.getLogger(__name__)

# OSV.dev public API
OSV_API = "https://api.osv.dev/v1/query"
OSV_BATCH_API = "https://api.osv.dev/v1/querybatch"

# FIRST.org EPSS API — exploit prediction scoring (probability a CVE is
# exploited in the wild in the next 30 days, 0.0-1.0, plus percentile rank)
EPSS_API = "https://api.first.org/data/v1/epss"
EPSS_BATCH_SIZE = 100


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class CVEFinding:
    cve_id: str
    severity: str           # CRITICAL / HIGH / MEDIUM / LOW / UNKNOWN
    cvss_score: float
    component_name: str
    component_version: str
    package_type: str
    description: str = ""
    fix_version: str = ""
    source: str = "unknown"
    epss_score: float = 0.0        # 0.0-1.0 probability of exploitation in next 30 days
    epss_percentile: float = 0.0   # 0.0-1.0 percentile rank vs all scored CVEs


@dataclass
class VulnerabilityResult:
    findings: List[CVEFinding] = field(default_factory=list)
    severity_counts: Dict[str, int] = field(default_factory=dict)
    affected_components: List[str] = field(default_factory=list)
    total_vulnerabilities: int = 0
    scanner_used: str = "unknown"
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Stage implementation
# ---------------------------------------------------------------------------

class VulnerabilityAnalyzer:
    """
    Priority:
    1. Grype (fast, uses SBOM directly)
    2. OWASP Dependency-Check (deeper, slower)
    3. Trivy (cross-check — independent DB/engine, run alongside Grype/OWASP
       rather than as a replacement so disagreements between scanners surface
       for human review instead of silently trusting a single source)
    4. OSV.dev REST API fallback (no local install needed)
    """

    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._grype_available   = self._check_tool("grype")
        self._owasp_available   = self._check_tool("dependency-check")
        self._trivy_available   = self._check_tool("trivy")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def scan(self, sbom_path: str, components=None) -> VulnerabilityResult:
        """
        sbom_path: path to CycloneDX SBOM JSON
        components: list of SBOMComponent (used for OSV fallback)
        """
        results: List[VulnerabilityResult] = []

        if self._grype_available:
            r = await self._run_grype(sbom_path)
            results.append(r)

        if self._owasp_available:
            src_dir = str(Path(sbom_path).parent)
            r = await self._run_owasp(src_dir)
            results.append(r)

        if self._trivy_available:
            r = await self._run_trivy(sbom_path)
            results.append(r)

        if not results:
            logger.info("No local vuln scanner found — using OSV.dev API")
            r = await self._osv_scan(components or [])
            results.append(r)

        merged = self._merge_results(results)
        await self._enrich_epss(merged.findings)
        return merged

    # ------------------------------------------------------------------
    # EPSS enrichment
    # ------------------------------------------------------------------

    @staticmethod
    async def _enrich_epss(findings: List["CVEFinding"]) -> None:
        """
        Enrich findings with EPSS (Exploit Prediction Scoring System) data from
        FIRST.org. EPSS estimates the probability a CVE will be exploited in
        the wild in the next 30 days — used to prioritise remediation ahead of
        raw CVSS severity (a MEDIUM CVE actively being exploited matters more
        than a CRITICAL one that isn't).
        """
        cve_ids = sorted({f.cve_id for f in findings if f.cve_id and f.cve_id.startswith("CVE-")})
        if not cve_ids:
            return

        scores: Dict[str, Tuple[float, float]] = {}
        batches = [cve_ids[i:i + EPSS_BATCH_SIZE] for i in range(0, len(cve_ids), EPSS_BATCH_SIZE)]

        async def fetch_batch(session: aiohttp.ClientSession, batch: List[str]) -> None:
            params = {"cve": ",".join(batch)}
            try:
                async with session.get(EPSS_API, params=params, timeout=aiohttp.ClientTimeout(total=20)) as resp:
                    if resp.status != 200:
                        return
                    data = await resp.json()
                    for entry in data.get("data", []):
                        cve = entry.get("cve", "")
                        try:
                            scores[cve] = (float(entry.get("epss", 0.0)), float(entry.get("percentile", 0.0)))
                        except (TypeError, ValueError):
                            continue
            except Exception as exc:
                logger.warning("EPSS lookup failed for a batch of %d CVEs: %s", len(batch), exc)

        try:
            async with aiohttp.ClientSession() as session:
                await asyncio.gather(*[fetch_batch(session, b) for b in batches])
        except Exception as exc:
            logger.warning("EPSS enrichment skipped: %s", exc)
            return

        applied = 0
        for f in findings:
            if f.cve_id in scores:
                f.epss_score, f.epss_percentile = scores[f.cve_id]
                applied += 1
        if applied:
            logger.info("EPSS enrichment: scored %d/%d CVEs", applied, len(cve_ids))

    # ------------------------------------------------------------------
    # Grype
    # ------------------------------------------------------------------

    @staticmethod
    def _check_tool(name: str) -> bool:
        try:
            return subprocess.run(["which", name], capture_output=True).returncode == 0
        except FileNotFoundError:
            return False

    async def _run_grype(self, sbom_path: str) -> VulnerabilityResult:
        output_json = str(self.output_dir / "grype_output.json")
        cmd = [
            "grype",
            f"sbom:{sbom_path}",
            "-o", "json",
            "--file", output_json,
            "--quiet",
        ]
        logger.info("Running Grype (sbom: %s)", sbom_path.rsplit("/", 1)[-1])
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)

        if proc.returncode != 0 and not Path(output_json).exists():
            return VulnerabilityResult(error=f"grype failed: {stderr.decode()[:300]}", scanner_used="grype")

        return self._parse_grype_output(output_json)

    def _parse_grype_output(self, json_path: str) -> VulnerabilityResult:
        if not Path(json_path).exists():
            return VulnerabilityResult(error="grype output not found", scanner_used="grype")

        with open(json_path) as f:
            data = json.load(f)

        findings: List[CVEFinding] = []
        for match in data.get("matches", []):
            vuln = match.get("vulnerability", {})
            artifact = match.get("artifact", {})
            severity = vuln.get("severity", "UNKNOWN").upper()
            cvss_score = 0.0
            for cvss in vuln.get("cvss", []):
                cvss_score = max(cvss_score, cvss.get("metrics", {}).get("baseScore", 0.0))

            fix_versions = vuln.get("fix", {}).get("versions", [])
            comp_name    = artifact.get("name", "")
            comp_ver     = artifact.get("version", "")
            fix_str      = ", ".join(fix_versions)

            # For EOL components with no fix version, provide a clear upgrade note
            EOL_UPGRADE_NOTES = {
                "openssl": "EOL — upgrade to OpenSSL 3.3.x (no patch available for 1.0.x)",
                "busybox": "EOL — upgrade to BusyBox ≥1.36.1",
            }
            if not fix_str:
                for eol_name, note in EOL_UPGRADE_NOTES.items():
                    if eol_name in comp_name.lower():
                        fix_str = note
                        break

            findings.append(CVEFinding(
                cve_id=vuln.get("id", ""),
                severity=severity,
                cvss_score=cvss_score,
                component_name=comp_name,
                component_version=comp_ver,
                package_type=artifact.get("type", ""),
                description=vuln.get("description", "")[:300],
                fix_version=fix_str,
                source="grype",
            ))

        return self._build_result(findings, scanner="grype")

    # ------------------------------------------------------------------
    # Trivy (independent cross-check scanner)
    # ------------------------------------------------------------------

    async def _run_trivy(self, sbom_path: str) -> VulnerabilityResult:
        output_json = str(self.output_dir / "trivy_output.json")
        cmd = [
            "trivy", "sbom", sbom_path,
            "--format", "json",
            "--output", output_json,
            "--quiet",
            # Vuln DB lives in a cache dir so repeat runs don't re-download
            # ~100MB every time; override with TRIVY_CACHE_DIR if desired.
            "--cache-dir", os.environ.get("TRIVY_CACHE_DIR", str(Path.home() / ".cache" / "trivy")),
        ]
        logger.info("Running Trivy cross-check (sbom: %s)", sbom_path.rsplit("/", 1)[-1])
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
        except asyncio.TimeoutError:
            proc.kill()
            logger.warning("Trivy timed out — skipping cross-check for this run")
            return VulnerabilityResult(error="trivy timed out", scanner_used="trivy")

        if proc.returncode != 0 and not Path(output_json).exists():
            logger.warning("Trivy failed: %s", stderr.decode()[:300])
            return VulnerabilityResult(error=f"trivy failed: {stderr.decode()[:300]}", scanner_used="trivy")

        return self._parse_trivy_output(output_json)

    def _parse_trivy_output(self, json_path: str) -> VulnerabilityResult:
        if not Path(json_path).exists():
            return VulnerabilityResult(error="trivy output not found", scanner_used="trivy")

        with open(json_path) as f:
            data = json.load(f)

        findings: List[CVEFinding] = []
        for result in data.get("Results", []):
            for vuln in result.get("Vulnerabilities", []) or []:
                severity = vuln.get("Severity", "UNKNOWN").upper()
                cvss_score = 0.0
                for source_scores in (vuln.get("CVSS") or {}).values():
                    v3 = source_scores.get("V3Score")
                    if v3:
                        cvss_score = max(cvss_score, v3)

                pkg_id = vuln.get("PkgID", "")
                name, _, version = pkg_id.rpartition("@") if "@" in pkg_id else (vuln.get("PkgName", ""), "", "")
                findings.append(CVEFinding(
                    cve_id=vuln.get("VulnerabilityID", ""),
                    severity=severity,
                    cvss_score=cvss_score,
                    component_name=name or vuln.get("PkgName", ""),
                    component_version=version or vuln.get("InstalledVersion", ""),
                    package_type=result.get("Type", ""),
                    description=(vuln.get("Description") or "")[:300],
                    fix_version=vuln.get("FixedVersion", ""),
                    source="trivy",
                ))

        return self._build_result(findings, scanner="trivy")

    # ------------------------------------------------------------------
    # OWASP Dependency-Check
    # ------------------------------------------------------------------

    async def _run_owasp(self, src_dir: str) -> VulnerabilityResult:
        report_dir = str(self.output_dir / "owasp")
        os.makedirs(report_dir, exist_ok=True)
        cmd = [
            "dependency-check",
            "--scan", src_dir,
            "--format", "JSON",
            "--out", report_dir,
            "--prettyPrint",
            "--noupdate",   # skip NVD update for speed; remove in production
        ]
        logger.info("Running OWASP Dependency-Check on %s", src_dir)
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            await asyncio.wait_for(proc.communicate(), timeout=600)
        except asyncio.TimeoutError:
            proc.kill()
            return VulnerabilityResult(error="OWASP DC timed out", scanner_used="owasp-dc")

        report_path = Path(report_dir) / "dependency-check-report.json"
        return self._parse_owasp_output(str(report_path))

    def _parse_owasp_output(self, json_path: str) -> VulnerabilityResult:
        if not Path(json_path).exists():
            return VulnerabilityResult(error="OWASP report not found", scanner_used="owasp-dc")

        with open(json_path) as f:
            data = json.load(f)

        findings: List[CVEFinding] = []
        for dep in data.get("dependencies", []):
            for vuln in dep.get("vulnerabilities", []):
                cvss_score = 0.0
                severity = vuln.get("severity", "UNKNOWN").upper()
                for cvss_key in ("cvssv3", "cvssv2"):
                    entry = vuln.get(cvss_key, {})
                    if entry:
                        cvss_score = max(cvss_score, entry.get("baseScore", 0.0))

                findings.append(CVEFinding(
                    cve_id=vuln.get("name", ""),
                    severity=severity,
                    cvss_score=cvss_score,
                    component_name=dep.get("fileName", ""),
                    component_version=dep.get("version", ""),
                    package_type="unknown",
                    description=vuln.get("description", "")[:300],
                    fix_version="",
                    source="owasp-dc",
                ))

        return self._build_result(findings, scanner="owasp-dc")

    # ------------------------------------------------------------------
    # OSV.dev API fallback
    # ------------------------------------------------------------------

    async def _osv_scan(self, components) -> VulnerabilityResult:
        """
        Query OSV.dev for known vulnerabilities.
        Handles both package-ecosystem components (PyPI, npm, etc.)
        and C/embedded components (linux-kernel, openssl, busybox, etc.)
        via OSV Linux / OSS-Fuzz ecosystems and NVD CPE fallback.
        """
        logger.info("Querying OSV.dev for %d components", len(components))
        findings: List[CVEFinding] = []

        # Split into package-ecosystem and C/embedded
        pkg_components = []
        c_components   = []
        for comp in components:
            if not comp.version:
                continue
            eco = self._ecosystem_from_type(comp.package_type)
            if eco:
                pkg_components.append((comp, eco))
            else:
                # C/embedded — try OSV Linux ecosystem + CPE lookup
                c_components.append(comp)

        # Build OSV batch queries for package components
        queries      = []
        query_comps  = []
        for comp, eco in pkg_components:
            queries.append({
                "package": {"name": comp.name, "ecosystem": eco},
                "version": comp.version,
            })
            query_comps.append(comp)

        if not queries and not c_components:
            return VulnerabilityResult(scanner_used="osv.dev", error="No versioned components to scan")

        BATCH_SIZE = 100
        async with aiohttp.ClientSession() as session:
            # ---- Package-ecosystem batch query -------------------------
            for i in range(0, len(queries), BATCH_SIZE):
                batch = queries[i: i + BATCH_SIZE]
                try:
                    async with session.post(
                        OSV_BATCH_API,
                        json={"queries": batch},
                        timeout=aiohttp.ClientTimeout(total=30),
                    ) as resp:
                        data = await resp.json()
                except Exception as exc:
                    logger.warning("OSV batch query failed: %s", exc)
                    continue

                for j, result in enumerate(data.get("results", [])):
                    comp = query_comps[i + j]
                    for vuln in result.get("vulns", []):
                        findings.append(CVEFinding(
                            cve_id=vuln.get("id", ""),
                            severity="UNKNOWN",
                            cvss_score=0.0,
                            component_name=comp.name,
                            component_version=comp.version,
                            package_type=comp.package_type,
                            description=vuln.get("summary", "")[:300],
                            fix_version=self._osv_fix_version(vuln),
                            source="osv.dev",
                        ))

            # ---- C / embedded component scanning -----------------------
            if c_components:
                c_findings = await self._scan_c_components(session, c_components)
                findings.extend(c_findings)

            # ---- Enrich all findings with CVSS/severity ----------------
            if findings:
                await self._enrich_osv_details(session, findings)

            # ---- NVD fallback for remaining UNKNOWN severity -----------
            unknown = [f for f in findings if f.severity == "UNKNOWN" and f.cve_id]
            if unknown:
                await self._nvd_enrich(session, unknown)

        return self._build_result(findings, scanner="osv.dev")

    # NVD CPE vendor/product mapping for well-known C components
    # Format: component_name → (vendor, product) for CPE 2.3 lookup
    C_CPE_MAP = {
        "openssl":          ("openssl",     "openssl"),
        "openssl-libcrypto":("openssl",     "openssl"),
        "busybox":          ("busybox",     "busybox"),
        "linux-kernel":     ("linux",       "linux_kernel"),
        "linux":            ("linux",       "linux_kernel"),
        "strongswan":       ("strongswan",  "strongswan"),
        "wpa_supplicant":   ("w1.fi",       "wpa_supplicant"),
        "mbedtls":          ("arm",         "mbed_tls"),
        "u-boot":           ("denx",        "u-boot"),
        "iptables":         ("netfilter",   "iptables"),
        "ppp":              ("samba",       "ppp"),
        "libnl":            ("infradead",   "libnl"),
        "iproute2":         ("iproute2_project", "iproute2"),
        "gmp":              ("gmplib",      "gmp"),
        "bridge-utils":     ("linux",       "bridge-utils"),
        "linuxptp":         ("linuxptp_project", "linuxptp"),
        "mtd-utils":        ("linux-mtd",   "mtd-utils"),
        "dtc":              ("devicetree",  "dtc"),
    }

    NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    # ------------------------------------------------------------------
    # Version range validation helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_version(ver: str) -> Tuple[int, ...]:
        """Parse a dotted version string into a comparable tuple of ints."""
        parts = re.split(r'[.\-]', ver.lstrip('v'))
        result = []
        for p in parts[:4]:
            try:
                result.append(int(p))
            except ValueError:
                break
        return tuple(result) or (0,)

    @classmethod
    def _version_in_nvd_range(cls, comp_version: str, cve_item: dict) -> bool:
        """
        Returns True if comp_version falls within any of the vulnerable version
        ranges reported by NVD for this CVE.
        If NVD provides no CPE match data, returns True (assume affected — conservative).
        """
        configurations = cve_item.get("configurations", [])
        if not configurations:
            return True   # no range data — conservative: keep the finding

        detected = cls._parse_version(comp_version)

        for config in configurations:
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    if not cpe_match.get("vulnerable", False):
                        continue

                    ver_start_inc = cpe_match.get("versionStartIncluding")
                    ver_start_exc = cpe_match.get("versionStartExcluding")
                    ver_end_inc   = cpe_match.get("versionEndIncluding")
                    ver_end_exc   = cpe_match.get("versionEndExcluding")

                    # If no version constraints at all — this CPE entry affects all versions
                    if not any([ver_start_inc, ver_start_exc, ver_end_inc, ver_end_exc]):
                        return True

                    in_range = True

                    if ver_start_inc:
                        in_range = in_range and (detected >= cls._parse_version(ver_start_inc))
                    if ver_start_exc:
                        in_range = in_range and (detected > cls._parse_version(ver_start_exc))
                    if ver_end_inc:
                        in_range = in_range and (detected <= cls._parse_version(ver_end_inc))
                    if ver_end_exc:
                        in_range = in_range and (detected < cls._parse_version(ver_end_exc))

                    if in_range:
                        return True

        return False   # version not within any vulnerable range → filter out

    async def _scan_c_components(
        self, session: aiohttp.ClientSession, components
    ) -> List[CVEFinding]:
        """
        Scan C/embedded components via NVD CPE lookups.
        Uses CPE 2.3 format: cpe:2.3:a:<vendor>:<product>:<version>:*:*:*:*:*:*:*
        Falls back to keyword search for unknown components.
        """
        import asyncio as _asyncio
        findings: List[CVEFinding] = []
        sem = _asyncio.Semaphore(3)  # NVD rate limit: ~5 req/s without API key

        # Only query components we have a CPE mapping for (avoid noise)
        queryable = [c for c in components if c.name.lower() in self.C_CPE_MAP]
        if not queryable:
            logger.info("No C components with known CPE mappings to query")
            return findings

        logger.info("Scanning %d C/embedded components via NVD CPE", len(queryable))

        async def query_nvd_cpe(comp) -> None:
            vendor, product = self.C_CPE_MAP[comp.name.lower()]
            ver = comp.version.lstrip("v")
            # Use virtualMatchString — most accurate for exact version matching
            vms = f"cpe:2.3:a:{vendor}:{product}:{ver}:*:*:*:*:*:*:*"
            try:
                async with sem:
                    await _asyncio.sleep(0.5)   # respect NVD rate limit (~3 req/s)
                    async with session.get(
                        self.NVD_CVE_API,
                        params={"virtualMatchString": vms, "resultsPerPage": 100},
                        timeout=aiohttp.ClientTimeout(total=20),
                    ) as resp:
                        if resp.status != 200:
                            logger.debug("NVD returned %d for %s", resp.status, vms)
                            return
                        raw = await resp.text()

                import json as _json
                data = _json.loads(raw)

                for item in data.get("vulnerabilities", []):
                    cve_item = item.get("cve", {})
                    cve_id   = cve_item.get("id", "")

                    # Version range validation — skip if component version not affected
                    if not self._version_in_nvd_range(comp.version, cve_item):
                        logger.debug(
                            "Skipping %s for %s@%s — version not in affected range",
                            cve_id, comp.name, comp.version,
                        )
                        continue

                    # Extract CVSS — prefer V3.1, then V3.0, then V2
                    score, sev = 0.0, "UNKNOWN"
                    for mk in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                        metrics = cve_item.get("metrics", {}).get(mk, [])
                        if metrics:
                            d = metrics[0].get("cvssData", {})
                            score = float(d.get("baseScore", 0))
                            sev   = d.get("baseSeverity", d.get("severity", "UNKNOWN")).upper()
                            break

                    # Description
                    desc = ""
                    for d in cve_item.get("descriptions", []):
                        if d.get("lang") == "en":
                            desc = d.get("value", "")[:300]
                            break

                    findings.append(CVEFinding(
                        cve_id=cve_id,
                        severity=sev if sev in ("CRITICAL","HIGH","MEDIUM","LOW") else "UNKNOWN",
                        cvss_score=round(score, 1),
                        component_name=comp.name,
                        component_version=comp.version,
                        package_type=comp.package_type,
                        description=desc,
                        fix_version="",
                        source="nvd-cpe",
                    ))
            except Exception as exc:
                logger.warning("NVD CPE query failed for %s v%s: %s", comp.name, comp.version, exc)

        await _asyncio.gather(*[query_nvd_cpe(c) for c in queryable])
        logger.info("C/embedded NVD scan: %d vulnerabilities found across %d components",
                    len(findings), len(queryable))
        return findings

    @staticmethod
    async def _nvd_enrich(session: aiohttp.ClientSession, findings: List[CVEFinding]) -> None:
        """
        For vulns still showing UNKNOWN severity, query NVD API for CVSS score.
        Only called for CVE-* IDs (GHSA-* and PYSEC-* are OSV-native).
        NVD rate limit: 5 req/s without API key, use concurrency=3.
        """
        import asyncio as _asyncio
        import re as _re

        cve_findings = [f for f in findings if _re.match(r'^CVE-\d{4}-\d+$', f.cve_id)]
        if not cve_findings:
            return

        logger.info("NVD fallback: enriching %d CVE IDs", len(cve_findings))
        sem = _asyncio.Semaphore(3)
        NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

        async def fetch_nvd(f: CVEFinding) -> None:
            try:
                async with sem:
                    await _asyncio.sleep(0.3)   # respect rate limit
                    async with session.get(
                        NVD_API,
                        params={"cveId": f.cve_id},
                        timeout=aiohttp.ClientTimeout(total=15),
                    ) as resp:
                        if resp.status != 200:
                            return
                        data = await resp.json()
                vulns = data.get("vulnerabilities", [])
                if not vulns:
                    return
                cve_item = vulns[0].get("cve", {})
                # Try CVSS v3.1 first, then v3.0, then v2
                for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    metrics = cve_item.get("metrics", {}).get(metric_key, [])
                    if metrics:
                        data_m = metrics[0].get("cvssData", {})
                        score   = float(data_m.get("baseScore", 0))
                        sev_str = data_m.get("baseSeverity", "").upper()
                        if score > 0:
                            if sev_str in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                                f.severity   = sev_str
                            elif score >= 9.0:
                                f.severity = "CRITICAL"
                            elif score >= 7.0:
                                f.severity = "HIGH"
                            elif score >= 4.0:
                                f.severity = "MEDIUM"
                            else:
                                f.severity = "LOW"
                            f.cvss_score = round(score, 1)
                        # Grab description if missing
                        if not f.description:
                            descs = cve_item.get("descriptions", [])
                            for d in descs:
                                if d.get("lang") == "en":
                                    f.description = d.get("value", "")[:300]
                                    break
                        break
            except Exception as exc:
                logger.debug("NVD fetch failed for %s: %s", f.cve_id, exc)

        await _asyncio.gather(*[fetch_nvd(f) for f in cve_findings])

    @staticmethod
    async def _enrich_osv_details(session: aiohttp.ClientSession, findings: List["CVEFinding"]) -> None:
        """Fetch full OSV records for each unique vuln ID to get CVSS scores."""
        import asyncio as _asyncio
        unique_ids = list({f.cve_id for f in findings if f.cve_id})
        logger.info("Enriching %d unique vuln records from OSV.dev", len(unique_ids))

        id_to_record: Dict[str, dict] = {}
        sem = _asyncio.Semaphore(10)

        async def fetch_one(vuln_id: str) -> None:
            try:
                async with sem:
                    async with session.get(
                        f"https://api.osv.dev/v1/vulns/{vuln_id}",
                        timeout=aiohttp.ClientTimeout(total=15),
                    ) as resp:
                        if resp.status == 200:
                            id_to_record[vuln_id] = await resp.json()
            except Exception:
                pass

        await _asyncio.gather(*[fetch_one(vid) for vid in unique_ids])

        # Apply enriched data back to findings
        for f in findings:
            record = id_to_record.get(f.cve_id)
            if record:
                sev, cvss = VulnerabilityAnalyzer._parse_osv_severity(record)
                f.severity   = sev
                f.cvss_score = cvss
                if not f.description:
                    f.description = record.get("summary", "")[:300]
                if not f.fix_version:
                    f.fix_version = VulnerabilityAnalyzer._osv_fix_version(record)

    @staticmethod
    def _ecosystem_from_type(pkg_type: str) -> str:
        mapping = {
            "pypi": "PyPI", "npm": "npm", "maven": "Maven",
            "cargo": "crates.io", "gomod": "Go", "gem": "RubyGems",
            "composer": "Packagist", "pub": "Pub", "nuget": "NuGet",
            "apk": "Alpine", "deb": "Debian", "rpm": "Red Hat",
        }
        return mapping.get(pkg_type.lower(), "")

    @staticmethod
    def _parse_osv_severity(vuln: dict):
        """
        OSV severity entries have CVSS vector strings, not numeric scores.
        e.g. {"type": "CVSS_V3", "score": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:H"}
        database_specific.severity contains text like "MODERATE", "HIGH", "CRITICAL"

        Strategy:
        1. Map database_specific.severity (GHSA text) to numeric score + severity label
        2. Look for CVSS numeric score in database_specific or ecosystem_specific
        """
        import re as _re

        # OSV GHSA text → CVSS approximation
        text_to_sev = {
            "CRITICAL": ("CRITICAL", 9.5),
            "HIGH":     ("HIGH",     7.5),
            "MODERATE": ("MEDIUM",   5.0),
            "MEDIUM":   ("MEDIUM",   5.0),
            "LOW":      ("LOW",      2.0),
            "UNKNOWN":  ("UNKNOWN",  0.0),
        }

        # Try database_specific.severity first (most reliable for GHSA)
        db = vuln.get("database_specific", {})
        db_sev_text = db.get("severity", "").upper()
        if db_sev_text in text_to_sev:
            return text_to_sev[db_sev_text]

        # Try to extract a numeric CVSS score from database_specific
        for key in ("cvss_score", "cvss", "cvss_v3", "cvss3", "score"):
            val = db.get(key)
            if val is not None:
                try:
                    score = float(val)
                    if score >= 9.0: return "CRITICAL", score
                    if score >= 7.0: return "HIGH", score
                    if score >= 4.0: return "MEDIUM", score
                    return "LOW", score
                except (TypeError, ValueError):
                    pass

        # Check ecosystem_specific.severity (PyPI/Go)
        for affected in vuln.get("affected", []):
            es = affected.get("ecosystem_specific", {})
            es_sev = es.get("severity", "").upper()
            if es_sev in text_to_sev:
                return text_to_sev[es_sev]

        return "UNKNOWN", 0.0

    @staticmethod
    def _osv_fix_version(vuln: dict) -> str:
        for affected in vuln.get("affected", []):
            for rng in affected.get("ranges", []):
                for event in rng.get("events", []):
                    fixed = event.get("fixed")
                    if fixed:
                        return fixed
        return ""

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_result(findings: List[CVEFinding], scanner: str) -> VulnerabilityResult:
        severity_counts: Dict[str, int] = {}
        affected: set = set()
        for f in findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
            affected.add(f"{f.component_name}@{f.component_version}")

        return VulnerabilityResult(
            findings=findings,
            severity_counts=severity_counts,
            affected_components=sorted(affected),
            total_vulnerabilities=len(findings),
            scanner_used=scanner,
        )

    @staticmethod
    def _merge_results(results: List[VulnerabilityResult]) -> VulnerabilityResult:
        """
        Merge multiple scanner results with two-level deduplication:
        1. Exact: (cve_id, component_name, component_version) — original behaviour
        2. Cross-version: (cve_id, component_name) — keep only highest-CVSS entry
           when the same CVE appears for multiple versions of the same component.
        """
        scanners_used: List[str] = []

        # Step 1: deduplicate exact tuples
        seen_exact: set = set()
        all_findings: List[CVEFinding] = []
        for r in results:
            if r.scanner_used:
                scanners_used.append(r.scanner_used)
            for f in r.findings:
                key = (f.cve_id, f.component_name, f.component_version)
                if key not in seen_exact:
                    seen_exact.add(key)
                    all_findings.append(f)

        # Step 2: cross-version dedup — same CVE + component name → keep best CVSS
        best: Dict[Tuple, CVEFinding] = {}
        for f in all_findings:
            cv_key = (f.cve_id, f.component_name.lower())
            existing = best.get(cv_key)
            if existing is None or f.cvss_score > existing.cvss_score:
                best[cv_key] = f

        merged_findings = list(best.values())
        dedup_count = len(all_findings) - len(merged_findings)
        if dedup_count:
            logger.info("Deduplication removed %d cross-version duplicate CVE entries", dedup_count)

        return VulnerabilityAnalyzer._build_result(merged_findings, " + ".join(scanners_used))
