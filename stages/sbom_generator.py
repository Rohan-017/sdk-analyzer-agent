"""
Stage 2: SBOM Generation using Syft
Produces SPDX and CycloneDX SBOM files.
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
# Data model
# ---------------------------------------------------------------------------

@dataclass
class SBOMComponent:
    name: str
    version: str
    package_type: str          # npm, pypi, maven, gem, cargo, apk, deb, rpm …
    licenses: List[str] = field(default_factory=list)
    purl: str = ""             # Package URL (purl spec)
    cpe: str = ""              # CPE 2.3 identifier
    location: str = ""         # path inside source tree
    is_direct: bool = True     # True = declared directly by the project manifest
    depth: int = 0             # 0 = direct dependency, 1+ = transitive depth


@dataclass
class SBOMResult:
    spdx_path: str
    cyclonedx_path: str
    components: List[SBOMComponent] = field(default_factory=list)
    total_components: int = 0
    license_summary: Dict[str, int] = field(default_factory=dict)
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Stage implementation
# ---------------------------------------------------------------------------

class SBOMGeneratorStage:
    """
    Wraps the `syft` CLI to generate SBOM files.
    Falls back to a lightweight Python-based scanner when syft is absent.
    """

    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._syft_available = self._check_syft()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def run(self, src_dir: str, license_distribution: Optional[Dict[str, int]] = None) -> SBOMResult:
        spdx_path = str(self.output_dir / "sbom.spdx.json")
        cdx_path  = str(self.output_dir / "sbom.cyclonedx.json")

        if self._syft_available:
            logger.info("Running Syft SBOM generation (src: %s)", src_dir.rsplit("/", 1)[-1])
            await self._run_syft(src_dir, "spdx-json",      spdx_path)
            await self._run_syft(src_dir, "cyclonedx-json", cdx_path)
            components = self._parse_cyclonedx(cdx_path)
            components = self._apply_dependency_graph(cdx_path, components)
            # Also run Python fallback C/embedded scan and merge — Syft misses vendored C libs
            c_components = self._c_component_scan(src_dir)
            if c_components:
                # Deduplicate against Syft results by (name, version)
                existing = {(c.name.lower(), c.version) for c in components}
                new_c = [c for c in c_components if (c.name.lower(), c.version) not in existing]
                logger.info("Merged %d additional C/embedded components from fallback scan", len(new_c))
                components.extend(new_c)
            # Deduplicate full list
            seen: set = set()
            deduped = []
            for c in components:
                key = (c.name.lower(), c.version or "")
                if key not in seen:
                    seen.add(key)
                    deduped.append(c)
            components = deduped
        else:
            logger.warning("syft not found — using fallback Python SBOM scanner")
            components = self._fallback_scan(src_dir)
            # Enrich PyPI component licenses via PyPI JSON API
            components = await self._enrich_pypi_licenses(components)
            self._write_fallback_spdx(components, spdx_path)
            self._write_fallback_cyclonedx(components, cdx_path)

        # Enrich components with license data from the regex license scanner
        if license_distribution:
            components = self._enrich_licenses_from_scan(components, license_distribution)

        license_summary: Dict[str, int] = {}
        for comp in components:
            for lic in comp.licenses:
                license_summary[lic] = license_summary.get(lic, 0) + 1

        result = SBOMResult(
            spdx_path=spdx_path,
            cyclonedx_path=cdx_path,
            components=components,
            total_components=len(components),
            license_summary=license_summary,
        )
        logger.info("SBOM generation complete: %d components", result.total_components)
        return result

    @staticmethod
    def _enrich_licenses_from_scan(
        components: List["SBOMComponent"],
        license_distribution: Dict[str, int],
    ) -> List["SBOMComponent"]:
        """
        For components whose licenses are empty or NOASSERTION/UNKNOWN,
        try to infer a license from the regex scan distribution using the component name.
        This is a best-effort heuristic: it assigns the most common license found in the
        scan to components whose names suggest a well-known package with a known license.
        """
        # Well-known component → expected SPDX license mapping
        KNOWN_LICENSES: Dict[str, str] = {
            "linux-kernel": "GPL-2.0-only",
            "linux":        "GPL-2.0-only",
            "busybox":      "GPL-2.0-only",
            "u-boot":       "GPL-2.0-or-later",
            "uboot":        "GPL-2.0-or-later",
            "openssl":      "Apache-2.0",
            "strongswan":   "GPL-2.0-or-later",
            "wpa_supplicant": "BSD-3-Clause",
            "mbedtls":      "Apache-2.0",
            "mbed-tls":     "Apache-2.0",
            "iptables":     "GPL-2.0-only",
            "iproute2":     "GPL-2.0-only",
            "ppp":          "BSD-3-Clause",
            "optee":        "BSD-2-Clause",
            "op-tee":       "BSD-2-Clause",
            "arm-trusted-firmware": "BSD-3-Clause",
            "atf":          "BSD-3-Clause",
            "gmp":          "LGPL-3.0-or-later",
            "zlib":         "Zlib",
            "libpng":       "Libpng",
            "curl":         "MIT",
            "sqlite":       "Unlicense",
            "expat":        "MIT",
            "libtomcrypt":  "Unlicense",
            "libtommath":   "Unlicense",
        }
        enriched = 0
        for comp in components:
            if comp.licenses and comp.licenses != ["NOASSERTION"] and comp.licenses != ["UNKNOWN"]:
                continue
            name_lower = comp.name.lower()
            for key, lic in KNOWN_LICENSES.items():
                if key in name_lower:
                    comp.licenses = [lic]
                    enriched += 1
                    break
        if enriched:
            logger.info("License enrichment: assigned known licenses to %d SBOM components", enriched)
        return components

    # ------------------------------------------------------------------
    # Syft helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _check_syft() -> bool:
        try:
            return subprocess.run(["which", "syft"], capture_output=True).returncode == 0
        except FileNotFoundError:
            return False

    @staticmethod
    async def _run_syft(src_dir: str, output_format: str, output_path: str) -> None:
        cmd = ["syft", src_dir, "-o", f"{output_format}={output_path}", "--quiet"]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode != 0:
            logger.error("syft failed: %s", stderr.decode())
        else:
            logger.info("syft wrote %s → %s", output_format, output_path)

    @staticmethod
    def _parse_cyclonedx(cdx_path: str) -> List[SBOMComponent]:
        components: List[SBOMComponent] = []
        if not Path(cdx_path).exists():
            return components
        with open(cdx_path) as f:
            data = json.load(f)

        for comp in data.get("components", []):
            licenses = []
            for lic_entry in comp.get("licenses", []):
                lic = lic_entry.get("license", {})
                lic_id = lic.get("id") or lic.get("name", "UNKNOWN")
                licenses.append(lic_id)

            components.append(SBOMComponent(
                name=comp.get("name", ""),
                version=comp.get("version", ""),
                package_type=comp.get("type", "library"),
                licenses=licenses,
                purl=comp.get("purl", ""),
                cpe=next((e.get("cpe", "") for e in comp.get("externalReferences", []) if "cpe" in e.get("type", "")), ""),
                location=comp.get("evidence", {}).get("occurrences", [{}])[0].get("location", "") if comp.get("evidence") else "",
            ))
        return components

    @staticmethod
    def _apply_dependency_graph(cdx_path: str, components: List["SBOMComponent"]) -> List["SBOMComponent"]:
        """
        Walk the CycloneDX "dependencies" graph (built by Syft from lockfiles
        such as package-lock.json / poetry.lock / go.sum / Gemfile.lock) to
        mark each component as direct (depth 0, declared by the project
        manifest) or transitive (depth 1+, pulled in by another dependency).
        This is what lets the report distinguish "you added this" from
        "something you added, added this".
        """
        if not Path(cdx_path).exists():
            return components
        try:
            with open(cdx_path) as f:
                data = json.load(f)
        except Exception:
            return components

        # bom-ref -> (name, version)
        ref_to_key: Dict[str, tuple] = {}
        for comp in data.get("components", []):
            ref = comp.get("bom-ref")
            if ref:
                ref_to_key[ref] = (comp.get("name", "").lower(), comp.get("version", ""))

        root_ref = data.get("metadata", {}).get("component", {}).get("bom-ref")
        dep_edges: Dict[str, List[str]] = {
            d.get("ref"): d.get("dependsOn", []) for d in data.get("dependencies", [])
        }
        if not dep_edges:
            # No dependency graph available (e.g. syft ran without lockfiles) —
            # nothing to distinguish, leave every component as direct/depth 0.
            return components

        # The graph "root" isn't always the synthetic metadata.component ref —
        # for ecosystems like npm, Syft anchors the graph on the project's own
        # package node instead (e.g. a "mini@1.0.0" component matching the
        # scanned directory). Treat every zero-indegree node (nothing depends
        # on it) as a root of "the project", seeded at depth -1 so its direct
        # dependencies land at depth 0 regardless of which root shape Syft used.
        all_targets = {t for deps in dep_edges.values() for t in deps}
        roots = [r for r in dep_edges if r not in all_targets]
        if root_ref and root_ref in dep_edges and root_ref not in roots:
            roots.append(root_ref)

        depth_by_ref: Dict[str, int] = {r: -1 for r in roots}
        frontier = list(roots)
        while frontier:
            next_frontier = []
            for ref in frontier:
                for dep_ref in dep_edges.get(ref, []):
                    new_depth = depth_by_ref[ref] + 1
                    if dep_ref not in depth_by_ref or new_depth < depth_by_ref[dep_ref]:
                        depth_by_ref[dep_ref] = new_depth
                        next_frontier.append(dep_ref)
            frontier = next_frontier

        key_to_depth: Dict[tuple, int] = {}
        for ref, depth in depth_by_ref.items():
            key = ref_to_key.get(ref)
            if key:
                adjusted = max(depth, 0)
                if key not in key_to_depth or adjusted < key_to_depth[key]:
                    key_to_depth[key] = adjusted

        for comp in components:
            key = (comp.name.lower(), comp.version)
            if key in key_to_depth:
                comp.depth = key_to_depth[key]
                comp.is_direct = comp.depth == 0
        return components

    # ------------------------------------------------------------------
    # PyPI license enrichment
    # ------------------------------------------------------------------

    @staticmethod
    async def _enrich_pypi_licenses(components: List["SBOMComponent"]) -> List["SBOMComponent"]:
        """
        For PyPI components without licenses, query PyPI JSON API to fetch
        the license metadata.  Runs batch of coroutines concurrently (max 20 at a time).
        """
        import aiohttp
        import asyncio

        pypi_comps = [c for c in components if c.package_type == "pypi" and not c.licenses and c.version]
        if not pypi_comps:
            return components

        logger.info("Enriching licenses for %d PyPI components via PyPI API", len(pypi_comps))
        sem = asyncio.Semaphore(10)

        async def fetch_license(session: aiohttp.ClientSession, comp) -> None:
            url = f"https://pypi.org/pypi/{comp.name}/{comp.version}/json"
            try:
                async with sem:
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            lic = data.get("info", {}).get("license", "")
                            if lic and lic not in ("UNKNOWN", "None", "", None):
                                comp.licenses = [lic]
            except Exception:
                pass

        async with aiohttp.ClientSession() as session:
            await asyncio.gather(*[fetch_license(session, c) for c in pypi_comps])

        return components

    # ------------------------------------------------------------------
    # Fallback scanner (no syft)
    # ------------------------------------------------------------------

    MANIFEST_PARSERS = {
        "requirements.txt": "_parse_pip_requirements",
        "package.json":     "_parse_npm_package",
        "pom.xml":          "_parse_maven_pom",
        "Cargo.toml":       "_parse_cargo_toml",
        "go.mod":           "_parse_go_mod",
        "Gemfile":          "_parse_gemfile",
        "composer.json":    "_parse_composer",
        "pubspec.yaml":     "_parse_pubspec",
        "build.gradle":     "_parse_gradle",
    }

    # Lockfiles list the *fully resolved* dependency set (direct + transitive).
    # Parsed in a second pass so anything not already declared by a manifest
    # above is flagged as a transitive dependency.
    LOCKFILE_PARSERS = {
        "package-lock.json": "_parse_npm_lockfile",
        "yarn.lock":         "_parse_yarn_lock",
        "poetry.lock":       "_parse_poetry_lock",
        "Pipfile.lock":      "_parse_pipfile_lock",
        "Gemfile.lock":      "_parse_gemfile_lock",
        "Cargo.lock":        "_parse_cargo_lock",
        "go.sum":            "_parse_go_sum",
    }

    def _fallback_scan(self, src_dir: str) -> List[SBOMComponent]:
        direct_components: List[SBOMComponent] = []
        lockfile_components: List[SBOMComponent] = []

        for root, _dirs, files in os.walk(src_dir):
            for fname in files:
                parser_name = self.MANIFEST_PARSERS.get(fname)
                if parser_name:
                    fpath = os.path.join(root, fname)
                    parser = getattr(self, parser_name, None)
                    if parser:
                        try:
                            direct_components.extend(parser(fpath))
                        except Exception as exc:
                            logger.warning("Parser %s failed on %s: %s", parser_name, fpath, exc)

                lock_parser_name = self.LOCKFILE_PARSERS.get(fname)
                if lock_parser_name:
                    fpath = os.path.join(root, fname)
                    lock_parser = getattr(self, lock_parser_name, None)
                    if lock_parser:
                        try:
                            lockfile_components.extend(lock_parser(fpath))
                        except Exception as exc:
                            logger.warning("Lockfile parser %s failed on %s: %s", lock_parser_name, fpath, exc)

        direct_keys = {(c.name.lower(), c.version) for c in direct_components}
        direct_names = {c.name.lower() for c in direct_components}
        transitive_count = 0
        components = list(direct_components)
        for c in lockfile_components:
            key = (c.name.lower(), c.version)
            if key in direct_keys:
                continue
            # A lockfile entry only counts as "direct" if its package name was
            # already declared in a manifest (package.json/requirements.txt/etc).
            c.is_direct = c.name.lower() in direct_names
            c.depth = 0 if c.is_direct else 1
            if not c.is_direct:
                transitive_count += 1
            components.append(c)

        if transitive_count:
            logger.info("Lockfile scan found %d additional transitive dependencies", transitive_count)

        # Also scan for embedded C/C++ components (kernel, busybox, openssl, etc.)
        c_components = self._c_component_scan(src_dir)
        if c_components:
            logger.info("C/embedded component scan found %d additional components", len(c_components))
            components.extend(c_components)

        # Deduplicate by (name, version)
        seen = set()
        deduped = []
        for c in components:
            key = (c.name.lower(), c.version)
            if key not in seen:
                seen.add(key)
                deduped.append(c)
        return deduped

    # ------------------------------------------------------------------
    # C / Embedded component detection
    # ------------------------------------------------------------------

    @staticmethod
    def _c_component_scan(src_dir: str) -> List["SBOMComponent"]:
        """
        Detect vendored/bundled C components that have no standard manifest.
        Strategies (in order):
          1. Versioned directory names  e.g. openssl-1.0.1p/
          2. Linux kernel Makefile      VERSION/PATCHLEVEL/SUBLEVEL
          3. configure.ac AC_INIT()     autoconf packages
          4. pkg-config .pc files       installed library metadata
          5. CMakeLists.txt project()   cmake projects
        """
        import re
        root = Path(src_dir)
        components: List[SBOMComponent] = []
        seen: set = set()

        def _add(name: str, version: str, pkg_type: str, location: str) -> None:
            key = (name.lower(), version)
            if key not in seen and name:
                seen.add(key)
                components.append(SBOMComponent(
                    name=name, version=version,
                    package_type=pkg_type, location=location,
                ))

        # ---- Strategy 1: versioned directory names ----------------------
        # Matches: openssl-1.0.1p  busybox-1.26.2  strongswan-5.9.11
        ver_dir_re = re.compile(
            r'^(?P<name>[a-zA-Z][a-zA-Z0-9_\-\.]+?)[-_]v?'
            r'(?P<ver>\d+[\.\d]*[a-z]?)$', re.IGNORECASE
        )
        for d in root.rglob('*'):
            if not d.is_dir():
                continue
            m = ver_dir_re.match(d.name)
            if m:
                name = m.group('name').lower()
                ver  = m.group('ver')
                # Skip obvious non-component dirs
                if name in {'build', 'test', 'tests', 'src', 'lib',
                            'include', 'doc', 'docs', 'example', 'examples',
                            'scripts', 'tools', 'arch', 'kernel'}:
                    continue
                if len(name) < 3:
                    continue
                _add(name, ver, 'c-embedded', str(d.relative_to(root)))

        # ---- Strategy 2: Linux kernel Makefile --------------------------
        for makefile in root.rglob('Makefile'):
            try:
                text = makefile.read_text(errors='ignore')
            except OSError:
                continue
            ver_re = re.compile(
                r'^VERSION\s*=\s*(\d+).*\n'
                r'PATCHLEVEL\s*=\s*(\d+).*\n'
                r'SUBLEVEL\s*=\s*(\d+)',
                re.MULTILINE
            )
            m = ver_re.search(text)
            if m and 'linux' in text.lower()[:500]:
                ver = f"{m.group(1)}.{m.group(2)}.{m.group(3)}"
                _add('linux-kernel', ver, 'kernel',
                     str(makefile.parent.relative_to(root)))
                break   # Only first kernel found

        # ---- Strategy 3: configure.ac / configure.in (autoconf) ---------
        for conf_ac in root.rglob('configure.ac'):
            try:
                text = conf_ac.read_text(errors='ignore')
            except OSError:
                continue
            # AC_INIT([name], [version], ...)  or  AC_INIT(name, version)
            ac_re = re.compile(
                r'AC_INIT\s*\(\s*[\[\(]?([^\],\)\[]+)[\]\)]?\s*,'
                r'\s*[\[\(]?([^\],\)\[]+)[\]\)]?',
                re.IGNORECASE
            )
            m = ac_re.search(text)
            if m:
                name = m.group(1).strip().strip('"\'').lower()
                ver  = m.group(2).strip().strip('"\'')
                if name and ver and not ver.startswith('$'):
                    _add(name, ver, 'autoconf',
                         str(conf_ac.parent.relative_to(root)))

        # ---- Strategy 4: pkg-config .pc files ---------------------------
        for pc_file in root.rglob('*.pc'):
            try:
                text = pc_file.read_text(errors='ignore')
            except OSError:
                continue
            name_m = re.search(r'^Name:\s*(.+)$', text, re.MULTILINE | re.IGNORECASE)
            ver_m  = re.search(r'^Version:\s*(.+)$', text, re.MULTILINE | re.IGNORECASE)
            if name_m and ver_m:
                name = name_m.group(1).strip().lower()
                ver  = ver_m.group(1).strip()
                if name and ver:
                    _add(name, ver, 'pkg-config',
                         str(pc_file.relative_to(root)))

        # ---- Strategy 5: CMakeLists.txt project() -----------------------
        for cmake in root.rglob('CMakeLists.txt'):
            # Only top-level or near-top-level CMakeLists
            depth = len(cmake.relative_to(root).parts)
            if depth > 4:
                continue
            try:
                text = cmake.read_text(errors='ignore')
            except OSError:
                continue
            proj_re = re.compile(
                r'project\s*\(\s*([^\s\)]+).*?VERSION\s+([\d\.]+)',
                re.IGNORECASE | re.DOTALL
            )
            m = proj_re.search(text)
            if m:
                name = m.group(1).strip().lower()
                ver  = m.group(2).strip()
                _add(name, ver, 'cmake',
                     str(cmake.parent.relative_to(root)))

        logger.info(
            "C/embedded component scan: %d components found "
            "(versioned-dirs + kernel + autoconf + pkg-config + cmake)",
            len(components)
        )
        return components

    @staticmethod
    def _parse_pip_requirements(path: str) -> List[SBOMComponent]:
        comps = []
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("-"):
                    continue
                if "==" in line:
                    name, version = line.split("==", 1)
                    version = version.split(";")[0].strip()
                elif ">=" in line:
                    name, version = line.split(">=", 1)
                    version = f">={version.strip()}"
                else:
                    name, version = line, ""
                comps.append(SBOMComponent(name=name.strip(), version=version, package_type="pypi"))
        return comps

    @staticmethod
    def _parse_npm_package(path: str) -> List[SBOMComponent]:
        comps = []
        try:
            with open(path) as f:
                data = json.load(f)
            for section in ("dependencies", "devDependencies", "peerDependencies"):
                for name, ver in data.get(section, {}).items():
                    comps.append(SBOMComponent(name=name, version=ver, package_type="npm"))
        except Exception:
            pass
        return comps

    @staticmethod
    def _parse_cargo_toml(path: str) -> List[SBOMComponent]:
        comps = []
        try:
            import re
            with open(path) as f:
                content = f.read()
            pattern = re.compile(r'(\w[\w\-_]+)\s*=\s*["\{]([0-9][^\s"}\,]+)', re.MULTILINE)
            for match in pattern.finditer(content):
                comps.append(SBOMComponent(name=match.group(1), version=match.group(2), package_type="cargo"))
        except Exception:
            pass
        return comps

    @staticmethod
    def _parse_go_mod(path: str) -> List[SBOMComponent]:
        comps = []
        with open(path) as f:
            in_require = False
            for line in f:
                line = line.strip()
                if line.startswith("require ("):
                    in_require = True
                    continue
                if in_require:
                    if line == ")":
                        in_require = False
                        continue
                    parts = line.split()
                    if len(parts) >= 2:
                        comps.append(SBOMComponent(name=parts[0], version=parts[1], package_type="gomod"))
                elif line.startswith("require "):
                    parts = line.split()
                    if len(parts) >= 3:
                        comps.append(SBOMComponent(name=parts[1], version=parts[2], package_type="gomod"))
        return comps

    @staticmethod
    def _parse_maven_pom(path: str) -> List[SBOMComponent]:
        comps = []
        try:
            import xml.etree.ElementTree as ET
            tree = ET.parse(path)
            root = tree.getroot()
            ns = {"m": "http://maven.apache.org/POM/4.0.0"}
            for dep in root.findall(".//m:dependency", ns):
                group_id   = (dep.find("m:groupId",    ns)    or dep.find("groupId"))
                artifact_id= (dep.find("m:artifactId", ns)    or dep.find("artifactId"))
                version_el = (dep.find("m:version",    ns)    or dep.find("version"))
                if group_id is not None and artifact_id is not None:
                    name    = f"{group_id.text}:{artifact_id.text}"
                    version = version_el.text if version_el is not None else ""
                    comps.append(SBOMComponent(name=name, version=version, package_type="maven"))
        except Exception:
            pass
        return comps

    @staticmethod
    def _parse_gemfile(path: str) -> List[SBOMComponent]:
        import re
        comps = []
        with open(path) as f:
            for line in f:
                m = re.match(r"\s*gem\s+['\"]([^'\"]+)['\"](?:,\s*['\"]([^'\"]+)['\"])?", line)
                if m:
                    comps.append(SBOMComponent(name=m.group(1), version=m.group(2) or "", package_type="gem"))
        return comps

    @staticmethod
    def _parse_composer(path: str) -> List[SBOMComponent]:
        comps = []
        try:
            with open(path) as f:
                data = json.load(f)
            for name, ver in {**data.get("require", {}), **data.get("require-dev", {})}.items():
                comps.append(SBOMComponent(name=name, version=ver, package_type="composer"))
        except Exception:
            pass
        return comps

    @staticmethod
    def _parse_pubspec(path: str) -> List[SBOMComponent]:
        comps = []
        try:
            import re
            with open(path) as f:
                content = f.read()
            in_deps = False
            for line in content.splitlines():
                if re.match(r"^dependencies\s*:", line):
                    in_deps = True
                    continue
                if in_deps:
                    m = re.match(r"^\s{2}(\w[\w_]+):\s*(.+)?$", line)
                    if m:
                        comps.append(SBOMComponent(name=m.group(1), version=(m.group(2) or "").strip(), package_type="pub"))
                    elif line and not line.startswith(" "):
                        in_deps = False
        except Exception:
            pass
        return comps

    @staticmethod
    def _parse_gradle(path: str) -> List[SBOMComponent]:
        import re
        comps = []
        pattern = re.compile(r"""(?:implementation|api|compile|testImplementation)\s+['"]([^'"]+)['"]""")
        with open(path) as f:
            for line in f:
                m = pattern.search(line)
                if m:
                    parts = m.group(1).split(":")
                    name    = ":".join(parts[:2]) if len(parts) >= 2 else parts[0]
                    version = parts[2] if len(parts) >= 3 else ""
                    comps.append(SBOMComponent(name=name, version=version, package_type="gradle"))
        return comps

    # ------------------------------------------------------------------
    # Lockfile parsers (resolved dependency tree — direct + transitive)
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_npm_lockfile(path: str) -> List[SBOMComponent]:
        comps = []
        try:
            with open(path) as f:
                data = json.load(f)
            # npm v2/v3 lockfile format: "packages" keyed by node_modules path
            packages = data.get("packages")
            if isinstance(packages, dict):
                for pkg_path, info in packages.items():
                    if not pkg_path or not isinstance(info, dict):
                        continue
                    name = info.get("name") or pkg_path.rsplit("node_modules/", 1)[-1]
                    version = info.get("version", "")
                    if name and version:
                        comps.append(SBOMComponent(name=name, version=version, package_type="npm"))
            else:
                # npm v1 lockfile format: "dependencies" nested tree
                def walk(deps: dict) -> None:
                    for name, info in deps.items():
                        version = info.get("version", "")
                        if name and version:
                            comps.append(SBOMComponent(name=name, version=version, package_type="npm"))
                        if isinstance(info.get("dependencies"), dict):
                            walk(info["dependencies"])
                walk(data.get("dependencies", {}))
        except Exception:
            pass
        return comps

    @staticmethod
    def _parse_yarn_lock(path: str) -> List[SBOMComponent]:
        import re
        comps = []
        try:
            with open(path, errors="ignore") as f:
                content = f.read()
            # Each entry: "pkg-name@^1.2.3":\n  version "1.2.5"
            for block in content.split("\n\n"):
                name_m = re.match(r'^"?([^@"\s]+)@', block.strip())
                ver_m = re.search(r'^\s*version\s+"([^"]+)"', block, re.MULTILINE)
                if name_m and ver_m:
                    comps.append(SBOMComponent(name=name_m.group(1), version=ver_m.group(1), package_type="npm"))
        except Exception:
            pass
        return comps

    @staticmethod
    def _parse_poetry_lock(path: str) -> List[SBOMComponent]:
        import re
        comps = []
        try:
            with open(path, errors="ignore") as f:
                content = f.read()
            for block in content.split("[[package]]"):
                name_m = re.search(r'^name\s*=\s*"([^"]+)"', block, re.MULTILINE)
                ver_m = re.search(r'^version\s*=\s*"([^"]+)"', block, re.MULTILINE)
                if name_m and ver_m:
                    comps.append(SBOMComponent(name=name_m.group(1), version=ver_m.group(1), package_type="pypi"))
        except Exception:
            pass
        return comps

    @staticmethod
    def _parse_pipfile_lock(path: str) -> List[SBOMComponent]:
        comps = []
        try:
            with open(path) as f:
                data = json.load(f)
            for section in ("default", "develop"):
                for name, info in data.get(section, {}).items():
                    version = str(info.get("version", "")).lstrip("=")
                    if name:
                        comps.append(SBOMComponent(name=name, version=version, package_type="pypi"))
        except Exception:
            pass
        return comps

    @staticmethod
    def _parse_gemfile_lock(path: str) -> List[SBOMComponent]:
        import re
        comps = []
        try:
            with open(path, errors="ignore") as f:
                for line in f:
                    m = re.match(r"^\s{4}([a-zA-Z0-9_\-]+)\s*\(([^)]+)\)", line)
                    if m:
                        comps.append(SBOMComponent(name=m.group(1), version=m.group(2), package_type="gem"))
        except Exception:
            pass
        return comps

    @staticmethod
    def _parse_cargo_lock(path: str) -> List[SBOMComponent]:
        import re
        comps = []
        try:
            with open(path, errors="ignore") as f:
                content = f.read()
            for block in content.split("[[package]]"):
                name_m = re.search(r'^name\s*=\s*"([^"]+)"', block, re.MULTILINE)
                ver_m = re.search(r'^version\s*=\s*"([^"]+)"', block, re.MULTILINE)
                if name_m and ver_m:
                    comps.append(SBOMComponent(name=name_m.group(1), version=ver_m.group(1), package_type="cargo"))
        except Exception:
            pass
        return comps

    @staticmethod
    def _parse_go_sum(path: str) -> List[SBOMComponent]:
        comps = []
        try:
            seen = set()
            with open(path, errors="ignore") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 2:
                        name, version = parts[0], parts[1].split("/")[0]
                        if (name, version) not in seen:
                            seen.add((name, version))
                            comps.append(SBOMComponent(name=name, version=version, package_type="gomod"))
        except Exception:
            pass
        return comps

    # ------------------------------------------------------------------
    # Fallback writers
    # ------------------------------------------------------------------

    @staticmethod
    def _write_fallback_spdx(components: List[SBOMComponent], path: str) -> None:
        import datetime
        doc = {
            "SPDXID": "SPDXRef-DOCUMENT",
            "spdxVersion": "SPDX-2.3",
            "creationInfo": {
                "created": datetime.datetime.utcnow().isoformat() + "Z",
                "creators": ["Tool: sdk-analyzer-agent-fallback"],
            },
            "name": "SDK-SBOM",
            "dataLicense": "CC0-1.0",
            "documentNamespace": "https://sdk-analyzer/sbom",
            "packages": [
                {
                    "SPDXID": f"SPDXRef-{i}",
                    "name": c.name,
                    "versionInfo": c.version,
                    "downloadLocation": "NOASSERTION",
                    "filesAnalyzed": False,
                    "licenseConcluded": c.licenses[0] if c.licenses else "NOASSERTION",
                    "licenseDeclared": c.licenses[0] if c.licenses else "NOASSERTION",
                    "copyrightText": "NOASSERTION",
                }
                for i, c in enumerate(components)
            ],
        }
        with open(path, "w") as f:
            json.dump(doc, f, indent=2)

    @staticmethod
    def _write_fallback_cyclonedx(components: List[SBOMComponent], path: str) -> None:
        import datetime, uuid
        doc = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                "tools": [{"name": "sdk-analyzer-agent-fallback", "version": "1.0"}],
            },
            "components": [
                {
                    "type": c.package_type or "library",
                    "name": c.name,
                    "version": c.version,
                    "purl": c.purl,
                    "licenses": [{"license": {"id": lic}} for lic in c.licenses] if c.licenses else [],
                }
                for c in components
            ],
        }
        with open(path, "w") as f:
            json.dump(doc, f, indent=2)
