"""
Stage 1: Input Ingestion and Language/Build-System Detection

Accepts three kinds of input:
  1. Archives   — .zip, .7z, .tar, .tar.gz, .tgz, .tar.bz2, .tar.xz  (extracted)
  2. Directories — an already-unpacked source tree                  (copied as-is)
  3. Single code files — e.g. a lone .py/.c/.js/.java file           (copied as-is)
"""

import os
import zipfile
import tarfile
import shutil
import logging
from pathlib import Path
from collections import Counter
from dataclasses import dataclass, field
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class ExtractionResult:
    src_dir: str                          # absolute path to extracted root
    sdk_name: str                         # derived from ZIP filename
    languages: List[str] = field(default_factory=list)
    build_systems: List[str] = field(default_factory=list)
    package_manifests: List[str] = field(default_factory=list)
    total_files: int = 0
    total_size_bytes: int = 0
    file_extension_counts: Dict[str, int] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Language / build-system detection tables
# ---------------------------------------------------------------------------

EXTENSION_LANGUAGE_MAP: Dict[str, str] = {
    ".py":    "Python",
    ".js":    "JavaScript",
    ".ts":    "TypeScript",
    ".jsx":   "JavaScript",
    ".tsx":   "TypeScript",
    ".java":  "Java",
    ".kt":    "Kotlin",
    ".scala": "Scala",
    ".c":     "C",
    ".cc":    "C++",
    ".cpp":   "C++",
    ".cxx":   "C++",
    ".h":     "C/C++",
    ".hpp":   "C++",
    ".cs":    "C#",
    ".go":    "Go",
    ".rs":    "Rust",
    ".rb":    "Ruby",
    ".php":   "PHP",
    ".swift": "Swift",
    ".m":     "Objective-C",
    ".r":     "R",
    ".sh":    "Shell",
    ".bash":  "Shell",
    ".dart":  "Dart",
    ".lua":   "Lua",
    ".pl":    "Perl",
    ".groovy":"Groovy",
}

BUILD_SYSTEM_INDICATORS: Dict[str, str] = {
    "CMakeLists.txt":           "CMake",
    "Makefile":                 "Make",
    "GNUmakefile":              "Make",
    "meson.build":              "Meson",
    "BUILD.bazel":              "Bazel",
    "WORKSPACE":                "Bazel",
    "build.gradle":             "Gradle",
    "build.gradle.kts":         "Gradle",
    "pom.xml":                  "Maven",
    "setup.py":                 "Python setuptools",
    "setup.cfg":                "Python setuptools",
    "pyproject.toml":           "Python (PEP 517)",
    "package.json":             "npm/Node.js",
    "yarn.lock":                "Yarn",
    "pnpm-lock.yaml":           "pnpm",
    "Cargo.toml":               "Cargo (Rust)",
    "go.mod":                   "Go Modules",
    "Podfile":                  "CocoaPods",
    "*.gemspec":                "RubyGems",
    "Gemfile":                  "Bundler (Ruby)",
    "composer.json":            "Composer (PHP)",
    "pubspec.yaml":             "Dart/Flutter",
}

PACKAGE_MANIFEST_NAMES = {
    "requirements.txt", "requirements*.txt",
    "package.json", "package-lock.json", "yarn.lock",
    "pom.xml", "build.gradle", "build.gradle.kts",
    "Cargo.toml", "Cargo.lock",
    "go.mod", "go.sum",
    "composer.json", "composer.lock",
    "Gemfile", "Gemfile.lock",
    "pubspec.yaml", "pubspec.lock",
    "pyproject.toml", "setup.py", "setup.cfg",
    "Pipfile", "Pipfile.lock",
    "conanfile.txt", "conanfile.py",
    "vcpkg.json",
}


# ---------------------------------------------------------------------------
# Stage implementation
# ---------------------------------------------------------------------------

class ExtractorStage:
    """
    Ingests an archive, a directory of source code, or a single code file
    and normalises it into a working directory for the rest of the pipeline.
    """

    SUPPORTED_EXTENSIONS = {".zip", ".7z", ".tar", ".gz", ".bz2", ".xz", ".tgz", ".tbz2"}
    ARCHIVE_SUFFIXES = (
        ".tar.gz", ".tar.bz2", ".tar.xz", ".tar.zst",
        ".7z", ".zip", ".tar", ".tgz", ".tbz2",
    )

    def __init__(self, work_dir: str = "/export/tmp/sdk_analyzer"):
        self.work_dir = Path(work_dir)
        self.work_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def extract(self, input_path: str) -> ExtractionResult:
        input_path = Path(input_path)
        if not input_path.exists():
            raise FileNotFoundError(f"Input not found: {input_path}")

        is_dir = input_path.is_dir()
        is_archive = (not is_dir) and self._is_archive(input_path)

        # Derive sdk_name — strip all known archive suffixes (files only)
        if is_dir:
            sdk_name = input_path.name
        else:
            sdk_name = input_path.name
            for suffix in self.ARCHIVE_SUFFIXES:
                if sdk_name.lower().endswith(suffix):
                    sdk_name = sdk_name[: -len(suffix)]
                    break
            else:
                sdk_name = input_path.stem or input_path.name

        dest_dir = self.work_dir / sdk_name

        # Clean previous run
        if dest_dir.exists():
            shutil.rmtree(dest_dir)
        dest_dir.mkdir(parents=True)

        if is_dir:
            logger.info("Copying source directory '%s' into workspace", input_path.name)
            self._copy_directory(input_path, dest_dir)
        elif is_archive:
            logger.info("Extracting archive '%s' into workspace", input_path.name)
            self._dispatch_extract(input_path, dest_dir)
        else:
            logger.info("Copying source file '%s' into workspace", input_path.name)
            shutil.copy2(input_path, dest_dir / input_path.name)

        result = ExtractionResult(
            src_dir=str(dest_dir),
            sdk_name=sdk_name,
        )
        self._analyse(dest_dir, result)
        self._log_summary(result)
        return result

    # ------------------------------------------------------------------
    # Input-type detection
    # ------------------------------------------------------------------

    @classmethod
    def _is_archive(cls, path: Path) -> bool:
        """Detect whether a file is a supported archive, by suffix or content sniffing."""
        name_lower = path.name.lower()
        if any(name_lower.endswith(suf) for suf in cls.ARCHIVE_SUFFIXES):
            return True
        try:
            if zipfile.is_zipfile(path):
                return True
        except OSError:
            pass
        try:
            if tarfile.is_tarfile(path):
                return True
        except OSError:
            pass
        return False

    @staticmethod
    def _copy_directory(src_dir: Path, dest_dir: Path) -> None:
        """Copy an already-unpacked source tree into the working directory."""
        for item in src_dir.iterdir():
            target = dest_dir / item.name
            if item.is_dir():
                shutil.copytree(item, target, dirs_exist_ok=True)
            else:
                shutil.copy2(item, target)

    # ------------------------------------------------------------------
    # Dispatch by format
    # ------------------------------------------------------------------

    def _dispatch_extract(self, archive_path: Path, dest_dir: Path) -> None:
        name_lower = archive_path.name.lower()

        if name_lower.endswith(".7z"):
            self._extract_7z(archive_path, dest_dir)
        elif tarfile.is_tarfile(archive_path):
            self._extract_tar(archive_path, dest_dir)
        elif zipfile.is_zipfile(archive_path):
            self._extract_zip(archive_path, dest_dir)
        else:
            raise ValueError(
                f"Unsupported archive format: {archive_path.suffix}. "
                "Supported: .zip, .7z, .tar, .tar.gz, .tgz, .tar.bz2, .tar.xz"
            )

    @staticmethod
    def _extract_zip(archive_path: Path, dest_dir: Path) -> None:
        """Extract ZIP while preventing path-traversal."""
        with zipfile.ZipFile(archive_path, "r") as zf:
            for member in zf.infolist():
                member_path = dest_dir / member.filename
                try:
                    member_path.resolve().relative_to(dest_dir.resolve())
                except ValueError:
                    logger.warning("Skipping unsafe path: %s", member.filename)
                    continue
                zf.extract(member, dest_dir)

    @staticmethod
    def _extract_tar(archive_path: Path, dest_dir: Path) -> None:
        """Extract tar/tar.gz/tar.bz2/tar.xz safely."""
        with tarfile.open(archive_path, "r:*") as tf:
            # Safe extraction: skip absolute paths and traversal
            safe_members = []
            for m in tf.getmembers():
                if m.name.startswith("/") or ".." in m.name:
                    logger.warning("Skipping unsafe tar path: %s", m.name)
                    continue
                safe_members.append(m)
            tf.extractall(path=dest_dir, members=safe_members)

    @staticmethod
    def _extract_7z(archive_path: Path, dest_dir: Path) -> None:
        """Extract 7z archive using py7zr."""
        try:
            import tempfile
            # Redirect tempfile to /export/tmp when /tmp is full
            tempfile.tempdir = "/export/tmp"
            import py7zr
            with py7zr.SevenZipFile(archive_path, mode="r") as sz:
                sz.extractall(path=dest_dir)
            logger.info("7z extraction complete (%s)", dest_dir.name)
        except ImportError:
            raise RuntimeError(
                "py7zr is required for .7z extraction. Install with: pip install py7zr"
            )
        except Exception as exc:
            raise RuntimeError(f"7z extraction failed: {exc}") from exc

    # ------------------------------------------------------------------
    # Helpers (kept for backward compat)
    # ------------------------------------------------------------------

    @staticmethod
    def _safe_extract(zf: zipfile.ZipFile, dest: Path) -> None:
        """Extract while preventing path-traversal attacks."""
        for member in zf.infolist():
            member_path = dest / member.filename
            try:
                member_path.resolve().relative_to(dest.resolve())
            except ValueError:
                logger.warning("Skipping unsafe path: %s", member.filename)
                continue
            zf.extract(member, dest)

    def _analyse(self, root: Path, result: ExtractionResult) -> None:
        ext_counter: Counter = Counter()
        build_systems_found: set = set()
        manifests_found: List[str] = []
        total_size = 0
        total_files = 0

        for path in root.rglob("*"):
            if path.is_file():
                total_files += 1
                total_size += path.stat().st_size
                ext = path.suffix.lower()
                if ext:
                    ext_counter[ext] += 1

                # Build system detection
                filename = path.name
                for indicator, bs_name in BUILD_SYSTEM_INDICATORS.items():
                    if filename == indicator or (indicator.startswith("*") and filename.endswith(indicator[1:])):
                        build_systems_found.add(bs_name)

                # Package manifest detection
                if filename in PACKAGE_MANIFEST_NAMES:
                    manifests_found.append(str(path.relative_to(root)))

        result.total_files = total_files
        result.total_size_bytes = total_size
        result.file_extension_counts = dict(ext_counter.most_common(20))

        # Derive top languages
        lang_counter: Counter = Counter()
        for ext, count in ext_counter.items():
            lang = EXTENSION_LANGUAGE_MAP.get(ext)
            if lang:
                lang_counter[lang] += count
        result.languages = [lang for lang, _ in lang_counter.most_common(10)]

        result.build_systems = sorted(build_systems_found)
        result.package_manifests = manifests_found

    @staticmethod
    def _log_summary(result: ExtractionResult) -> None:
        logger.info(
            "Extraction complete — %d files, %.1f MB, languages: %s, build systems: %s",
            result.total_files,
            result.total_size_bytes / 1024 / 1024,
            ", ".join(result.languages) or "none",
            ", ".join(result.build_systems) or "none",
        )
