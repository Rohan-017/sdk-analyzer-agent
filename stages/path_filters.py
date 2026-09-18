"""
Shared vendored/third-party/generated-code exclusion list.

Problem this solves
--------------------
Every scanner in this pipeline (quality/security rules, secret detection,
license detection) was walking the *entire* extracted source tree,
including bundled copies of other projects' code the SDK author didn't
write and can't fix: vendored crypto libraries, node_modules, generated
protobuf/gRPC stubs, test fixtures shipped inside third-party dependencies,
etc. Scanning these produces findings that are technically "true" but not
actionable, and inflates result counts (e.g. a real run against a 154k-file
SDK produced 12,282 files labeled "Proprietary" and 487 secret findings —
a large share from vendored/test code, not code the SDK team owns).

Rather than scanning everything and relabeling noise afterwards (which is
what stages/confidence_triage.py does for secrets already reported), this
module lets each scanner skip these paths *before* scanning, which is both
faster and produces a cleaner result set. It's intentionally a single
shared list so every stage stays in sync instead of each maintaining a
slightly different set of exclusions.

Precedence note: this is about excluding paths from scanning entirely. It
is distinct from (and complementary to) confidence_triage.py's job, which
only downgrades — never deletes — a finding's confidence, for the case
where a finding does get produced (e.g. via a scanner that doesn't support
path exclusion) and needs after-the-fact triage instead.
"""

import re
from pathlib import Path
from typing import Iterable, List

# Directory names that indicate vendored/third-party/generated/test code,
# not code the SDK team wrote or is expected to fix. Matched as an exact
# path-component name (case-sensitive, since these are conventional
# directory names in most ecosystems), not a substring, to avoid over-
# matching (e.g. a real dir named "attestor" should not be excluded just
# because it contains "test").
EXCLUDED_DIR_NAMES = {
    # Vendored / third-party dependencies
    "vendor", "vendored", "third_party", "third-party", "3rdparty", "3rd_party",
    "node_modules", "bower_components",
    # Test fixtures / sample / demo data (separate concern from production code)
    "testprof", "test-vectors", "testdata", "test-data", "fixtures", "mocks",
    "samples", "examples", "demos",
    # Generated / build output
    "generated", "gen", "__generated__", "dist", "build", "out", ".build",
    # VCS / tooling / caches
    ".git", ".svn", ".hg", "__pycache__", ".venv", "venv", ".github",
}

# Filename glob suffixes that indicate generated code even when not inside
# one of the directories above (e.g. a generated protobuf stub sitting
# next to hand-written source).
EXCLUDED_FILE_SUFFIXES = (
    ".pb.go", ".pb.cc", ".pb.h", "_pb2.py", ".g.dart", ".generated.cs",
)


def is_excluded_path(path: Path) -> bool:
    """True if any component of `path` names a vendored/third-party/generated dir,
    or the filename itself looks generated."""
    if any(part in EXCLUDED_DIR_NAMES for part in path.parts):
        return True
    name = path.name
    return any(name.endswith(suffix) for suffix in EXCLUDED_FILE_SUFFIXES)


def semgrep_exclude_args() -> List[str]:
    """--exclude flags for Semgrep, one glob per excluded dir name."""
    args: List[str] = []
    for d in sorted(EXCLUDED_DIR_NAMES):
        args += ["--exclude", d]
    return args


def gitleaks_allowlist_config(extra_dirs: Iterable[str] = ()) -> str:
    """
    A minimal gitleaks TOML config that extends the built-in default rule
    set (so we keep all of gitleaks' provider-specific detectors) and adds
    a path allowlist so vendored/third-party/test directories are skipped
    entirely rather than scanned and reported.
    """
    all_dirs = sorted(set(EXCLUDED_DIR_NAMES) | set(extra_dirs))
    pattern = r"(^|/)(" + "|".join(re.escape(d) for d in all_dirs) + r")(/|$)"
    return (
        "[extend]\n"
        'useDefault = true\n\n'
        "[allowlist]\n"
        f"paths = [\n  '''{pattern}''',\n]\n"
    )
