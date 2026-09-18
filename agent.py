"""
SDK Analyzer Agent — Main Orchestrator
=======================================
Accepts a source-code archive, a directory, or a single code file and runs
the full analysis pipeline:

  Stage 1  →  Ingest input (archive/dir/file) + detect language/build-system
  Stage 2  →  Generate SBOM (Syft / fallback)
  Stage 3A →  License scan (FOSSology REST API / nomos / Python fallback)
  Stage 3B →  License cross-validation (ScanCode / Python fallback)
  Stage 4  →  Vulnerability analysis (Grype / OWASP DC / OSV.dev API)
  Stage 5  →  Code quality & improvement analysis (Semgrep / built-in)
  Stage 6  →  Report aggregation → JSON + HTML dashboard

Usage (CLI):
    python agent.py <path/to/sdk.zip | /path/to/src_dir | /path/to/file.py> [--output-dir ./output]

Usage (Python API):
    from agent import SDKAnalyzerAgent
    agent = SDKAnalyzerAgent()
    report = await agent.analyze("/path/to/sdk.zip")       # archive
    report = await agent.analyze("/path/to/src_dir")       # directory
    report = await agent.analyze("/path/to/main.py")       # single code file
"""

import argparse
import asyncio
import logging
import os
import sys
import time
from pathlib import Path
from typing import Optional

from stages.extractor       import ExtractorStage
from stages.sbom_generator  import SBOMGeneratorStage
from stages.fossology_scanner import FossologyScanner
from stages.scancode_runner import ScancodeRunner
from stages.vuln_analyzer   import VulnerabilityAnalyzer
from stages.quality_checker import QualityChecker
from stages.report_builder  import ReportBuilder, AnalysisReport

try:
    from rich.console import Console
    from rich.logging import RichHandler
    from rich.panel import Panel
    from rich.table import Table
    _RICH_AVAILABLE = True
except ImportError:
    _RICH_AVAILABLE = False

# ---------------------------------------------------------------------------
# Logging setup — colorized via rich when available, plain otherwise
# ---------------------------------------------------------------------------

# Force a minimum console width so Rich never falls back to hard-breaking
# long unbreakable tokens (file paths, SDK names) mid-word when the detected
# terminal width is narrow or unavailable (e.g. piped output, some CI runners).
_console = Console(width=max(Console().size.width, 120), soft_wrap=False) if _RICH_AVAILABLE else None

if _RICH_AVAILABLE:
    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
        datefmt="%H:%M:%S",
        handlers=[RichHandler(
            console=_console, show_path=False, markup=True, rich_tracebacks=True,
            show_time=True, log_time_format="[%H:%M:%S]",
        )],
    )
else:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
        datefmt="%H:%M:%S",
    )
logger = logging.getLogger("sdk-analyzer")


def _stage_banner(stage_num: int, total: int, title: str) -> None:
    """Print a clean, non-wrapping stage separator instead of raw log lines."""
    if _RICH_AVAILABLE:
        _console.rule(f"[bold cyan]Stage {stage_num}/{total}[/bold cyan]  {title}", style="grey50")
    else:
        logger.info("-" * 70)
        logger.info("[Stage %d/%d] %s", stage_num, total, title)


def _short(path: str, keep: int = 2) -> str:
    """Shorten a long absolute path to its last `keep` components for log readability."""
    p = Path(path)
    parts = p.parts[-keep:]
    prefix = ".../" if len(p.parts) > keep else ""
    return prefix + str(Path(*parts)) if parts else str(p)


# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------

class SDKAnalyzerAgent:
    """
    Orchestrates the full SDK analysis pipeline.

    Parameters
    ----------
    work_dir    : Temporary extraction directory  (default: /export/tmp/sdk_analyzer)
    output_dir  : Where reports and SBOM files are written  (default: ./output)
    fossology_url   : Optional FOSSology server URL  (or set FOSSOLOGY_URL env)
    fossology_token : Optional FOSSology API token   (or set FOSSOLOGY_TOKEN env)
    """

    def __init__(
        self,
        work_dir:         str = os.environ.get("SDK_WORK_DIR", "/export/tmp/sdk_analyzer"),
        output_dir:       str = "./output",
        fossology_url:    Optional[str] = None,
        fossology_token:  Optional[str] = None,
    ):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.extractor   = ExtractorStage(work_dir=work_dir)
        self.sbom_gen    = SBOMGeneratorStage(output_dir=str(self.output_dir))
        self.fossology   = FossologyScanner(
            fossology_url=fossology_url,
            fossology_token=fossology_token,
        )
        self.scancode    = ScancodeRunner(output_dir=str(self.output_dir))
        self.vuln_analyzer = VulnerabilityAnalyzer(output_dir=str(self.output_dir))
        self.quality     = QualityChecker(output_dir=str(self.output_dir))
        self.reporter    = ReportBuilder(
            output_dir=str(self.output_dir),
            templates_dir=str(Path(__file__).parent / "templates"),
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def analyze(self, input_path: str, baseline_report: Optional[str] = None) -> AnalysisReport:
        """
        Run the full analysis pipeline on a source-code archive, a directory,
        or a single code file. Returns an AnalysisReport with all findings.

        baseline_report: optional path to a previous sdk_analysis_report.json —
        if given, a scan_diff.json is written comparing this run against it
        (new/resolved vulnerabilities, added/removed components, risk trend).
        """
        start_time = time.monotonic()
        if _RICH_AVAILABLE:
            _console.rule("[bold]SDK Analyzer Agent[/bold]", style="cyan")
            _console.print(f"  [bold]Input[/bold]      {_short(input_path, 3)}")
            _console.print(f"  [bold]Output dir[/bold]  {self.output_dir}\n")
        else:
            logger.info("=" * 60)
            logger.info("SDK Analyzer Agent — starting analysis")
            logger.info("Input: %s", input_path)
            logger.info("Output dir: %s", self.output_dir)
            logger.info("=" * 60)

        # ----------------------------------------------------------------
        # Stage 1: Extraction
        # ----------------------------------------------------------------
        _stage_banner(1, 6, "Ingesting input and detecting metadata")
        extraction_result = self.extractor.extract(input_path)
        src_dir = extraction_result.src_dir
        logger.info(
            "✓ %d files detected  |  SDK: %s  |  languages: %s",
            extraction_result.total_files,
            extraction_result.sdk_name,
            ", ".join(extraction_result.languages),
        )

        # ----------------------------------------------------------------
        # Stage 2 + Stage 3 (A & B) run in parallel
        # ----------------------------------------------------------------
        _stage_banner(2, 6, "Generating SBOM and scanning licenses (parallel)")
        # Run license scans first so their results can enrich the SBOM
        fossology_task  = asyncio.create_task(self.fossology.scan(src_dir))
        scancode_task   = asyncio.create_task(self.scancode.scan(src_dir, file_count_hint=extraction_result.total_files))
        fossology_result, scancode_result = await asyncio.gather(
            fossology_task, scancode_task, return_exceptions=False,
        )
        # Merge license distributions from both scanners to pass into SBOM enrichment
        merged_license_dist: dict = {}
        for dist in (fossology_result.license_distribution, scancode_result.license_distribution):
            for k, v in dist.items():
                merged_license_dist[k] = merged_license_dist.get(k, 0) + v

        # Now run SBOM generation with license context
        sbom_result = await self.sbom_gen.run(src_dir, license_distribution=merged_license_dist)

        logger.info("✓ SBOM: %d components", sbom_result.total_components)
        logger.info(
            "✓ License scan (FOSSology): %d files scanned, %d copyleft",
            fossology_result.total_files_scanned,
            len(fossology_result.copyleft_files),
        )
        logger.info(
            "✓ License scan (ScanCode):  %d files scanned",
            scancode_result.total_files_scanned,
        )

        # ----------------------------------------------------------------
        # Stage 4: Vulnerability analysis (needs SBOM)
        # ----------------------------------------------------------------
        _stage_banner(4, 6, "Analyzing vulnerability exposure")
        vuln_result = await self.vuln_analyzer.scan(
            sbom_path=sbom_result.cyclonedx_path,
            components=sbom_result.components,
        )
        logger.info(
            "✓ Vulnerabilities: %d total (critical=%d, high=%d, medium=%d, low=%d)",
            vuln_result.total_vulnerabilities,
            vuln_result.severity_counts.get("CRITICAL", 0),
            vuln_result.severity_counts.get("HIGH", 0),
            vuln_result.severity_counts.get("MEDIUM", 0),
            vuln_result.severity_counts.get("LOW", 0),
        )

        # ----------------------------------------------------------------
        # Stage 5: Code quality (runs in parallel with vuln if desired)
        # ----------------------------------------------------------------
        _stage_banner(5, 6, "Running code quality and improvement analysis")
        quality_result = await self.quality.scan(src_dir)
        logger.info(
            "✓ Quality findings: %d  |  Recommendations: %d",
            quality_result.total_findings,
            len(quality_result.recommendations),
        )

        # ----------------------------------------------------------------
        # Stage 6: Report generation
        # ----------------------------------------------------------------
        _stage_banner(6, 6, "Building JSON + HTML reports")
        duration = time.monotonic() - start_time
        report = self.reporter.build(
            extraction_result=extraction_result,
            sbom_result=sbom_result,
            fossology_result=fossology_result,
            scancode_result=scancode_result,
            vuln_result=vuln_result,
            quality_result=quality_result,
            duration_seconds=duration,
            baseline_report=baseline_report,
        )

        if _RICH_AVAILABLE:
            _console.rule(f"[bold green]Analysis complete[/bold green]  ({duration:.1f}s)", style="green")
        else:
            logger.info("=" * 60)
            logger.info("Analysis complete in %.1f seconds", duration)
            logger.info("Risk Level   : %s (score: %s/100)", report.risk_level, report.risk_score)
            logger.info("Compliance   : %s", report.compliance_status)
            logger.info("JSON report  : %s/sdk_analysis_report.json", self.output_dir)
            logger.info("HTML report  : %s/sdk_analysis_report.html", self.output_dir)
            if baseline_report and (self.output_dir / "scan_diff.json").exists():
                logger.info("Scan diff    : %s/scan_diff.json", self.output_dir)
            logger.info("=" * 60)

        return report


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="SDK Analyzer Agent — SBOM, license compliance, and vulnerability analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python agent.py my_sdk.zip
  python agent.py ./my_source_dir
  python agent.py my_module.py
  python agent.py my_sdk.zip --output-dir ./reports
  python agent.py my_sdk.zip --fossology-url http://localhost:8081/repo
  python agent.py my_sdk_v2.zip --baseline ./reports_v1/sdk_analysis_report.json
        """,
    )
    parser.add_argument("input_path",       help="Path to a source code archive (ZIP, 7z, tar.gz, etc.), a directory, or a single code file")
    parser.add_argument("--output-dir",     default="./output", help="Output directory for reports (default: ./output). Reports are overwritten in place on each run.")
    parser.add_argument("--work-dir",       default=os.environ.get("SDK_WORK_DIR", "/export/tmp/sdk_analyzer"), help="Temporary extraction directory (env: SDK_WORK_DIR)")
    parser.add_argument("--fossology-url",  default=None, help="FOSSology server URL (optional)")
    parser.add_argument("--fossology-token",default=None, help="FOSSology API token (optional)")
    parser.add_argument("--baseline",       default=None, help="Path to a previous sdk_analysis_report.json to diff against (writes scan_diff.json)")
    parser.add_argument("--log-level",      default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    return parser.parse_args()


def _print_summary(report: AnalysisReport, output_dir: Path) -> None:
    """Print a colorized end-of-run summary via rich, or plain log lines as fallback."""
    if not _RICH_AVAILABLE:
        logger.info("=" * 60)
        logger.info("Risk Level   : %s (score: %s/100)", report.risk_level, report.risk_score)
        logger.info("Compliance   : %s", report.compliance_status)
        logger.info("Reports      : %s", output_dir)
        return

    risk_style = {"LOW": "green", "MEDIUM": "yellow", "HIGH": "orange3", "CRITICAL": "bold red"}.get(report.risk_level, "white")
    compliance_style = "green" if report.compliance_status == "PASS" else "bold red"

    table = Table(show_header=False, box=None, padding=(0, 1))
    table.add_row("SDK", report.sdk_name)
    table.add_row("Risk", f"[{risk_style}]{report.risk_level}[/{risk_style}] ({report.risk_score}/100)")
    table.add_row("Compliance", f"[{compliance_style}]{report.compliance_status}[/{compliance_style}]")
    table.add_row("Components", str(report.total_components))
    table.add_row("Vulnerabilities", f"{report.total_vulnerabilities} "
                  f"(critical={report.severity_counts.get('CRITICAL', 0)}, high={report.severity_counts.get('HIGH', 0)})")
    table.add_row("Quality findings", str(report.quality_findings_count))
    table.add_row("HTML report", str(output_dir / "sdk_analysis_report.html"))
    table.add_row("JSON report", str(output_dir / "sdk_analysis_report.json"))

    _console.print(Panel(table, title="[bold]SDK Analyzer — Run Complete[/bold]", border_style=risk_style))


async def _main() -> int:
    args = parse_args()
    logging.getLogger().setLevel(getattr(logging, args.log_level))

    agent = SDKAnalyzerAgent(
        work_dir=args.work_dir,
        output_dir=args.output_dir,
        fossology_url=args.fossology_url,
        fossology_token=args.fossology_token,
    )

    report = await agent.analyze(args.input_path, baseline_report=args.baseline)

    _print_summary(report, Path(args.output_dir))

    # Exit code: 1 if compliance FAIL, CRITICAL risk, or (with --baseline) a
    # new CRITICAL/HIGH vulnerability regression was introduced since the baseline.
    if report.compliance_status == "FAIL" or report.risk_level == "CRITICAL":
        return 1
    if args.baseline:
        diff_path = Path(args.output_dir) / "scan_diff.json"
        if diff_path.exists():
            import json
            with open(diff_path) as f:
                diff = json.load(f)
            if diff["verdict"].startswith("REGRESSION"):
                logger.error("CI gate FAILED: %s", diff["verdict"])
                return 1
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(_main()))
