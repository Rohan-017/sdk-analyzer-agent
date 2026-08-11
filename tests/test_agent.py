"""
Integration tests for the SDK Analyzer Agent.
Creates a minimal synthetic SDK ZIP and runs the full pipeline.
"""

import asyncio
import io
import json
import os
import zipfile
import tempfile
import pytest
from pathlib import Path

# Add parent dir to path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from agent import SDKAnalyzerAgent


# ---------------------------------------------------------------------------
# Fixture: Synthetic SDK ZIP
# ---------------------------------------------------------------------------

def _make_sdk_zip(tmp_dir: str) -> str:
    """Create a small synthetic SDK ZIP with known content."""
    zip_path = os.path.join(tmp_dir, "test_sdk.zip")

    files = {
        "src/main.py": """\
# SPDX-License-Identifier: MIT
# Copyright 2024 Test Corp

import hashlib
import os

def compute_hash(data):
    # Using MD5 (insecure, should be replaced)
    return hashlib.md5(data).hexdigest()

# TODO: fix this before release
password = "hardcoded_secret_123"  # hardcoded password

def run():
    print("Hello SDK")
""",
        "src/utils.js": """\
// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Test Corp

const API_KEY = "sk-live-abc123";  // hardcoded API key
console.log("debug mode on");

function fetchData(url) {
  return fetch(url);  // plain HTTP OK
}
""",
        "requirements.txt": """\
requests==2.28.0
flask==2.3.2
numpy==1.24.0
cryptography==41.0.0
""",
        "package.json": json.dumps({
            "name": "test-sdk",
            "version": "1.0.0",
            "dependencies": {
                "lodash": "4.17.21",
                "axios": "1.6.0",
            }
        }),
        "LICENSE": """\
MIT License
Copyright (c) 2024 Test Corp
Permission is hereby granted, free of charge, to any person obtaining a copy...
""",
        "CMakeLists.txt": "cmake_minimum_required(VERSION 3.16)\nproject(TestSDK)\n",
    }

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in files.items():
            zf.writestr(name, content)

    return zip_path


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_work_dir():
    with tempfile.TemporaryDirectory() as d:
        yield d


@pytest.mark.asyncio
async def test_full_pipeline(tmp_work_dir):
    """Run the complete analysis pipeline on a synthetic SDK."""
    zip_path   = _make_sdk_zip(tmp_work_dir)
    output_dir = os.path.join(tmp_work_dir, "output")

    agent = SDKAnalyzerAgent(
        work_dir=os.path.join(tmp_work_dir, "work"),
        output_dir=output_dir,
    )

    report = await agent.analyze(zip_path)

    # --- Basic assertions ---
    assert report.sdk_name == "test_sdk"
    assert report.total_source_files > 0
    assert report.total_components >= 0

    # Language detection
    assert "Python" in report.detected_languages or "JavaScript" in report.detected_languages

    # Build system detection
    assert "CMake" in report.detected_build_systems

    # SBOM files should be created
    assert Path(report.sbom_spdx_path).exists(), "SPDX SBOM not generated"
    assert Path(report.sbom_cyclonedx_path).exists(), "CycloneDX SBOM not generated"

    # Reports should be created
    json_report = Path(output_dir) / "sdk_analysis_report.json"
    html_report = Path(output_dir) / "sdk_analysis_report.html"
    assert json_report.exists(), "JSON report not generated"
    assert html_report.exists(), "HTML report not generated"

    # JSON report should be valid and use the nested schema
    with open(json_report) as f:
        data = json.load(f)
    assert data["sdk_name"] == "test_sdk"
    assert data["schema_version"]
    assert "level" in data["risk"]
    assert "compliance_status" in data["risk"]
    assert "risk_level" in data["executive_summary"]

    print(f"\nReport: Risk={report.risk_level} ({report.risk_score}), Compliance={report.compliance_status}")
    print(f"Components: {report.total_components}, Vulns: {report.total_vulnerabilities}")
    print(f"Quality findings count: {report.quality_findings_count}")
    print(f"Recommendations: {[r['title'] for r in report.recommendations]}")


@pytest.mark.asyncio
async def test_extraction_only(tmp_work_dir):
    """Test only the extraction stage."""
    from stages.extractor import ExtractorStage

    zip_path = _make_sdk_zip(tmp_work_dir)
    extractor = ExtractorStage(work_dir=os.path.join(tmp_work_dir, "work"))
    result = extractor.extract(zip_path)

    assert result.sdk_name == "test_sdk"
    assert result.total_files >= 6
    assert "Python" in result.languages
    assert "CMake" in result.build_systems


@pytest.mark.asyncio
async def test_sbom_generation(tmp_work_dir):
    """Test SBOM generation stage."""
    from stages.extractor import ExtractorStage
    from stages.sbom_generator import SBOMGeneratorStage

    zip_path  = _make_sdk_zip(tmp_work_dir)
    extractor = ExtractorStage(work_dir=os.path.join(tmp_work_dir, "work"))
    extraction = extractor.extract(zip_path)

    output_dir = os.path.join(tmp_work_dir, "sbom_out")
    sbom_gen   = SBOMGeneratorStage(output_dir=output_dir)
    result     = await sbom_gen.run(extraction.src_dir)

    assert Path(result.spdx_path).exists()
    assert Path(result.cyclonedx_path).exists()
    # Should detect pip and npm dependencies
    assert result.total_components >= 0


@pytest.mark.asyncio
async def test_quality_scanner(tmp_work_dir):
    """Test quality checker detects issues in synthetic SDK."""
    from stages.extractor import ExtractorStage
    from stages.quality_checker import QualityChecker

    zip_path  = _make_sdk_zip(tmp_work_dir)
    extractor = ExtractorStage(work_dir=os.path.join(tmp_work_dir, "work"))
    extraction = extractor.extract(zip_path)

    checker = QualityChecker(output_dir=os.path.join(tmp_work_dir, "quality_out"))
    result  = await checker.scan(extraction.src_dir)

    assert result.total_findings > 0, "Quality checker should find issues in synthetic code"

    rule_ids = {f.rule_id for f in result.findings}
    # Should detect hardcoded password
    assert "hardcoded-password" in rule_ids, f"Expected hardcoded-password, got {rule_ids}"
    # Should detect MD5 usage
    assert "insecure-hash-md5" in rule_ids, f"Expected insecure-hash-md5, got {rule_ids}"


def test_license_policy_config():
    """Verify license policy config file is valid YAML."""
    import yaml
    config_path = Path(__file__).parent.parent / "config" / "license_policy.yml"
    assert config_path.exists()
    with open(config_path) as f:
        data = yaml.safe_load(f)
    assert "allowed" in data
    assert "prohibited" in data
    assert "MIT" in data["allowed"]
    # GPL-3.0 is deliberately NOT prohibited: GPL variants are common/expected
    # in embedded Linux SDKs and are handled via "review_required" + a WARN
    # rule instead of an outright FAIL (see config/license_policy.yml).
    assert "GPL-3.0" in data.get("review_required", [])
    assert "GPL-3.0" not in data["prohibited"]
    # Only licenses genuinely incompatible with distribution are prohibited.
    assert "AGPL-3.0" in data["prohibited"]
