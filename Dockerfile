FROM python:3.11-slim

LABEL maintainer="sdk-analyzer-agent"
LABEL description="SDK Analyzer Agent — SBOM, license compliance, vulnerability analysis"

# ---------------------------------------------------------------------------
# System dependencies + open-source tools
#
# NOTE: FOSSology's CLI scanners (nomos/monk/copyright) are NOT available as
# Debian/Ubuntu apt packages — "fossology-nomos" etc. do not exist upstream,
# so installing them here always failed the build. License scanning against
# FOSSology instead goes through its REST API, served by the separate
# `fossology` container defined in docker-compose.yml (see FOSSOLOGY_URL /
# FOSSOLOGY_TOKEN below). If FOSSology is unreachable, the agent falls back
# to a built-in Python regex license scanner automatically.
# ---------------------------------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl wget tar gzip git unzip \
    # Java (needed for OWASP Dependency-Check)
    default-jre-headless \
    # libgomp1 (GNU OpenMP runtime) is required by ScanCode Toolkit's
    # bundled libarchive extension — without it "scancode --version"
    # fails at import time with "libgomp.so.1: cannot open shared object".
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# ---------------------------------------------------------------------------
# Install Syft (SBOM generator)
# ---------------------------------------------------------------------------
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
    | sh -s -- -b /usr/local/bin

# ---------------------------------------------------------------------------
# Install Grype (vulnerability scanner)
# ---------------------------------------------------------------------------
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \
    | sh -s -- -b /usr/local/bin

# ---------------------------------------------------------------------------
# Install OWASP Dependency-Check
# ---------------------------------------------------------------------------
ENV DC_VERSION=9.0.9
RUN mkdir -p /opt/dependency-check && \
    wget -q "https://github.com/jeremylong/DependencyCheck/releases/download/v${DC_VERSION}/dependency-check-${DC_VERSION}-release.zip" \
         -O /tmp/dc.zip && \
    unzip -q /tmp/dc.zip -d /opt/ && \
    rm /tmp/dc.zip && \
    ln -s /opt/dependency-check/bin/dependency-check.sh /usr/local/bin/dependency-check

# ---------------------------------------------------------------------------
# Install Semgrep
# ---------------------------------------------------------------------------
RUN pip install --no-cache-dir semgrep

# ---------------------------------------------------------------------------
# Install ScanCode Toolkit
# ---------------------------------------------------------------------------
RUN pip install --no-cache-dir scancode-toolkit

# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /app/output /tmp/sdk_analyzer

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:8000/health || exit 1

CMD ["python", "server.py"]
