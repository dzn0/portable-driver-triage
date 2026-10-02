# syntax=docker/dockerfile:1
#
# Portable Driver Triage — single zero-config image (static pipeline).
#
# Everything the L0-L3+ static pipeline needs is bundled: Python + the analysis
# deps (pefile, capstone, cryptography, angr, …), 7-Zip for installer
# extraction, and the vendored DrvEye engine. "Clone the repo, build, triage"
# with no host-side "install these 14 libraries first".
#
# Multi-stage so the compiler toolchain stays in the discarded builder and the
# final image carries only the runtime venv.
#
#   docker build -t portable-driver-triage:latest .
#   docker run --rm -v "$PWD/pipeline_out:/work/pipeline_out" \
#                   -v "$PWD/reports:/work/reports" \
#                   portable-driver-triage:latest pipeline.collect --list
#
# NOTE: this is the STATIC pipeline only. Nothing here executes a driver — the
# .sys files are parsed as bytes. Dynamic analysis is explicitly out of scope
# (see README → Safety model).

# ───────────────────────── builder ─────────────────────────
FROM python:3.13-bookworm AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install deps first (cached layer): the vendored engine's own requirements plus
# this pipeline's (which includes angr for on-demand decompilation).
COPY vendor/drveye/requirements.txt /tmp/drveye-req.txt
COPY pipeline/requirements.txt      /tmp/pipeline-req.txt
RUN pip install -r /tmp/drveye-req.txt -r /tmp/pipeline-req.txt

# ───────────────────────── runtime ─────────────────────────
FROM python:3.13-slim-bookworm AS runtime

# 7-Zip (installer extraction in the collectors) + curl (download fallback) +
# CA certs (vendor HTTPS downloads).
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        p7zip-full curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING=utf-8
COPY --from=builder /opt/venv /opt/venv

WORKDIR /work
COPY . /work

# Fail the build early if the engine or any core dep is missing.
RUN python -c "import capstone, pefile, cryptography, jinja2, yaml, angr; print('core deps OK')" \
 && python -m pipeline.collect --list >/dev/null && echo "pipeline imports OK"

# `python -m` entrypoint: pass a module + args, e.g.
#   docker run ... portable-driver-triage pipeline.analyze <sha256> --scope msr-access
ENTRYPOINT ["python", "-m"]
CMD ["pipeline.collect", "--list"]
