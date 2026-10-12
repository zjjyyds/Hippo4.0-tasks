FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Pinned Python dependency set (ccl_chromium_reader is a git dependency and is
# pinned by requirements.txt itself to a fixed upstream commit).
RUN git clone https://github.com/RyanDFIR/hindsight.git /workspace/hindsight \
    && cd /workspace/hindsight \
    && git checkout 25bfb163bdcbb095daf33d55f087cab9a086a23f \
    && pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir pytest

WORKDIR /workspace/hindsight

# The task specification is the only documentation shipped to the agent.
RUN mkdir -p /task_docs
COPY task_docs/ /task_docs/

# Pre-compile and run the upstream test suite once at build time so that a
# broken baseline never masquerades as an agent failure.
RUN python -m pytest tests/ -q
