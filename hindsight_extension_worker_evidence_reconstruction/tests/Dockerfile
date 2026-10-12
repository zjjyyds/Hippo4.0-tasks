FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Same pinned environment as the agent side.
RUN git clone https://github.com/RyanDFIR/hindsight.git /workspace/hindsight \
    && cd /workspace/hindsight \
    && git checkout 25bfb163bdcbb095daf33d55f087cab9a086a23f \
    && pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir pytest

WORKDIR /tests

COPY verify.py test.sh ANALYSIS.md /tests/
COPY expected/ /tests/expected/
COPY fixtures/ /tests/fixtures/

RUN chmod +x /tests/test.sh
