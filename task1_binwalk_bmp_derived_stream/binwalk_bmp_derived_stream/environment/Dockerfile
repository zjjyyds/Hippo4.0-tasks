FROM rust:latest

ENV DEBIAN_FRONTEND=noninteractive

# Use mirror for fast, reliable package downloads
RUN (sed -i 's/deb.debian.org/mirrors.ustc.edu.cn/g' /etc/apt/sources.list.d/debian.sources 2>/dev/null || \
     sed -i 's/deb.debian.org/mirrors.ustc.edu.cn/g' /etc/apt/sources.list 2>/dev/null || true) \
    && apt-get update && apt-get install -y --no-install-recommends \
    git \
    ca-certificates \
    build-essential \
    pkg-config \
    libfontconfig1-dev \
    python3 \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /task_docs /workspace
COPY derived-bitmap-stream.md /task_docs/derived-bitmap-stream.md
COPY samples /task_docs/samples/
COPY starter.py dbsf_smoke.rs public_check.py /task_docs/

WORKDIR /workspace
RUN git clone https://github.com/ReFirmLabs/binwalk.git /workspace/binwalk \
    && cd /workspace/binwalk \
    && git checkout 26713972e3f9f52dc37d4a421c4554b0bd9e82ef \
    && cargo test --no-run --locked

# Add the public skeleton after upstream has been built and pinned. The
# test/verifier container does not contain this starter or the hidden tests.
RUN python3 /task_docs/starter.py /workspace/binwalk \
    && mkdir -p /workspace/binwalk/examples \
    && cp /task_docs/dbsf_smoke.rs /workspace/binwalk/examples/dbsf_smoke.rs \
    && cd /workspace/binwalk && cargo check --offline --locked --lib --bins

WORKDIR /workspace/binwalk
