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

WORKDIR /workspace
RUN git clone https://github.com/ReFirmLabs/binwalk.git /workspace/binwalk \
    && cd /workspace/binwalk \
    && git checkout 26713972e3f9f52dc37d4a421c4554b0bd9e82ef \
    && cargo test --no-run --locked

WORKDIR /workspace/binwalk
