FROM rust:latest

ENV DEBIAN_FRONTEND=noninteractive

# Use mirror for fast, reliable package downloads
RUN (sed -i 's/deb.debian.org/mirrors.ustc.edu.cn/g' /etc/apt/sources.list.d/debian.sources 2>/dev/null || \
     sed -i 's/deb.debian.org/mirrors.ustc.edu.cn/g' /etc/apt/sources.list 2>/dev/null || true) \
    && apt-get update && apt-get install -y --no-install-recommends \
    git \
    ca-certificates \
    python3 \
    build-essential \
    pkg-config \
    libfontconfig1-dev \
    libseccomp2 \
    util-linux \
    && rm -rf /var/lib/apt/lists/*

# Pre-fetch and pre-compile all binwalk and harness dependencies during image build
# so that test.sh runs 100% offline without network access.
WORKDIR /workspace
RUN git clone https://github.com/ReFirmLabs/binwalk.git /workspace/binwalk \
    && cd /workspace/binwalk \
    && git checkout 26713972e3f9f52dc37d4a421c4554b0bd9e82ef \
    && cargo test --no-run --locked

WORKDIR /tests

COPY generate_cases.py verify.py sandbox.py make_runtime.py test_verify.py security_probe.c test.sh /tests/
COPY rust_harness /tests/rust_harness/
COPY signature_reference /tests/signature_reference/

# Build against the pristine pinned checkout before installing any submission.
# The trusted scanner is never rebuilt during grading.
RUN cargo build --release --offline --locked --manifest-path /tests/signature_reference/Cargo.toml \
    && cp /tests/signature_reference/target/release/signature_reference /tests/trusted_signature_reference \
    && python3 /tests/make_runtime.py /tests/trusted_signature_reference /tests/runtime-root \
    && cd /workspace/binwalk && sha256sum Cargo.toml Cargo.lock > /tests/upstream-cargo.sha256 \
    && mkdir -p /opt/dbsf-build-config \
    && cp -a /root/.config/kaleido /opt/dbsf-build-config/ \
    && chmod -R a+rX /opt/dbsf-build-config \
    && chmod +x /tests/generate_cases.py /tests/verify.py /tests/test.sh \
    && chmod -R go-w /tests \
    && python3 -B /tests/test_verify.py
