FROM rust:1.88-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends git python3 util-linux ca-certificates && rm -rf /var/lib/apt/lists/*
RUN git clone https://github.com/SecurityRonin/browser-forensic.git /opt/wal-upstream \
 && cd /opt/wal-upstream \
 && git checkout 10e2f70bd53d50144edcff849749efd0095c9a03 \
 && CARGO_TARGET_DIR=/opt/wal-target cargo build --locked -p browser-forensic-core
COPY base_cases.py generate_cases.py verify.py self_test.py test.sh /tests/
COPY harness /tests/harness/
RUN python3 -B -m py_compile /tests/generate_cases.py /tests/verify.py \
 && python3 -B /tests/self_test.py \
 && chmod -R go-rwx /tests \
 && chmod +x /tests/test.sh \
 && mkdir -p /logs/verifier /tmp/wal-build
WORKDIR /workspace/browser-forensic
