FROM rust:1.88-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends git python3 ca-certificates && rm -rf /var/lib/apt/lists/*
RUN git clone https://github.com/SecurityRonin/browser-forensic.git /workspace/browser-forensic \
 && cd /workspace/browser-forensic \
 && git checkout 10e2f70bd53d50144edcff849749efd0095c9a03
COPY starter.py /opt/wal-starter.py
RUN python3 /opt/wal-starter.py \
 && cd /workspace/browser-forensic \
 && cargo build --locked -p browser-forensic-core
WORKDIR /workspace/browser-forensic
