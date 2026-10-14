FROM python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive

# Use reliable mirror for system dependencies
RUN (sed -i 's/deb.debian.org/mirrors.ustc.edu.cn/g' /etc/apt/sources.list.d/debian.sources 2>/dev/null || \
     sed -i 's/deb.debian.org/mirrors.ustc.edu.cn/g' /etc/apt/sources.list 2>/dev/null || true) \
    && apt-get update && apt-get install -y --no-install-recommends \
       git \
       ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace
RUN git clone https://github.com/5h4d0wn1k/d4-net-forensics.git /workspace/d4-net-forensics \
    && cd /workspace/d4-net-forensics \
    && git checkout 06e8f893bc0818327a8d28da4264985cdeb731ab \
    && python3 -m unittest discover tests

WORKDIR /workspace/d4-net-forensics
