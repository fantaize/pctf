FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONDONTWRITEBYTECODE=1

# ── Node.js (required by Claude Code CLI bundled with the SDK) ──
RUN apt-get update && apt-get install -y curl ca-certificates gnupg && \
    curl -fsSL https://deb.nodesource.com/setup_22.x | bash - && \
    apt-get install -y nodejs && \
    rm -rf /var/lib/apt/lists/*

# ── Minimal system tools (Claude Code can apt-get install more as needed) ──
RUN apt-get update && apt-get install -y \
    gcc g++ make cmake \
    git wget netcat-openbsd nmap socat \
    binutils binwalk file xxd zip unzip \
    openssl libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# ── Python dependencies (just what the agent + common CTF needs) ──
RUN pip install --no-cache-dir \
    claude-agent-sdk \
    requests \
    beautifulsoup4 \
    rich \
    httpx \
    pwntools \
    pycryptodome \
    Pillow \
    numpy \
    sympy

# ── Non-root user (required: Claude Code refuses --dangerously-skip-permissions as root) ──
RUN useradd -m -s /bin/bash solver && \
    apt-get update && apt-get install -y sudo && rm -rf /var/lib/apt/lists/* && \
    echo "solver ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

WORKDIR /app

COPY . /app

RUN mkdir -p /app/workdir /app/logs && chown -R solver:solver /app

USER solver

ENTRYPOINT ["python3"]
CMD ["orchestrator.py"]
