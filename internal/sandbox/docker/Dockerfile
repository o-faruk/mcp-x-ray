FROM node:20-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv strace curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/root/.local/bin:${PATH}"

WORKDIR /work
