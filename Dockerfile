# syntax=docker/dockerfile:1.7
#
# bgpeek — multi-stage build with uv.
# Final image: non-root, tini, slim.

# ===== Stage 1: build venv with uv =====
FROM python:3.12-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential \
      libffi-dev \
      libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:0.6 /uv /usr/local/bin/uv

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/opt/venv

WORKDIR /app

ENV PATH="/opt/venv/bin:$PATH"

COPY pyproject.toml uv.lock* README.md ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv venv /opt/venv && \
    uv sync --frozen --no-install-project --no-dev 2>/dev/null \
      || uv pip install --python /opt/venv/bin/python --no-cache -r pyproject.toml

COPY src ./src
RUN --mount=type=cache,target=/root/.cache/uv \
    uv pip install --python /opt/venv/bin/python --no-cache --no-deps -e .

# Build Tailwind CSS (standalone binary, no Node.js needed)
ARG TAILWIND_VERSION=v3.4.17
ARG TAILWIND_LINUX_X64_SHA256=7d24f7fa191d2193b78cd5f5a42a6093e14409521908529f42d80b11fde1f1d4
ADD https://github.com/tailwindlabs/tailwindcss/releases/download/${TAILWIND_VERSION}/tailwindcss-linux-x64 /usr/local/bin/tailwindcss
RUN echo "${TAILWIND_LINUX_X64_SHA256}  /usr/local/bin/tailwindcss" | sha256sum -c - \
    && chmod +x /usr/local/bin/tailwindcss
COPY tailwind.config.js ./
RUN tailwindcss -i src/bgpeek/static/css/input.css -o src/bgpeek/static/css/tailwind.css --minify

# ===== Stage 2: runtime =====
FROM python:3.12-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
      libffi8 \
      openssl \
      ca-certificates \
      curl \
      tini \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 1000 bgpeek \
    && useradd -u 1000 -g bgpeek -s /bin/sh -m bgpeek

WORKDIR /app

COPY --from=builder --chown=bgpeek:bgpeek /opt/venv /opt/venv
COPY --from=builder --chown=bgpeek:bgpeek /app/src /app/src
COPY --chown=bgpeek:bgpeek pyproject.toml README.md ./
COPY --chown=bgpeek:bgpeek migrations ./migrations

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    BGPEEK_HOST=0.0.0.0 \
    BGPEEK_PORT=8000

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${BGPEEK_PORT}/api/health" || exit 1

USER bgpeek

ENTRYPOINT ["tini", "--"]
CMD ["python3", "-m", "bgpeek.main"]
