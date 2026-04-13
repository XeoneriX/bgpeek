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

# ===== Stage 2: runtime =====
FROM python:3.12-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
      libffi8 \
      openssl \
      ca-certificates \
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

USER bgpeek

ENTRYPOINT ["tini", "--"]
CMD ["python3", "-m", "bgpeek.main"]
