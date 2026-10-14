# syntax=docker/dockerfile:1
# Multi-arch, distroless image: no shell, no package manager, runs as nonroot.
# Base images are pinned by digest (Dependabot bumps them).
# The builder and runtime share the same Python minor (3.13) so compiled wheels match.

FROM python:3.14-slim-trixie@sha256:a2b82f3c48559aa0a8446d9af49826b6e2b2016f4cd2afabfe6013ec53729170 AS build
COPY --from=ghcr.io/astral-sh/uv:0.9@sha256:538e0b39736e7feae937a65983e49d2ab75e1559d35041f9878b7b7e51de91e4 /uv /bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy
WORKDIR /src
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY src ./src
RUN uv export --locked --no-dev --no-emit-project --format requirements-txt -o requirements.txt \
 && uv pip install --python python3.13 --target /app --require-hashes -r requirements.txt \
 && uv build --wheel --out-dir /dist \
 && uv pip install --python python3.13 --target /app --no-deps /dist/*.whl

FROM gcr.io/distroless/python3-debian13:nonroot@sha256:774595d652a294b54c9bd575b2d9fdd1a4b47547dc17b8bfa4c0e953c64855b3
LABEL org.opencontainers.image.title="mcp-posture" \
      org.opencontainers.image.description="Security posture scanner for remote MCP servers" \
      org.opencontainers.image.source="https://github.com/batou9150/mcp-posture" \
      org.opencontainers.image.licenses="MIT"
COPY --from=build /app /app
ENV PYTHONPATH=/app PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /work
ENTRYPOINT ["/usr/bin/python3", "-m", "mcp_posture"]
CMD ["--help"]
