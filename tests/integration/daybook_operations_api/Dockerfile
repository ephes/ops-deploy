# Disposable PostgreSQL fixture: no host database/configuration mounts.
FROM ghcr.io/astral-sh/uv:0.13.5 AS uv
FROM postgres:17-bookworm
COPY --from=uv /uv /usr/local/bin/uv
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates git python3 rsync systemd && rm -rf /var/lib/apt/lists/*
ENV UV_PYTHON_INSTALL_DIR=/opt/owned-python UV_CACHE_DIR=/opt/owned-uv-cache
RUN uv python install 3.14.7 3.13
