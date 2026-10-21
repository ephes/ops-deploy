# Layer-2 containers of the Rust echoport-command-guard (PLAN.md 7.5): the
# hosts' distributions with their system Python and the policies' users.
# Build context: the rust/ workspace. `run-layer2.sh` builds and runs both:
#
#   BASE=ubuntu:24.04   Python 3.12 (production)
#   BASE=debian:13      Python 3.13 (staging)
#
# The probe is built on Debian 12 (glibc 2.36, below both hosts) with the
# workspace's pinned toolchain, from the committed Cargo.lock.
ARG BASE=ubuntu:24.04

FROM rust:1.99.1-slim-bookworm AS build
WORKDIR /src
COPY . .
# No git in the context: `--version` of this build says `unknown`.
ENV RUSTUP_TOOLCHAIN=1.99.1
RUN cargo build --locked --release -p echoport-command-guard --example env-probe \
    && install -m 0755 target/release/examples/env-probe /env-probe

FROM ${BASE} AS layer2
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3 \
    && rm -rf /var/lib/apt/lists/*
# The users of the fixture policies (fixtures/policies/), as system users.
RUN for user in postgres gotosocial marina villakunterbunt python-podcast; do \
        useradd --system --user-group --no-create-home --shell /usr/sbin/nologin "$user"; \
    done
COPY --from=build /env-probe /usr/local/bin/env-probe
COPY echoport-command-guard/parity/e2e/layer2_realpath.py /e2e/layer2_realpath.py
CMD ["python3", "-I", "/e2e/layer2_realpath.py", "--probe", "/usr/local/bin/env-probe"]
