# Layer-2 containers of the Rust echoport-command-guard (PLAN.md 7.5): the
# hosts' distributions with their system Python and the policies' users.
# Build context: the rust/ workspace, so the Python guard (outside it) is
# mounted at run time as /e2e/guard.py. `run-layer2.sh` builds and runs both:
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
RUN cargo build --locked --release -p echoport-command-guard --bin echoport-command-guard --example env-probe \
    && install -m 0755 target/release/examples/env-probe /env-probe \
    && install -m 0755 target/release/echoport-command-guard /echoport-command-guard

FROM ${BASE} AS layer2
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3 \
    && rm -rf /var/lib/apt/lists/*
# The users of the fixture policies (fixtures/policies/), as system users.
RUN for user in postgres gotosocial marina villakunterbunt python-podcast; do \
        useradd --system --user-group --no-create-home --shell /usr/sbin/nologin "$user"; \
    done
COPY --from=build /env-probe /usr/local/bin/env-probe
COPY --from=build /echoport-command-guard /usr/local/bin/echoport-command-guard
COPY echoport-command-guard/fixtures/policies/ /e2e/policies/
COPY echoport-command-guard/parity/e2e/layer2_realpath.py echoport-command-guard/parity/e2e/layer2_decide.py /e2e/
CMD ["python3", "-I", "/e2e/layer2_realpath.py", "--probe", "/usr/local/bin/env-probe"]

# A local release-layout archive of the guard binary (the binary and LICENSE
# at the archive root, as rust-release.yml packs them) for the role's molecule
# scenarios (PLAN.md 6.2, S6). Built for the Docker host's architecture, on
# Debian 12 (glibc 2.36), so it runs in the Ubuntu 24.04 and Debian 13
# instances. `build-local-archive.sh` exports it:
#
#   docker build --target local-archive --output type=local,dest=<dir> rust/
FROM build AS guard-build
RUN cargo build --locked --release -p echoport-command-guard --bin echoport-command-guard \
    && mkdir /archive \
    && install -m 0755 target/release/echoport-command-guard /archive/echoport-command-guard \
    && install -m 0644 LICENSE /archive/LICENSE \
    && tar --sort=name --owner=0 --group=0 --numeric-owner --mtime=@0 \
        -czf /echoport-command-guard-local.tar.gz -C /archive echoport-command-guard LICENSE

FROM scratch AS local-archive
COPY --from=guard-build /echoport-command-guard-local.tar.gz /echoport-command-guard-local.tar.gz

# Layer 3 (PLAN.md 7.6): the same containers with sshd, the ssh/scp/sftp
# clients and rsync; `run-layer3.sh` runs parity/e2e/layer3_sshd.py in them.
FROM layer2 AS layer3
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        openssh-server openssh-client rsync \
    && rm -rf /var/lib/apt/lists/*
COPY echoport-command-guard/fixtures/corpus/runner.jsonl /e2e/runner.jsonl
COPY echoport-command-guard/parity/e2e/layer3_sshd.py echoport-command-guard/parity/e2e/stub-tool.sh /e2e/
