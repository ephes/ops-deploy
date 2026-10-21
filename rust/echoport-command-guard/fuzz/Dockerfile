# The fuzzing toolchain of echoport-command-guard (PLAN.md 7.4): a pinned
# nightly and cargo-fuzz on Debian 12. `run-fuzz.sh` builds and uses it; the
# sources are mounted, not copied.
FROM rust:1.99.1-bookworm
ARG NIGHTLY=nightly-2026-10-01
ARG CARGO_FUZZ=0.13.2
RUN rustup toolchain install "$NIGHTLY" --profile minimal \
    && cargo +"$NIGHTLY" install cargo-fuzz --version "$CARGO_FUZZ" --locked \
    && rm -rf /usr/local/cargo/registry
ENV FUZZ_TOOLCHAIN=$NIGHTLY
