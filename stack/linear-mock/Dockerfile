# Image for linear-mock, the lab-only stand-in for the Linear GraphQL API
# (see the module doc at the top of src/main.rs).
#
# Build context is this directory: stack/linear-mock.
#
#   docker build -f stack/linear-mock/Dockerfile stack/linear-mock
#
# Runtime: MOCK_API_KEY and MOCK_TEAM_ID are required. issues.json lives in
# MOCK_DATA_DIR (default /data); mount a directory there that uid 1000 can
# write, not the single file (writes replace the file by rename). The binary
# does not handle SIGTERM, so run it with an init process (compose `init: true`)
# for a prompt stop. `linear-mock healthcheck` can serve as the container
# healthcheck: the image has no curl or wget.
#
# Proxy: HTTP_PROXY / HTTPS_PROXY / NO_PROXY are Docker's predefined build args,
# needed for cargo to reach crates.io behind the corporate proxy. They are
# deliberately not declared with ARG, which keeps them out of `docker history`
# and the image. The runtime stage installs nothing, so it needs no proxy and
# no ca-certificates (the mock makes no outbound connections).

FROM rust:1.99.1-slim-trixie AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked \
 && cp target/release/linear-mock /usr/local/bin/linear-mock

FROM debian:trixie-slim
RUN useradd --uid 1000 --create-home --shell /usr/sbin/nologin app \
 && mkdir /data \
 && chown app:app /data
COPY --from=build /usr/local/bin/linear-mock /usr/local/bin/linear-mock
USER app
ENV MOCK_DATA_DIR=/data PORT=8080
EXPOSE 8080
ENTRYPOINT ["linear-mock"]
