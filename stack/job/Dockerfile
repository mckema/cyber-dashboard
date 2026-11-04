# Image for the exploit-watch binary (subcommands: run, bootstrap, demo).
#
# Build context: stack/job (the crate), filtered by Dockerfile.dockerignore.
# compose.yml bind-mounts the repo root at /app for state/, stack/wiki/page/, .env,
# the component list and the test fixtures; the binary itself is built into the
# image, so code changes need `docker compose build job`.
#
# Proxy: HTTP_PROXY / HTTPS_PROXY / NO_PROXY are Docker's predefined build args.
# compose.yml passes them from the host so cargo can reach crates.io and
# apt can reach Debian behind the corporate proxy. They are deliberately not
# declared with ARG, which keeps them out of `docker history` and the image.

FROM rust:1.99.1-slim-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked \
 && cp target/release/exploit-watch /usr/local/bin/exploit-watch

FROM debian:bookworm-slim
# ca-certificates: TLS roots for the feeds; apt only honours the lowercase proxy variables.
RUN http_proxy="$HTTP_PROXY" https_proxy="$HTTPS_PROXY" apt-get update \
 && http_proxy="$HTTP_PROXY" https_proxy="$HTTPS_PROXY" apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --uid 1000 --create-home --shell /usr/sbin/nologin app
COPY --from=build /usr/local/bin/exploit-watch /usr/local/bin/exploit-watch
WORKDIR /app
USER app
ENTRYPOINT ["exploit-watch"]
CMD ["run"]
