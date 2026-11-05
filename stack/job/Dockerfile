# Image for the exploit-watch binary (subcommands: run, bootstrap, demo, triage,
# report, serve) plus the typst CLI that `report` uses to render the PDF.
#
# Build context: stack/job (the crate), filtered by Dockerfile.dockerignore.
# compose.yml bind-mounts the repo root at /app for state/, stack/wiki/page/, .env,
# the component list and the test fixtures; the binary itself is built into the
# image, so code changes need `docker compose build job`.
#
# typst: a pinned release binary (x86_64 musl, static) from GitHub, checked against
# its sha256 (the digest GitHub lists for the release asset). Its own stage, so the
# download is cached and only the binary reaches the runtime image. To upgrade, set
# TYPST_VERSION and TYPST_SHA256 together and run the ignored report test.
#
# Proxy: HTTP_PROXY / HTTPS_PROXY / NO_PROXY are Docker's predefined build args.
# compose.yml passes them from the host so cargo can reach crates.io and
# apt and curl can reach Debian and GitHub behind the corporate proxy. They are
# deliberately not declared with ARG, which keeps them out of `docker history` and
# the image.

FROM rust:1.99.1-slim-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked \
 && cp target/release/exploit-watch /usr/local/bin/exploit-watch

FROM debian:bookworm-slim AS typst
ARG TYPST_VERSION=0.15.1
ARG TYPST_SHA256=a6d077d0a95eed5a2eba715b2dae06be954f624ccbf85758a03f389ded33118c
# apt and curl only honour the lowercase proxy variables.
RUN http_proxy="$HTTP_PROXY" https_proxy="$HTTPS_PROXY" apt-get update \
 && http_proxy="$HTTP_PROXY" https_proxy="$HTTPS_PROXY" apt-get install -y --no-install-recommends ca-certificates curl xz-utils \
 && rm -rf /var/lib/apt/lists/*
RUN https_proxy="$HTTPS_PROXY" curl -fsSL -o /tmp/typst.tar.xz \
      "https://github.com/typst/typst/releases/download/v${TYPST_VERSION}/typst-x86_64-unknown-linux-musl.tar.xz" \
 && echo "${TYPST_SHA256}  /tmp/typst.tar.xz" | sha256sum -c - \
 && tar -xJf /tmp/typst.tar.xz -C /tmp \
 && install -m 0755 /tmp/typst-x86_64-unknown-linux-musl/typst /usr/local/bin/typst \
 && /usr/local/bin/typst --version

FROM debian:bookworm-slim
# ca-certificates: TLS roots for the feeds; apt only honours the lowercase proxy variables.
RUN http_proxy="$HTTP_PROXY" https_proxy="$HTTPS_PROXY" apt-get update \
 && http_proxy="$HTTP_PROXY" https_proxy="$HTTPS_PROXY" apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --uid 1000 --create-home --shell /usr/sbin/nologin app
COPY --from=typst /usr/local/bin/typst /usr/local/bin/typst
COPY --from=build /usr/local/bin/exploit-watch /usr/local/bin/exploit-watch
WORKDIR /app
USER app
ENTRYPOINT ["exploit-watch"]
CMD ["run"]
