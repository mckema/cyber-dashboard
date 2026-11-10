# Image for the exploit-watch binary (subcommands: run, bootstrap, demo, triage,
# report, serve) plus the typst CLI that `report` uses to render the PDF.
#
# Build context: the repo root, filtered by .dockerignore. The page content (page/)
# is built into the binary. compose.yml bind-mounts the repo root at /app for state/,
# .env, the component list and the test fixtures; the binary itself is built into the
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
#
# Base images: pinned as tag@sha256 (the registry index digest); bump the digest
# together with the tag. The runtime stage runs apt-get upgrade so Debian security
# fixes released after the base image (trixie-security) are in the image.

FROM rust:1.99.1-slim-trixie@sha256:f6c4a35d21dbb3c89d7a8d056c193e94fc09037f2b58dd858b09c39a47dd02d7 AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY page ./page
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked \
 && cp target/release/exploit-watch /usr/local/bin/exploit-watch

FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2 AS typst
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

FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
# ca-certificates: TLS roots for the feeds; apt only honours the lowercase proxy variables.
# upgrade: Debian security fixes newer than the base image.
RUN http_proxy="$HTTP_PROXY" https_proxy="$HTTPS_PROXY" apt-get update \
 && http_proxy="$HTTP_PROXY" https_proxy="$HTTPS_PROXY" apt-get upgrade -y --no-install-recommends \
 && http_proxy="$HTTP_PROXY" https_proxy="$HTTPS_PROXY" apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --uid 1000 --create-home --shell /usr/sbin/nologin app
COPY --from=typst /usr/local/bin/typst /usr/local/bin/typst
COPY --from=build /usr/local/bin/exploit-watch /usr/local/bin/exploit-watch
# Component list for deployments without the repo bind mount (Cloud Run sets
# COMPONENTS_FILE=/etc/exploit-watch/components.toml). Outside /app, because
# compose bind-mounts the repo over /app. COMPONENTS_SRC picks the file from the
# build context; the sample list until the agreed list exists.
ARG COMPONENTS_SRC=components.sample.toml
COPY ${COMPONENTS_SRC} /etc/exploit-watch/components.toml
WORKDIR /app
USER app
ENTRYPOINT ["exploit-watch"]
CMD ["run"]
