# Dockerfile for DNSSECVerif
# ==========================
# Builds Tamarin 1.10.0 and ProVerif 2.04 for the SAPIC+/Tamarin and ProVerif
# models of "Mind the Gap: Cross-RFC Formal Analysis Exposes DNSSEC's Hidden
# Vulnerabilities" (ACM CCS 2026; GPL-3.0-only). See README.md.
#
# Build (single-arch, local):
#   docker build -t dnssecverif .
#
# Multi-arch build (linux/amd64 + linux/arm64) with buildx:
#   docker buildx create --use --name multibuild   # one-time setup
#   docker buildx build --platform linux/amd64,linux/arm64 -t dnssecverif .
#   # load a single platform locally (buildx cannot --load two platforms at once):
#   docker buildx build --platform linux/arm64 -t dnssecverif:arm64 --load .
#
# Run quick verification:
#   docker run --rm dnssecverif --quick
#
# Run full verification (mount results out):
#   docker run --rm -v $(pwd)/results:/app/results dnssecverif --full
#
# Tamarin provisioning (selected automatically via TARGETARCH):
#   - amd64: downloads the pre-built Tamarin 1.10.0 binary (fast, seconds).
#   - arm64: builds Tamarin 1.10.0 from source with stack/ghc (slow, ~30 min
#     build time, but required because no pre-built arm64 binary is published).
# ProVerif is compiled from source via opam on both architectures.

# The TARGETARCH build arg is set automatically by docker buildx for each
# --platform. For a plain `docker build` it defaults to the host architecture.
ARG TARGETARCH
ARG TARGETPLATFORM

FROM ubuntu:22.04 AS base

ARG TARGETARCH
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC

# Install system dependencies (shared by all stages).
# libgmp-dev/zlib1g-dev: Tamarin (Haskell) runtime + build deps.
# maude/graphviz: Tamarin rewriting-engine backend and trace rendering.
# ocaml/opam: ProVerif build.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    wget \
    git \
    ca-certificates \
    libgmp-dev \
    zlib1g-dev \
    graphviz \
    maude \
    ocaml \
    opam \
    && rm -rf /var/lib/apt/lists/*

# =============================================================================
# Stage 1: Build/obtain Tamarin Prover
#   - amd64: download the official pre-built binary.
#   - arm64: build from source with stack (no pre-built arm64 binary exists).
# Both branches produce /build/tamarin-prover.
# =============================================================================
FROM base AS tamarin-builder

ARG TARGETARCH
WORKDIR /build

RUN if [ "$TARGETARCH" = "arm64" ] || [ "$TARGETARCH" = "aarch64" ]; then \
        echo "[Dockerfile] arm64: building Tamarin from source (this takes ~30-45 min and several GB of RAM)"; \
        apt-get update && apt-get install -y --no-install-recommends \
            xz-utils \
            ca-certificates \
            libffi-dev \
            libncurses-dev \
            libtinfo-dev \
            libpcre3-dev \
            pkg-config \
            && rm -rf /var/lib/apt/lists/*; \
        curl -sSL https://get.haskellstack.org/ | sh; \
        git clone --depth 1 --branch 1.10.0 https://github.com/tamarin-prover/tamarin-prover.git /build/tamarin-prover-src; \
        cd /build/tamarin-prover-src; \
        stack --no-terminal setup; \
        stack --no-terminal install --local-bin-path /build; \
        chmod +x /build/tamarin-prover; \
        rm -rf /build/tamarin-prover-src /root/.stack; \
    else \
        echo "[Dockerfile] amd64: downloading pre-built Tamarin binary"; \
        curl -L -o tamarin.tar.gz \
            "https://github.com/tamarin-prover/tamarin-prover/releases/download/1.10.0/tamarin-prover-1.10.0-linux64-ubuntu.tar.gz" \
            && tar -xzf tamarin.tar.gz \
            && chmod +x tamarin-prover \
            && rm -f tamarin.tar.gz; \
    fi

# =============================================================================
# Stage 2: Build ProVerif (from source via opam, works on both arches)
# =============================================================================
FROM base AS proverif-builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    libexpat1-dev \
    libgtk2.0-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

RUN opam init --disable-sandboxing --yes \
    && eval $(opam env) \
    && opam install -y proverif.2.04

# =============================================================================
# Stage 3: Final runtime image
# =============================================================================
FROM ubuntu:22.04 AS runtime

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC

# Install runtime dependencies and locale support
RUN apt-get update && apt-get install -y --no-install-recommends \
    maude \
    graphviz \
    libgmp10 \
    zlib1g \
    libffi8 \
    libncurses6 \
    libtinfo6 \
    locales \
    && rm -rf /var/lib/apt/lists/* \
    && locale-gen en_US.UTF-8

# Set locale environment variables for UTF-8 support
ENV LANG=en_US.UTF-8
ENV LANGUAGE=en_US:en
ENV LC_ALL=en_US.UTF-8

# Copy Tamarin binary from builder
COPY --from=tamarin-builder /build/tamarin-prover /usr/local/bin/

# Copy ProVerif binary from builder (installed via opam)
COPY --from=proverif-builder /root/.opam/default/bin/proverif /usr/local/bin/

# Create app directory
WORKDIR /app

# Copy models and scripts
COPY models/ /app/models/
COPY run_all.sh /app/
COPY README.md /app/
COPY MODEL_INDEX.md /app/
COPY LICENSE NOTICE /app/
COPY docker-entrypoint.sh /app/

# Make scripts executable
RUN chmod +x /app/run_all.sh /app/docker-entrypoint.sh

# Create results directory
RUN mkdir -p /app/results

# Set environment
ENV PATH="/usr/local/bin:${PATH}"

# Verify installations (simple check - full verification at runtime)
RUN which tamarin-prover && which proverif && which maude

# Default entrypoint
ENTRYPOINT ["/app/docker-entrypoint.sh"]

# Default command (quick mode)
CMD ["--quick"]

# =============================================================================
# Metadata
# =============================================================================
LABEL org.opencontainers.image.title="DNSSECVerif"
LABEL org.opencontainers.image.description="Artifact for Mind the Gap: Cross-RFC Formal Analysis Exposes DNSSEC's Hidden Vulnerabilities"
LABEL org.opencontainers.image.authors="Qifan Zhang, Zilin Shen, Imtiaz Karim, Elisa Bertino, Daiping Liu, Zhou Li"
LABEL org.opencontainers.image.licenses="GPL-3.0-only"
LABEL org.opencontainers.image.source="https://github.com/DNSSECVerif/DNSSECVerif"
LABEL org.opencontainers.image.documentation="https://github.com/DNSSECVerif/DNSSECVerif#readme"
