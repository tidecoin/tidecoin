# syntax=docker/dockerfile:1.7

FROM debian:trixie-slim AS builder

ARG BUILD_JOBS=0
ARG INSTALL_PREFIX=/opt/tidecoin
ARG TARGETARCH

ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /usr/src/tidecoin

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        bison \
        build-essential \
        ca-certificates \
        ccache \
        cmake \
        curl \
        git \
        make \
        ninja-build \
        patch \
        pkgconf \
        procps \
        python3 \
        rsync \
        xz-utils && \
    rm -rf /var/lib/apt/lists/*

COPY --link . .

RUN set -eux; \
    build_jobs="${BUILD_JOBS}"; \
    if [ "${build_jobs}" = "0" ] || [ -z "${build_jobs}" ]; then \
        build_jobs="$(nproc)"; \
    fi; \
    arch="${TARGETARCH:-$(dpkg --print-architecture)}"; \
    case "${arch}" in \
        amd64|x86_64) host_triplet="x86_64-pc-linux-gnu" ;; \
        arm64|aarch64) host_triplet="aarch64-linux-gnu" ;; \
        *) echo "Unsupported TARGETARCH: ${arch}" >&2; exit 1 ;; \
    esac; \
    make -C depends -j"${build_jobs}" HOST="${host_triplet}" NO_QT=1 NO_QR=1 NO_WALLET=1 NO_ZMQ=1 NO_IPC=1 NO_USDT=1; \
    cmake -S . -B build \
        -G Ninja \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX="${INSTALL_PREFIX}" \
        -DCMAKE_TOOLCHAIN_FILE="$PWD/depends/${host_triplet}/toolchain.cmake" \
        -DBUILD_TIDECOIN_BIN=OFF \
        -DBUILD_DAEMON=ON \
        -DBUILD_CLI=ON \
        -DBUILD_TX=OFF \
        -DBUILD_UTIL=OFF \
        -DBUILD_TESTS=OFF \
        -DBUILD_BENCH=OFF \
        -DBUILD_FUZZ_BINARY=OFF \
        -DBUILD_GUI=OFF \
        -DBUILD_GUI_TESTS=OFF \
        -DBUILD_WALLET_TOOL=OFF \
        -DENABLE_WALLET=OFF \
        -DENABLE_IPC=OFF \
        -DENABLE_EXTERNAL_SIGNER=OFF \
        -DWITH_ZMQ=OFF \
        -DWITH_USDT=OFF \
        -DREDUCE_EXPORTS=ON \
        -DINSTALL_MAN=OFF \
        -DWERROR=ON; \
    cmake --build build -j"${build_jobs}" --target install


FROM debian:trixie-slim AS runtime

ENV DEBIAN_FRONTEND=noninteractive \
    HOME=/home/tidecoin \
    TIDECOIN_DATA=/data

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        gosu \
        libgcc-s1 \
        libstdc++6 \
        tini && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd --system --gid 10001 tidecoin && \
    useradd --system --uid 10001 --gid tidecoin --home-dir /home/tidecoin --create-home --shell /usr/sbin/nologin tidecoin && \
    mkdir -p /data && \
    chown -R tidecoin:tidecoin /data /home/tidecoin

COPY --from=builder /opt/tidecoin/bin/tidecoind /usr/local/bin/tidecoind
COPY --from=builder /opt/tidecoin/bin/tidecoin-cli /usr/local/bin/tidecoin-cli
COPY --link docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

RUN chmod 0755 /usr/local/bin/tidecoind /usr/local/bin/tidecoin-cli /usr/local/bin/docker-entrypoint.sh

WORKDIR /data
VOLUME ["/data"]

EXPOSE 8755 7585

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/docker-entrypoint.sh"]
CMD ["tidecoind", "-printtoconsole", "-datadir=/data", "-conf=/data/tidecoin.conf"]
