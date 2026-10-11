#!/usr/bin/env bash
# Copyright (c) The Tidecoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# Build the patched Cap'n Proto library for native CI jobs using NO_DEPENDS.
set -euo pipefail

REPO_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
WORK_DIR=${1:?Usage: install_capnp.sh WORK_DIR}
mkdir -p "${WORK_DIR}"
WORK_DIR=$(cd "${WORK_DIR}" && pwd)

# Match depends/packages/native_capnp.mk. Apply the same patch as capnp.mk.
VERSION=1.2.0
SHA256=ed00e44ecbbda5186bc78a41ba64a8dc4a861b5f8d4e822959b0144ae6fd42ef
ARCHIVE="${WORK_DIR}/capnproto-c++-${VERSION}.tar.gz"
curl --fail --location --retry 3 --output "${ARCHIVE}" \
  "https://capnproto.org/capnproto-c++-${VERSION}.tar.gz"
printf '%s  %s\n' "${SHA256}" "${ARCHIVE}" | shasum -a 256 --check

tar -xzf "${ARCHIVE}" -C "${WORK_DIR}"
patch --batch -p1 -d "${WORK_DIR}/capnproto-c++-${VERSION}" \
  < "${REPO_DIR}/depends/patches/capnp/macos_accept_dead_socket.patch"
cmake -S "${WORK_DIR}/capnproto-c++-${VERSION}" -B "${WORK_DIR}/build" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="${WORK_DIR}/install" \
  -DCMAKE_INSTALL_LIBDIR=lib -DBUILD_SHARED_LIBS=OFF -DBUILD_TESTING=OFF \
  -DWITH_OPENSSL=OFF -DWITH_ZLIB=OFF
cmake --build "${WORK_DIR}/build" --parallel "${CMAKE_BUILD_PARALLEL_LEVEL:-2}"
cmake --install "${WORK_DIR}/build"
