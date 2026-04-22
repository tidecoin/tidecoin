#!/bin/sh
set -eu

TIDECOIN_DATA="${TIDECOIN_DATA:-/data}"

if [ "${1#-}" != "$1" ]; then
    set -- tidecoind -printtoconsole -datadir="${TIDECOIN_DATA}" -conf="${TIDECOIN_DATA}/tidecoin.conf" "$@"
fi

if [ "$(id -u)" = "0" ]; then
    mkdir -p "${TIDECOIN_DATA}"
    find "${TIDECOIN_DATA}" -mindepth 0 -exec chown tidecoin:tidecoin {} \; 2>/dev/null || true
    exec gosu tidecoin "$@"
fi

exec "$@"
