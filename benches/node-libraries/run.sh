#!/usr/bin/env bash
# Same conditions every time: one core, a memory cap, and the addon built fresh.
#
#   ./run.sh
#
# The cap is generous because some of these libraries pull in undici, which allocates
# WebAssembly address space at import; too tight a limit fails at require() rather than
# telling you anything about Hive.
set -eu
core="${CORE:-14}"
here="$(cd "$(dirname "$0")" && pwd)"
( cd "$here/../../hivecomb-node" && npx napi build --platform --release >/dev/null )
exec systemd-run --user --scope -q -p MemoryMax=6G -- \
    taskset -c "$core" node "$here/bench.mjs" "$@"
