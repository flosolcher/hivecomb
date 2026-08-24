#!/usr/bin/env bash
# One core, a memory cap, and the extension built fresh from the working tree.
#
#   ./run.sh
#
# VENV can point at any interpreter that has beem, hive-nectar and lighthive installed:
#
#   uv venv --python 3.12 /tmp/pybench
#   VIRTUAL_ENV=/tmp/pybench uv pip install beem hive-nectar lighthive
#   VENV=/tmp/pybench ./run.sh
set -eu
core="${CORE:-14}"
here="$(cd "$(dirname "$0")" && pwd)"
root="$here/../.."
venv="${VENV:?set VENV to a virtualenv with beem, hive-nectar and lighthive installed}"

( cd "$root" && cargo build --release -p hivecomb-py >/dev/null )
site="$("$venv/bin/python" -c 'import site; print(site.getsitepackages()[0])')"
command cp -f "$root/target/release/libhivecomb.so" "$site/hivecomb.so"

exec systemd-run --user --scope -q -p MemoryMax=4G -- \
    taskset -c "$core" "$venv/bin/python" "$here/bench.py" "$@"
