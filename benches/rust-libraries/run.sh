#!/usr/bin/env bash
# Run the Rust-library comparison under the same conditions every time.
#
#   ./run.sh
#
# Pinned to one core so the run cannot migrate mid-window, and under a memory cap so a
# runaway dies alone rather than taking the machine with it. cpuset is not delegated to
# the user slice on every system, so CPU pinning uses taskset (a process attribute,
# needing no delegation) while the memory cap uses a systemd scope, which is delegated.
set -eu
core="${CORE:-14}"
cargo build --release
exec systemd-run --user --scope -q -p MemoryMax=4G -- \
    taskset -c "$core" ./target/release/hivecomb-rust-comparison "$@"
