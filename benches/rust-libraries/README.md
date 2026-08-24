# Measuring against the other Rust Hive libraries

```sh
cd benches/rust-libraries
./run.sh
```

Pinned to one core and run under a memory cap, so the numbers are reproducible rather
than whatever the machine felt like. `CORE=n ./run.sh` picks a different core.

This crate is deliberately **outside the workspace**. It depends on
[`hive-xylem`](https://github.com/srbde/hive-xylem),
[`hive-rs`](https://crates.io/crates/hive-rs) and
[`hive_memo`](https://crates.io/crates/hive_memo) purely in order to measure them, and
those have no business in `hivecomb`'s dependency tree, its MSRV job or
`cargo test --workspace`. Same arrangement as `fuzz/`.

## What it checks before it measures anything

All three general-purpose libraries must produce the **same transaction digest** for the
same transaction. That is the value the chain signs, so agreement means the serializers
agree byte for byte. If they disagree the run stops: timing implementations that are not
doing the same work measures nothing.

The memo libraries are asked to read each other's output, and any difference is reported
rather than judged.

## Reading the output

The `spread` column is `(median - minimum) / minimum` across the libraries in that row.
**A difference smaller than the spread is not a difference.**

This machine's CPU has no SHA extensions, so SHA-256 runs in software at roughly
180 MB/s — about 1.9 µs for a 344-byte digest. Every library here pays that identically,
and it is most of what the digest rows measure, which is why they converge as the payload
grows. On a CPU with SHA-NI the same rows would look different for all of them.
