# Measuring against the other Node Hive libraries

```sh
cd benches/node-libraries
npm install
./run.sh
```

Pinned to one core and run under a memory cap. `CORE=n ./run.sh` picks a different core.
The addon is rebuilt first, so the numbers are always for the working tree rather than
whatever was built last.

Versions are **read from the installed packages at run time** and printed with the
results. A table that names a version it did not actually measure is worse than one with
no version at all, so the harness never takes a version on trust.

## What it checks before it measures anything

Every library that can produce a transaction digest must produce the **same** one. That
is the value the chain signs, so agreement means the serializers agree byte for byte. A
mismatch stops the run.

`@hiveio/hive-js` exposes no digest entry point, so it is checked the only way it can
be: the signature it produces is recovered under a different library and must yield the
right public key.

## Reading the output

The `spread` column is `(median − minimum) / minimum` across the row. **A difference
smaller than the spread is not a difference.**

The signing rows differ mostly by how each library obtains secp256k1, which is a
deliberate trade rather than a quality difference — `hive-tx` has no runtime dependencies
at all so that it runs unchanged in browsers, workers and serverless runtimes, and
`hive-pollen` uses audited pure-JavaScript crypto. A library that chooses portability
over a native binding pays for it in a microbenchmark, and that is the choice working as
intended.
