# Measuring against the other Python Hive libraries

```sh
uv venv --python 3.12 /tmp/pybench
VIRTUAL_ENV=/tmp/pybench uv pip install beem hive-nectar lighthive
VENV=/tmp/pybench ./run.sh
```

Pinned to one core, run under a memory cap, with the extension rebuilt from the working
tree. `CORE=n` picks a different core.

Versions are **read from the installed distributions at run time** and printed with the
results. A table that names a version it did not actually measure is worse than one with
no version at all.

## What it checks before it measures anything

All three libraries must produce the **same transaction digest** for the same
transaction. A mismatch stops the run.

beem is handed the real chain id explicitly, because its own `known_chains["HIVE"]`
carries the pre-hardfork-24 all-zero value; without that it would sign against a chain
that has not existed since 2020 and the comparison would be measuring different work.

## lighthive is named but has no row

`lighthive` serializes by asking a Hive node for the transaction hex
(`condenser_api.get_transaction_hex`) and signs what comes back. It therefore has no
local serializer to measure and does not sign offline at all. That is a deliberate design
— it keeps the library small and defers to the node, which is authoritative about the
wire format — but it puts lighthive on a different axis from the others, so it is named
here rather than given a misleading row.

## Reading the output

The `spread` column is `(median − minimum) / minimum` across the row. **A difference
smaller than the spread is not a difference.**
