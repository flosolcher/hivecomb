<!-- Written for the question "is a posting transaction sufficient, and should I fund
     a throwaway account?" The short answer is yes and no respectively; the reasoning
     is below because it changed once hived turned out to be usable as an oracle. -->

# Validating against the real chain

`hivecomb` can be checked against the Hive network in two stages. The first costs
nothing, needs no account and writes nothing to the chain, and it covers most of the
risk. The second needs one account and one transaction, and covers the rest.

---

## Stage 1 — serialization, proven for free

`condenser_api.get_transaction_hex` makes a node serialize a transaction and hand back
the bytes. That is the authority: not beem, not a fixture, not this project's own
expectations. Comparing `sha256(chain_id || hived's bytes)` against the digest
`hivecomb` computed independently proves the wire format matches, because a single
differing byte changes the hash.

```
PYTHONPATH=<dir with hivecomb.so> python3 tests/hived_serialization_oracle.py
```

57 cases, one per signable operation plus awkward values where they matter. No account,
no keys with value, no broadcast.

**This found four real defects that 292 unit tests and a 134-case differential oracle
against beem had all missed:**

| defect | why the existing tests could not see it |
|---|---|
| `escrow_transfer` field order — amounts before `escrow_id`/`agent`, `json_meta` before the deadlines | round-trip tests wrote and read with the same wrong order |
| `limit_order_create2` — `exchange_rate` precedes `fill_or_kill` | same |
| `recurrent_transfer` `pair_id` is `uint8_t`, written here as `u16` | the beem corpus never reached this operation |
| that extension's JSON must be `{"type","value"}`; hived refuses `[1, {…}]` outright | the binary form was right; only the node objects |

and it overturned a fifth thing, in the other direction — see
[finding 8](SECURITY_FINDINGS.md#8), which claimed beem mangles control characters and
was exactly backwards, so `hivecomb` had "fixed" something that was never broken and
broke itself doing it.

All four defects would have produced transactions the chain refuses, and so would the
control-character handling. None were detectable without asking hived.

---

## Stage 2 — the signature, which needs one real broadcast

Stage 1 proves hived and `hivecomb` agree on the bytes. It does not prove hived accepts
a *signature* over the digest of those bytes. Nothing offline can, because that is the
one step where the chain's answer is the only answer.

### Is a posting-authority transaction sufficient?

**Yes.** The authority level changes which key signs and nothing else. The digest is
`sha256(chain_id || tx)` either way, the signature is the same canonical 65-byte compact
form either way, and TaPoS, expiration and the broadcast envelope are identical. A
posting-authority `custom_json` exercises every step that could be wrong.

It used to be true that a posting-only test left `Amount` serialization untested, since
a `custom_json` carries no asset. That was the one argument for also sending a
`transfer`. Stage 1 removes it: assets are now verified against hived directly, in eight
separate cases including HBD, VESTS and a value past 2⁵³ units.

So posting authority is not a compromise. It is the correct choice, because it is the
lowest-privilege key that proves the same thing.

### Should the account be funded?

**No.** A `custom_json` costs no HIVE — only resource credits, which every account has.
Sending HIVE or Hive-Engine tokens to a validation account adds nothing to the proof and
adds something to lose.

Hive-Engine is worth a separate note, since it looks like it needs funding: a
Hive-Engine token transfer *is* a `custom_json` with id `ssc-mainnet-hive`. Hive's job
ends when it accepts that operation, which is exactly what stage 2 already tests. What
tokens would additionally exercise is Hive-Engine's sidechain — someone else's software,
not this library.

### Which keys should exist anywhere near this

Only the **posting** key of a throwaway account.

Posting authority cannot move funds, cannot change keys and cannot recover the account.
The worst case if it leaks is unwanted posts and votes under a name that exists for this
one purpose. An active or owner key has no such ceiling, and there is no reason for
either to be in an environment variable, a `.env`, a shell history or a transcript.

`.env`, `.env.*`, `*.wif` and `wallet.json` are in `.gitignore`. That is a backstop, not
a plan — this repository is intended to be public, and git history keeps what you delete.

`tests/hived_broadcast_check.py` refuses to run if the key it is given turns out to be
the account's active or owner key, so a mis-paste fails closed rather than broadcasting.

### Where the key goes

In a file containing nothing but the WIF, mode 600, **outside this repository**.

```bash
( umask 077; read -rs KEY && printf '%s' "$KEY" > ~/.hivecomb-posting-key )
```

That prompts on a blank line: paste the key and press Enter. `read -rs` does not
echo it, so it never reaches the terminal, the scrollback or shell history, and
`umask 077` creates the file mode 600. The script refuses to read a key file that
any other user can read.

Outside the repository rather than in it, because `.gitignore` is a backstop and a
path that is not in the working tree cannot be committed by a typo at all.

Prefer this to an environment variable. `HIVE_POSTING_WIF` still works for a
throwaway shell, but an env var is inherited by every child process, is routinely
captured by crash reporters, and outlives the command it was meant for.

Never paste a key into a chat, an issue, a commit message or a terminal command
that will be recorded. Use `read -rs`, or an editor, and nothing else.

### Running it

```bash
export HIVE_ACCOUNT=yourthrowaway

# The node verifies the signature without anything being broadcast.
PYTHONPATH=<dir> python3 tests/hived_broadcast_check.py \
    --key-file ~/.hivecomb-posting-key --dry-run

# The real thing: broadcast, wait for inclusion, compare transaction ids.
PYTHONPATH=<dir> python3 tests/hived_broadcast_check.py \
    --key-file ~/.hivecomb-posting-key
```

The script prints the *public* key it derives, so you can confirm which key was
used. It never prints, logs or copies the private one.

`--dry-run` calls `database_api.verify_authority`, which has the node check the signature
against the account's declared authority and return a verdict — without writing to the
chain. If that returns `true`, the signature is valid by the chain's own reckoning. It is
most of stage 2 with none of the consequences, and it is worth running first.

The full run then broadcasts, waits for a block to include the transaction, and asserts
that the transaction id the chain filed it under equals the one `hivecomb` computed
offline. That equality is the proof: the chain derived the same id from the same bytes.

The `custom_json` it sends carries the id `hivecomb_validation`, which no application
consumes, so nothing downstream acts on it.

---

## What is still not proven after both stages

Honest limits, since the point of this document is to say what is actually established:

- **One operation, not 48.** Stage 2 proves the signature path with a `custom_json`.
  Stage 1 proves the *bytes* of every operation, so the combination is strong, but no
  single broadcast proves that all 48 operations are individually accepted.
- **Acceptance is not correctness of intent.** The chain checks that a transaction is
  well-formed, authorized and unexpired. It does not check that the operation does what
  the caller meant.
- **Nothing here is production exposure.** Passing both stages means the library agrees
  with hived. It does not mean the library has been run in anger. See
  [COMPARISON.md](COMPARISON.md), which says the same thing about maturity.
