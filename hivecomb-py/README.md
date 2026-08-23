# hivecomb

Hive blockchain keys, serialization and **offline** transaction signing. A Python
extension module written in Rust.

```sh
pip install hivecomb
```

<!-- PRE-RELEASE-NOTICE: delete this block when the first release is published.
     RELEASING.md carries a checklist item for it. -->
> **Not published yet.** This name is reserved for the first release. Until then, build
> from the [repository](https://github.com/flosolcher/hivecomb) — see
> [RELEASING.md](https://github.com/flosolcher/hivecomb/blob/main/RELEASING.md).
<!-- /PRE-RELEASE-NOTICE -->

Wheels are `abi3`, so one per platform covers CPython 3.8 and up. No Python
dependencies — where `beem` pulled in `requests`, `websocket-client`, `Click`,
`click-shell`, `pycryptodomex` and `prettytable`, this pulls in nothing.

**Replacing beem in an existing program?** Install
[`hivecomb-beem`](https://pypi.org/project/hivecomb-beem/) instead and keep writing
`import beem`. This package is the layer underneath it.

---

## Signing needs no network

A transaction needs exactly two things from outside itself: the chain id, which is a
compile-time constant, and a recent block reference, which stays valid far longer than
any submit window. So the signing key never has to live on a machine that talks to a
node.

```python
import hivecomb

# The only input from the chain. From any node, or carried across an air gap.
ref = hivecomb.BlockRef.from_block_id(head_block_id)

tx = hivecomb.sign_transaction(
    [("custom_json", {
        "required_auths": [],
        "required_posting_auths": ["alice"],
        "id": "my_app",
        "json": {"hello": "hive"},
    })],
    ref,
    [posting_wif],
)
# tx is the exact envelope condenser_api.broadcast_transaction wants
```

`sign_transaction` takes `(operations, block_ref, wifs)` and returns a dict with
`ref_block_num`, `ref_block_prefix`, `expiration`, `operations`, `extensions`,
`signatures` and `trx_id`. Pass `expiration_seconds=` to change the default 60s window,
and `chain=` to sign for a testnet.

## API

### Keys

```python
key = hivecomb.PrivateKey(wif)                    # WIF or 64-char hex
key = hivecomb.PrivateKey.generate()              # from the OS CSPRNG
key = hivecomb.PrivateKey.from_login("alice", "posting", master_password)

key.public_key()          # -> PublicKey
str(key.public_key())     # 'STM8...'
repr(key)                 # '<PrivateKey redacted>' — never the secret
```

A private key is redacted in `repr()`, `str()` and f-strings, so it cannot reach a log
line or a crash report by accident. `beem` returned the raw scalar from `__repr__`.

BIP-39 mnemonics: `generate_mnemonic(words=12)`, `validate_mnemonic(phrase)`.

### Messages

```python
sig = hivecomb.sign_message("login challenge", wif)   # hex, same shape as beem's
hivecomb.verify_message("login challenge", sig, str(pubkey))   # -> bool
hivecomb.recover_message("login challenge", sig)               # -> the signing key
```

`verify_message` returns a bool that you must check. `beem`'s equivalent computed the
answer and discarded it.

### Memos

```python
cipher = hivecomb.encode_memo("hello", sender_memo_wif, recipient_memo_pubkey)
plain  = hivecomb.decode_memo(cipher, recipient_memo_wif)
hivecomb.is_encrypted_memo(cipher)     # leading '#'
```

Interoperable with Keychain, hive-js, dhive and beem: the plaintext carries the varint
length prefix the rest of the ecosystem writes.

### Authorities

```python
check = hivecomb.check_authority(account["posting"], [str(pubkey)])
check["satisfied"]            # met from these keys alone
check["conclusive"]           # False => depends on accounts not looked up
check["unresolved_accounts"]  # the delegations not followed
```

The three-way answer matters: most active Hive accounts share posting rights with an
app account, and "not from these keys alone" is not the same as "no".

### Block references and TaPoS

```python
ref = hivecomb.BlockRef.from_block_id(head_block_id)

cache = hivecomb.TaposCache(max_age_seconds=600)   # refresh out of band
cache.store_block_id(head_block_id)
ref = cache.block_ref()                            # raises once stale
```

### Wallet

```python
w = hivecomb.Wallet(path)
w.create(passphrase); w.unlock(passphrase)
w.add_key(wif); w.get_key(str(pubkey))
```

scrypt for the key derivation, AES-256-GCM for the contents — authenticated, so a
tampered file fails to open rather than decrypting to garbage.

### Hive-Engine and other sidechains

A Hive-Engine operation is a `custom_json`, so signing one needs nothing this library
does not already do:

```python
tx = hivecomb.sign_transaction(
    [("custom_json", {
        "required_auths": ["alice"],        # see the note below
        "required_posting_auths": [],
        "id": "ssc-mainnet-hive",
        "json": {
            "contractName": "tokens",
            "contractAction": "transfer",
            "contractPayload": {
                "symbol": "BEE",
                "to": "bob",
                "quantity": "1.234",        # a decimal string, never a float
                "memo": "",
            },
        },
    })],
    ref, [active_wif],
)
```

Two things are easy to get wrong, and neither is something Hive will tell you about.

**The authority depends on the contract action, and Hive does not check it.** hived sees
a `custom_json` and validates whatever authority you declared; the *sidechain* then
decides which list it reads. Declare the wrong one and the transaction is accepted by
Hive and quietly does nothing on Hive-Engine — no error, no rejection, just a no-op you
paid resource credits for. Most actions (tokens, market, marketpools) want
`required_auths`; several NFT actions want `required_posting_auths`. Take the split from
a library that tracks the sidechain — [nectarengine](https://github.com/srbde/nectarengine)
is the current one — rather than guessing.

**Quantities are decimal strings at the token's precision.** Not floats. `1.1` as a
double is `1.100000000000000088…`, and rounding that down to a token's precision can
land one unit low. The token's precision comes from a Hive-Engine API call, which this
library does not make.

`hivecomb` deliberately ships no Hive-Engine client. It is a separate chain with its own
nodes and its own contract schema, on its own release schedule — the same reason there
is no HAF client. What it does is sign the `custom_json` correctly, which is the part
where a mistake costs you money.

### Types, and why you should still check at runtime

The wheel ships `py.typed` and `__init__.pyi`, so a type checker resolves the module
fully rather than as `Any`.

**Stubs are not a substitute for a runtime capability check, and it is worth being
precise about why.** They are checked against whatever is on the path at type-check
time; a capability check runs against the `.so` that is actually loaded. The failure
they cannot catch is a **stale installed build** — source updated, package not
reinstalled — where the checker is perfectly happy and the loaded module is old. An
integrator hit exactly that state while upgrading and reported it.

So bind to `__all__`, which is declared explicitly and is identical however the package
was installed:

```python
REQUIRED = {"sign_transaction", "transaction_digest", "chain_id", "TaposCache"}
missing = REQUIRED - set(hivecomb.__all__)
if missing:
    raise RuntimeError(f"hivecomb is missing {missing}; is the installed build stale?")
```

Not `dir()`: Python binds a submodule on its parent at import, so a wheel-installed
package also has `hivecomb.hivecomb` in `dir()` where a bare `.so` does not. That
difference is an artifact of packaging, not of version, and it is exactly the sort of
thing a capability tuple should not trip over.

`__version__` is available too, but it tells you what the source claimed, not what is
loaded — which is the question worth asking.

## Things worth knowing

- **Amounts are exact.** `"50000000000.123456 VESTS"` is parsed as a decimal, never
  through a float. beem's `float()` path loses digits past 2⁵³ units.
- **Timestamps are UTC**, parsed strictly. hived's "never" sentinel — printed as
  `1969-12-31T23:59:59` — reads as `None` rather than a date in 1969.
- **`custom_json` auth lists are sorted**, because hived declares them `flat_set` and
  reconstructs them sorted before checking the signature. An unsorted list yields a
  signature the chain will not accept.
- **Every post-HF25 operation is available**, including `recurrent_transfer` with the
  HF28 `pair_id`, `collateralized_convert` and the DHF proposal operations.

## How this is verified

- **Against hived itself** — a node is asked to serialize each of the 48 operations and
  the digests are compared. 57/57 identical.
- **Against beem** — 150-case differential digest corpus, 0 unexpected divergences.
- **On the live chain** — a transaction signed by this library was accepted into block
  [109242605](https://hivehub.dev/tx/ebb44fb5dedd544b7deeb62f81660983233a559f).

One accepted transaction is a proof, not a track record. What is and is not established
is written down in
[BROADCAST.md](https://github.com/flosolcher/hivecomb/blob/main/BROADCAST.md).

## Credit

A reimplementation of [`beem`](https://github.com/holgern/beem) by Holger Nahrstaedt,
which descends from `python-bitshares` and `python-graphenelib` by Fabian Schuh. The
protocol knowledge is theirs. See
[CREDITS.md](https://github.com/flosolcher/hivecomb/blob/main/CREDITS.md).

MIT.
