# Findings in `beem` 0.24.26

Everything below was read out of the **installed distribution** at
`beem 0.24.26` (site-packages), not from memory or from the upstream repository, so
line numbers refer to what actually ships on PyPI. Each finding names the file, the
line, what the code does, why it matters, and where `comb` addresses it.

`beem` is unmaintained: its trove classifiers stop at `Programming Language :: Python
:: 3.9`, its status is `Development Status :: 4 - Beta`, and its last release was
0.24.26. None of this is a criticism of the authors — the library did its job for
years and this port is derived from their work (see `CREDITS.md`). It is context for
why these defects are still open.

Severity is judged by **what a failure produces**, not by how hard it is to trigger.
A bug that yields a silently-invalid signature ranks above one that raises.

| # | Severity | Area | One line |
|---|---|---|---|
| [1](#1) | Critical | op ids | Missing comma concatenates two operation names, shifting every HF25 id |
| [2](#2) | Critical | op ids | Shipped table cannot encode `recurrent_transfer` / `collateralized_convert`; all virtual ids off by two |
| [3](#3) | High | signing | Silent fall-through to variable-time pure-Python ECDSA (Minerva) |
| [4](#4) | High | signing | Wall-clock time used as ECDSA nonce entropy |
| [5](#5) | High | chain id | Bare `except:` falls back to the pre-HF24 all-zero chain id |
| [6](#6) | High | verify | `ecdsa_verify` result discarded; verification does not verify |
| [7](#7) | High | verify | `Signed_Transaction.verify()` collects all four recovery candidates |
| [8](#8) | High | serialization | `String` mangles control characters into literal text |
| [9](#9) | High | key hygiene | `repr()`/`str()` of a private key return the secret |
| [10](#10) | Medium | base58 | Invalid characters decode to wrong bytes instead of erroring |
| [11](#11) | Medium | base58 | WIF version byte discarded unchecked |
| [12](#12) | Medium | validation | Length checks use bare `assert`, stripped under `python -O` |
| [13](#13) | Medium | key validation | Private scalar never range-checked |
| [14](#14) | Medium | brain keys | Biased word selection, and an index one past the end |
| [15](#15) | Medium | memo | Unauthenticated AES-CBC; padding not validated on unpad |
| [16](#16) | Medium | money | Amounts round-trip through binary `float`; global decimal context mutated |
| [17](#17) | Medium | time | Timezone-aware datetimes read as though UTC |
| [18](#18) | Low | correctness | `is` used to compare integers |
| [19](#19) | Low | dead code | `init_aes` defined three times; broken import path in base class |
| [20](#20) | Low | passwords | Master password stretched with a single unsalted SHA-256 |
| [21](#21) | High | serialization | `flat_set` fields serialized in caller order, not sorted |
| [22](#22) | Critical | operations | `escrow_release` omits `agent` and `receiver`; `escrow_dispute` omits `agent` |
| [23](#23) | High | operations | `custom_binary` serializes 2 of 6 fields, and mistypes `id` |
| [24](#24) | Medium | memo | Encrypted memos omit the varint length prefix the ecosystem writes |
| [25](#25) | High | wallet | Key store uses unsalted SHA-256 and unauthenticated AES-CBC |

---

<a id="1"></a>
## 1. Missing comma silently concatenates two operation names — Critical

**`beembase/operationids.py:13-15`**

```python
    'convert',
    'collateralized_convert'      # <-- no comma
    'account_create',
```

Python concatenates adjacent string literals. The list element is therefore the single
string `'collateralized_convertaccount_create'`. `ops_HF25` contains **neither**
`collateralized_convert` **nor** `account_create`, and because one element replaced
two, **every operation id from index 10 onward is shifted down by one**.

The list is not active by default, but the file invites you to enable it:

```python
operations = {o: ops.index(o) for o in ops}
# uncoment when using with HF25
# operations = {o: ops_HF25.index(o) for o in ops_HF25}
```

Uncommenting that line — which the comment presents as the correct thing to do on
HF25 — makes every transaction serialize under the wrong operation id. The signature
is well-formed; it just authorises a different operation than intended, and the chain
rejects it. A user following the file's own instruction gets silent, total breakage.

**In `comb`:** operation ids are a Rust `enum` with explicit discriminants and an
exhaustive round-trip test against the id list from hived's
`libraries/protocol/include/hive/protocol/operations.hpp`. There is no second list to
fall out of sync.

---

<a id="2"></a>
## 2. The active operation table does not match the chain — Critical

**`beembase/operationids.py:56-131`** (the `ops` list that is actually used)

The shipped table predates HF25 and diverges from hived in three ways:

1. **`recurrent_transfer` (id 49) is absent**, and `collateralized_convert` (id 48) is
   absent. beem simply **cannot build either operation** — `Operation.__init__` raises
   `ValueError("Unknown operation")`. Recurrent transfers have been live since HF25
   (2021).
2. **`ops_HF25` inserts them in the wrong place.** It puts `recurring_transfer` at
   index 3 and `collateralized_convert` at index 10, i.e. in the middle. hived
   *appended* them at 48 and 49; the static variant is append-only precisely because
   inserting renumbers everything after it.
3. **The name is wrong.** hived calls it `recurrent_transfer_operation`; beem spells it
   `recurring_transfer`.

Because the two missing non-virtual ops are absent, **every virtual operation id in
beem is two lower than on chain**. `fill_convert_request` is 50 on chain and 48 in
beem; `producer_reward` is 64 on chain and 62 in beem. Any code using
`getOperationNameForId`, or passing an operation-id bitmask to
`account_history_api.get_account_history`, reads the wrong operations.

**In `comb`:** the full 0–92 table, generated against hived's `operations.hpp`, with
both spellings accepted on input and `recurrent_transfer` used on the wire.

---

<a id="3"></a>
## 3. Silent fall-through to variable-time pure-Python ECDSA — High

**`beemgraphenebase/ecdsasig.py:17-33`**

```python
try:
    import secp256k1prp as secp256k1
    ...
except:                                    # bare except, line 22
    try:
        import secp256k1
    except ImportError:
        try:
            import cryptography
        except ImportError:
            SECP256K1_MODULE = "ecdsa"     # line 33
```

With none of the first three installed, signing runs through the pure-Python `ecdsa`
package: **variable-time scalar multiplication**. That is the primitive behind the
Minerva class of attacks (GHSA-wj6h-64fc-37mp) — signing timings leak bits of the
nonce, and enough leaked nonce bits recover the private key.

Nothing announces the choice beyond a `log.debug`. The only mitigation available to a
downstream project is to install `cryptography` *purely to change an import order*,
with no test able to detect its loss. The `except:` on line 22 is bare, so it also
swallows `KeyboardInterrupt` and `SystemExit`.

**In `comb`:** one backend, libsecp256k1 via the `secp256k1` crate, constant-time by
construction. There is no selection order to get wrong.

---

<a id="4"></a>
## 4. Wall-clock time used as ECDSA nonce entropy — High

**`beemgraphenebase/ecdsasig.py:220-228`**

```python
k = ecdsa.rfc6979.generate_k(
    ..., hashlib.sha256(
        digest +
        struct.pack("d", time.time())  # use the local time to randomize the signature
    ).digest())
```

A `double` of the current time carries a few tens of bits of real entropy at best, and
is partially known to anyone who observed when the transaction was broadcast. Feeding
low-entropy, externally-estimable data into ECDSA nonce derivation is the exact shape
of failure that has repeatedly cost ECDSA users their keys. RFC 6979's whole point is
that the nonce is derived from the private key by HMAC and needs no external
randomness; the extra-entropy field exists for domain separation, not for a clock.

This path is reached only on the pure-Python backend — the same one reached by
[finding 3](#3).

**In `comb`:** RFC 6979 with an incrementing counter in the extra-entropy field, the
same construction libsecp256k1 exposes as `ndata`. Signing is deterministic and
reproducible.

---

<a id="5"></a>
## 5. Bare `except:` falls back to the pre-HF24 chain id — High

**`beem/blockchaininstance.py:493-496`** and **`:749`**, with
**`beemgraphenebase/chains.py:3-13`**

```python
try:
    return self.rpc.get_network(props=config)
except:
    return known_chains["HIVE"]
```

The entry named `"HIVE"` carries `"chain_id": "0" * 64` — the **pre-HF24 all-zero id**.
The live chain id lives under the key `"HIVE2"`
(`beeab0de00000000000000000000000000000000000000000000000000000000`). The rename never
happened because maintenance stopped.

A signature computed over the wrong chain id is invalid. So a node error at exactly
this point does not raise and does not time out — it **silently produces a signature
that cannot be accepted**, which downstream looks like a relay rejection rather than a
signing failure. This is the same silent-fallback shape as finding 3, in the same code
path.

Worth noting: the chain id is a **compile-time constant**. This network call exists
partly to look up something that never changes between hardforks.

**In `comb`:** `chains::HIVE_CHAIN_ID` is a constant; `Chain::from_name("HIVE")`
resolves to the live post-HF24 id; there is no fallback for an unknown chain; and
`ChainId::is_all_zero()` lets a caller refuse the legacy id explicitly.

---

<a id="6"></a>
## 6. `verify_message` discards the verification result — High

**`beemgraphenebase/ecdsasig.py:285-292`**

```python
verifyPub = secp256k1.PublicKey(pub.ecdsa_recover(message, sig))
normalSig = verifyPub.ecdsa_recoverable_convert(sig)
verifyPub.ecdsa_verify(message, normalSig)      # <-- return value dropped
phex = verifyPub.serialize(compressed=True)
return phex
```

`ecdsa_verify` returns a boolean. It is never inspected. Public-key *recovery* succeeds
for essentially any well-formed 65-byte input, so the function returns a
plausible-looking public key regardless of whether the signature is valid, and leaves
every caller to notice on its own.

The damage is bounded only because callers usually compare the returned key against an
expected one — and a recovered key from a bad signature will not match. That is a
property of how it happens to be used, not of the function.

**In `comb`:** `sign::verify` and `sign::recover` return `Result` and error unless the
signature verifies against the digest. There is a regression test that tampers with a
signature and asserts the failure.

---

<a id="7"></a>
## 7. `Signed_Transaction.verify()` collects every recovery candidate — High

**`beemgraphenebase/signedtransactions.py:140-155`**

```python
if p is None:
    for i in range(4):
        try:
            p = verify_message(self.message, bytes(signature), recover_parameter=i)
            phex = hexlify(p).decode('ascii')
            pubKeysFound.append(phex)     # appended for every i that does not raise
        except Exception:
            p = None
```

For a single signature this appends **up to four unrelated public keys** to
`pubKeysFound`, because recovery succeeds for multiple recovery parameters and, per
[finding 6](#6), nothing verifies the result. The function's own docstring —
*"Returned pubkeys have to be checked if they are existing"* — concedes that the
return value cannot be trusted.

Relatedly, `verify(chain=None)` executes a bare `raise` with no active exception, which
raises `RuntimeError: No active exception to reraise` rather than saying the chain
argument is missing.

**In `comb`:** verification recovers exactly one key, verifies it, and compares it. The
recovery id comes from the signature's own header byte, which is range-checked.

---

<a id="8"></a>
## 8. `String` serialization mangles control characters — High

**`beemgraphenebase/types.py:170-186`**

```python
if (o <= 7) or (o == 11) or (o > 13 and o < 32):
    r.append("u%04x" % o)     # line 175 — note: no backslash
elif o == 8:
    r.append("b")             # line 177 — no backslash
elif o == 12:
    r.append("f")             # line 183 — no backslash
```

These branches are missing their escape backslash. A `0x01` byte is serialized as the
four *literal characters* `u0001`, and a backspace as the letter `b`. The varint length
prefix then counts the expanded bytes.

hived does no such thing. A Graphene string is a varint byte length followed by the raw
UTF-8 bytes. So **any `custom_json` payload, memo, comment body or JSON metadata
containing a control character serializes to different bytes in beem than the chain
expects** — the transaction is signed over content that is not what was submitted.

This looks like a Python-2-era escaping hack that lost its backslashes and was never
exercised, because control characters are rare in practice.

**In `comb`:** `types::write_string` writes a varint length and the raw UTF-8 bytes,
with regression tests pinning `\u{1}`, `\u{8}` and `\u{c}` to one byte each.

---

<a id="9"></a>
## 9. A private key renders itself as the secret — High

**`beemgraphenebase/account.py:806-813`**

```python
def __repr__(self):
    return repr(self._wif)          # the raw private scalar, as hex

def __str__(self):
    return format(self._wif, "WIF") # the WIF
```

Every ordinary way of rendering an object discloses the key:

* `print(key)` and `f"{key}"` emit the WIF;
* `log.debug("key=%r", key)` emits the raw scalar;
* any debugger, crash reporter, or test framework that renders local variables — and
  Python tracebacks that include `repr()` of arguments — emits it;
* `PrivateKey` instances inside a list or dict are rendered with `repr()` by default.

For a value that is the entire security of an account, "the default rendering is the
secret" is the wrong default. Python `str` is also immutable and interned, so the key
cannot be wiped from memory even in principle.

**In `comb`:** `Debug` and `Display` for `PrivateKey` both print
`PrivateKey(<redacted>)`. Disclosure requires the explicitly-named `to_wif()` or
`expose_secret()`, both of which return `Zeroizing` wrappers that wipe on drop. Key
bytes never appear in an `Error`. There is a test asserting the rendered form contains
no key material.

---

<a id="10"></a>
## 10. Invalid base58 decodes to wrong bytes instead of erroring — Medium

**`beemgraphenebase/base58.py:104-106`**

```python
n = n * 58 + BASE58_ALPHABET.find(py23_chr(b))
```

`bytes.find` returns **`-1`** when the character is not in the alphabet, and that `-1`
is folded straight into the accumulator. Input containing `0`, `O`, `I`, `l`, or any
other non-alphabet byte therefore **decodes to bytes** rather than raising.

In most paths a checksum catches it afterwards, so the practical effect is a confusing
error rather than a wrong key. But `base58decode` is also called directly —
`bip38.decrypt` (`bip38.py:99`) and `extract_memo_data` (`beembase/memo.py`) both use
it with no checksum verification at all.

**In `comb`:** `base58::decode` rejects any character outside the alphabet, and both
checksum schemes compare in constant time.

---

<a id="11"></a>
## 11. The WIF version byte is discarded without being checked — Medium

**`beemgraphenebase/base58.py:164-173`**

```python
def base58CheckDecode(s, skip_first_bytes=True):
    ...
    if skip_first_bytes:
        return dec[2:]        # line 171 — drops the version byte, never checks it
```

The leading byte is stripped unconditionally. A key encoded under any other version —
a Bitcoin testnet WIF (`0xef`), for example — is accepted as a Hive key.

Compounding this, `Base58.__init__` (`base58.py:40-48`) dispatches on the first
character and handles `K`/`L` (Bitcoin **compressed**-form WIFs) by
`base58CheckDecode(data)[:-2]`, silently discarding the trailing compression flag. So a
compressed-form key is accepted and produces a key for a different address than the
user expects. The dispatch also tests `all(c in string.hexdigits for c in data)` first,
which is vacuously true for the empty string.

**In `comb`:** `base58::decode_check_version` requires the exact version byte;
`PrivateKey::from_wif` requires a leading `5` and rejects `K`/`L` with an error naming
the reason.

---

<a id="12"></a>
## 12. Validation via bare `assert`, removed under `python -O` — Medium

**`beemgraphenebase/types.py:215, 221, 227`** and **`account.py:738`**

```python
class Sha256(Hash):
    def __init__(self, a):
        assert len(a) == 64, "Require 64 char long hex"
...
class PrivateKey(Prefix):
    def __init__(self, wif=None, prefix=None):
        ...
        assert len(repr(self._wif)) == 64
```

Python's `-O` flag strips `assert` statements entirely. Any deployment that runs with
`-O` or `PYTHONOPTIMIZE=1` — a common production setting — loses the **only** length
check on a private key and on every fixed-width hash field. Serialization then produces
a short or long field with no complaint.

(The explicit `raise AssertionError()` calls elsewhere in `base58.py` are *not*
affected by `-O`; only the `assert` statement form is.)

**In `comb`:** all validation is ordinary checked control flow returning `Result`.
Rust has no equivalent of `-O` stripping.

---

<a id="13"></a>
## 13. The private scalar is never range-checked — Medium

**`beemgraphenebase/account.py:726-738`**

`PrivateKey.__init__` checks only that the hex is 64 characters. It never checks that
the scalar lies in `[1, n-1]`, the valid range for a secp256k1 secret. Zero, `n`
itself, and any value above `n` are all accepted. `PrivateKey(None)` generates from
`os.urandom(32)` with the same absence of validation.

On the libsecp256k1 backend the failure surfaces later as an opaque error; on the
pure-Python backend the arithmetic proceeds and produces a key that does not correspond
to the intended point.

**In `comb`:** `PrivateKey::from_bytes` constructs a `secp256k1::SecretKey`, which
enforces the range, and tests pin the rejection of zero, of the curve order, and of
all-`0xff`.

---

<a id="14"></a>
## 14. Brain-key word selection is biased and can index out of range — Medium

**`beemgraphenebase/account.py:154-163`**

```python
urand = os.urandom(2)
num = int.from_bytes(urand, byteorder="little")   # 0 .. 65535
rndMult = num / 2 ** 16                           # float in [0, 1)
wIdx = int(round(len(dict_lines) * rndMult))      # 0 .. 49744  <-- line 162
brainkey[j] = dict_lines[wIdx]
```

Three defects compound:

1. **Scaling bias.** 65536 equiprobable draws map onto 49744 words. Since 65536 is not
   a multiple of 49744, some words are reachable from two source values and others from
   one — roughly a 2:1 probability ratio across the dictionary.
2. **Half-width end buckets.** `round()` sends only `[0, 0.5)` to index 0 and only
   `[n-0.5, n)` to the last index, so the extreme words are half as likely as the rest.
3. **Out-of-range index.** `round(49744 * rndMult)` can return `49744`, one past the
   end — an `IndexError` roughly once per 130k words drawn.

The cost of (1) and (2) is entropy. A uniform draw from 49744 words is 15.60 bits, so a
16-word brain key should carry ~249.6 bits; the biased draw carries measurably less.
For a value that is the sole backup of an account, advertised entropy that the
generator does not deliver is the wrong direction to err in.

**In `comb`:** `BrainKey::suggest` uses `OsRng` with rejection sampling, so selection
is exactly uniform, and refuses fewer than 12 words.

---

<a id="15"></a>
## 15. Encrypted memos are unauthenticated, and unpad fails open — Medium

**`beembase/memo.py`**

* `encode_memo` / `decode_memo` use **AES-CBC with no MAC**. The 4-byte `check` field
  is a checksum **of the derived key**, not of the ciphertext — it detects the wrong
  key, not a modified message. Ciphertext is malleable, and the decrypt path is a
  textbook padding-oracle shape.
* `_unpad` **returns the input unchanged when the padding is invalid** rather than
  raising:

  ```python
  def _unpad(s, BS):
      count = s[-1]
      if s[-count::] == count * struct.pack("B", count):
          return s[:-count]
      return s          # <-- silently returns padded data as plaintext
  ```

* `init_aes` is **defined three times in the same module**; the last definition wins
  and the first two are dead. See [finding 19](#19).
* The nonce is caller-supplied. Reusing one with the same key pair repeats both key and
  IV, which for CBC leaks plaintext relationships.
* A comment in `decode_memo` concedes an unfixed bug: `# remove the varint prefix
  (FIXME, long messages!)`.

This is the memo format Hive defines, so `comb` must remain wire-compatible. What it
can do is fail closed.

**In `comb`:** padding is validated and a bad pad is an error; the nonce is generated
from the OS CSPRNG unless explicitly supplied; the key checksum is compared in constant
time; and the API documents plainly that Hive memo encryption provides confidentiality
but **not** integrity.

---

<a id="16"></a>
## 16. Amounts round-trip through binary `float`, and mutate global state — Medium

**`beembase/objects.py:24-26`**

```python
def value_to_decimal(value, decimal_places):
    decimal.getcontext().rounding = decimal.ROUND_DOWN     # line 25
    return decimal.Decimal(str(float(value))).quantize(...)  # line 26
```

Two problems in two lines:

1. **`float(value)`** converts a monetary amount to an IEEE-754 double before it
   reaches `Decimal`. Passing through binary floating point is exactly what `Decimal`
   exists to avoid, and it is being done to a value denominated in money.
2. **`decimal.getcontext().rounding = ...`** mutates the **process-global** decimal
   context as a side effect of formatting an amount. Every unrelated `Decimal`
   operation in the host application silently switches to `ROUND_DOWN` from then on.
   For an application that does its own financial arithmetic, that is a defect
   injected into code that never called beem.

### This is reachable, and it was measured

Running both implementations over the same inputs (`tests/differential_beem.py`):

| amount | beem units | correct units | error |
|---|---|---|---|
| `1.234 HIVE` | 1234 | 1234 | — |
| `98765432.109 HIVE` | 98765432109 | 98765432109 | — |
| `9007199254740.993 HIVE` | 9007199254740992 | 9007199254740993 | −1 |
| `50000000000.123456 VESTS` | 50000000000123460 | 50000000000123456 | +4 |
| `123456789012.345678 VESTS` | 123456789012345670 | 123456789012345678 | −8 |

Everyday amounts are unaffected: the error appears once the value exceeds a double's
53-bit mantissa, i.e. **2^53 = 9,007,199,254,740,992 smallest units**.

For HIVE and HBD (3 decimals) that threshold is ~9.007 trillion, which the supply does
not reach. **For VESTS (6 decimals) it is 9,007,199,254 VESTS** — roughly 4.9 million
HP at typical ratios. Hive's largest accounts hold more than that, so
`delegate_vesting_shares`, `withdraw_vesting` and `transfer_to_vesting` on a large
account can silently serialize a different amount than was requested. The transaction
is signed over the wrong number.

**In `comb`:** amounts are integers of the asset's smallest unit throughout — the same
representation the chain uses — parsed from decimal strings without any float step. All
five rows above are exact.

---

<a id="17"></a>
## 17. Timezone-aware datetimes are read as though UTC — Medium

**`beemgraphenebase/types.py:270-278`**

```python
if isinstance(self.data, datetime):
    unixtime = timegm(self.data.timetuple())     # line 274
elif ...:
    unixtime = timegm(time.strptime((self.data + "UTC"), timeformat))
```

`timetuple()` discards the timezone, and `timegm` then interprets the remaining
wall-clock fields as UTC. A timezone-aware `datetime` in, say, `Europe/Berlin` is read
two hours off, shifting the transaction's `expiration` by the UTC offset. In the string
branch the literal text `"UTC"` is appended to the input so that `%Z` has something to
match — fragile, and locale-dependent.

An expiration that is silently early expires the transaction; one that is silently late
is rejected for exceeding the chain's maximum expiration window.

**In `comb`:** `types::PointInTime` holds `u32` seconds since the Unix epoch, parses
strictly, accepts a trailing `Z`, and **rejects** any other offset rather than guessing.

---

<a id="18"></a>
## 18. `is` used to compare integers — Low

**`beemgraphenebase/objects.py:61`**, and identically in `beembase/objects.py` and
`beembase/operationids.py`:

```python
if int(self.operations()[key]) is int(i):
```

`is` is identity, not equality. This works only because CPython interns small integers
(−5 to 256) — an implementation detail, not a language guarantee. Operation ids happen
to stay under 256 today. It also emits a `SyntaxWarning` on modern Python.

**In `comb`:** operation ids are an `enum`; the comparison is exhaustive matching.

---

<a id="19"></a>
## 19. Dead code and a broken import path — Low

* **`beembase/memo.py`** defines `init_aes` **three times**. The first two are
  unreachable. The first and third differ in their key-derivation construction, so
  which one is live is not obvious to a reader.
* **`beemgraphenebase/objects.py:66`**:
  ```python
  module = __import__("graphenebase.operations", fromlist=["operations"])
  ```
  The package is named `beemgraphenebase`, not `graphenebase`. The base-class method is
  broken and only works because `beembase.objects.Operation` overrides it. Anyone using
  the graphene base classes directly gets an `ImportError` surfaced as
  `NotImplementedError("Unimplemented Operation ...")`, which names the wrong cause.
* **`beemgraphenebase/objects.py:88-92`**: `GrapheneObject.__bytes__` appends a raw
  `str` field as UTF-8 with **no varint length prefix**, unlike every other field type.
  Any raw string reaching `data` corrupts the serialization silently.

---

<a id="20"></a>
## 20. Master passwords get a single unsalted SHA-256 — Low (protocol-inherent)

**`beemgraphenebase/account.py:50-62`**

```python
seed = self.account + self.role + self.password
s = hashlib.sha256(py23_bytes(seed, 'utf8')).digest()
return PrivateKey(hexlify(s).decode('ascii'), ...)
```

One unsalted, unstretched SHA-256 over a human-chosen password, with the account name
as the only salt-like input. No work factor. An attacker holding an account's public
key can test password guesses at raw SHA-256 speed — billions per second on commodity
hardware.

This is **Hive's scheme**, not beem's invention, and cannot be changed without breaking
compatibility. It is listed because it is a real property of any key derived this way
and deserves to be visible.

**In `comb`:** the derivation is reproduced exactly, but `PasswordKey::new` takes a
required `i_understand_this_is_unstretched: bool` argument, so choosing it is explicit
at the call site, and the module documentation states the cost plainly.

---

<a id="21"></a>
## 21. `flat_set` fields are serialized in caller order — High

**`beembase/operations.py`**, `Custom_json` and `Custom`

```python
('required_auths', Array([String(o) for o in kwargs["required_auths"]])),
('required_posting_auths', Array([String(o) for o in kwargs["required_posting_auths"]])),
```

hived declares both of these as `flat_set<account_name_type>` — an **ordered, unique**
container. That matters for signing, because of how hived validates:

1. It deserializes the transaction. `fc`'s `unpack` for `flat_set` inserts each element,
   so the set comes out **sorted** regardless of the order on the wire.
2. It computes `sig_digest` by **re-serializing** that in-memory object.
3. It checks the signature against that digest.

So a transaction whose auth list arrives unsorted is re-serialized sorted, producing a
digest that differs from the one the client signed. **The signature does not verify and
the transaction is rejected** — with no indication that ordering was the problem.

beem passes the caller's order straight through, with no sort and no dedup. Any
`custom_json` with more than one entry in either auth list is therefore at the mercy of
whatever order the caller happened to build the list in.

This was found by the differential harness rather than by reading: 26 of 134 corpus
cases diverged, and every one of them was an unsorted auth list.

**In `comb`:** `write_sorted_account_set` sorts and rejects duplicates, and the same is
done for `proposal_ids` (also a `flat_set`) and for authority key/account maps
(`flat_map` — see `authority.rs`, where beem additionally sorted keys by their
**ripemd160 address** rather than by the serialized key). Tests assert that input order
does not change the output bytes.

---

<a id="22"></a>
## 22. The escrow operations are missing fields — Critical

**`beembase/operations.py`**, `Escrow_release` and `Escrow_dispute`

hived declares:

```cpp
struct escrow_release_operation {
   account_name_type from, to, agent, who, receiver;
   uint32_t          escrow_id;
   asset             hbd_amount, hive_amount;
};
struct escrow_dispute_operation {
   account_name_type from, to, agent, who;
   uint32_t          escrow_id;
};
```

beem serializes:

| operation | hived fields | beem fields | omitted |
|---|---|---|---|
| `escrow_release` | from, to, **agent**, who, **receiver**, escrow_id, hbd_amount, hive_amount | from, to, who, escrow_id, hbd_amount, hive_amount | **`agent`, `receiver`** |
| `escrow_dispute` | from, to, **agent**, who, escrow_id | from, to, who, escrow_id | **`agent`** |

Graphene serialization is positional — no names, no padding — so an omitted field does
not produce a short record with a gap. **Every subsequent field shifts left.** hived
reads `who` where `agent` should be, `escrow_id` where `receiver` should be, and then
runs off the end of the buffer or reads an asset out of whatever follows.

For `escrow_release` the omitted `receiver` is *the field that says who the funds go
to*. There is no interpretation of the resulting bytes under which the operation means
what the caller asked for.

`Escrow_transfer` and `Escrow_approve` are correct, which is what makes this
particularly easy to miss: two of the four escrow operations are right.

**In `comb`:** all eight and all five fields respectively, with tests asserting the
serialized length and that `agent` actually appears in the bytes.

---

<a id="23"></a>
## 23. `custom_binary` serializes two of its six fields — High

**`beembase/operations.py`**, `Custom_binary`

```python
super(Custom_binary, self).__init__(OrderedDict([
    ('id', Uint16(int(kwargs["id"]))),
    ('data', String(kwargs["data"])),
]))
```

hived declares six members:

```cpp
struct custom_binary_operation {
   flat_set<account_name_type> required_owner_auths;
   flat_set<account_name_type> required_active_auths;
   flat_set<account_name_type> required_posting_auths;
   vector<authority>           required_auths;
   custom_id_type              id;      // a string
   vector<char>                data;
};
```

Two problems compound. The three auth sets and the authority vector are missing
entirely, so nothing declares who must sign. And `id` is a `custom_id_type` — a
**string** — while beem writes a `uint16`, which is what `custom_operation` (a
different operation) uses.

The output cannot be deserialized as a `custom_binary_operation` under any reading.

**In `comb`:** all six fields, with the three `flat_set` members sorted and
deduplicated per [finding 21](#21), and `id` length-checked against
`custom_id_type`'s 32-byte limit.

---

<a id="24"></a>
## 24. Encrypted memos omit the varint length prefix — Medium

**`beembase/memo.py`**, `encode_memo` and `decode_memo`

Every reference implementation — `hive-js`, `dhive`, Hive Keychain, HiveSigner —
encrypts the memo as a **Graphene string**: a varint byte length followed by the UTF-8
bytes. From `hive-js/src/auth/memo.js`:

```javascript
const mbuf = new ByteBuffer(ByteBuffer.DEFAULT_CAPACITY, ByteBuffer.LITTLE_ENDIAN)
mbuf.writeVString(memo)          // <- varint length prefix
memo = new Buffer(mbuf.copy(0, mbuf.offset).toBinary(), 'binary')
```

beem's `encode_memo` does not write it:

```python
raw = py23_bytes(message, "utf8")
raw = _pad(raw, 16)              # no prefix
```

while its `decode_memo` *does* try to strip one, with a heuristic its own comment flags
as broken:

```python
# remove the varint prefix (FIXME, long messages!)
n = varintdecode(message)
if (len(message) - n) > 0 and (len(message) - n) < 8:
    return '#' + message[len(message) - n:].decode("utf8")
```

So beem encodes in one format and decodes in another.

### Measured

Most messages survive, because both beem's heuristic and hive-js's `try readVString /
catch → raw` fallback happen to fire. The failure is a message whose **first byte, read
as a varint, equals the length of the rest** — then the prefix is indistinguishable from
data, and the leading byte is consumed as a length:

| message | beem → beem | beem → comb | comb → comb |
|---|---|---|---|
| `"\x05hello"` | `"hello"` | `"hello"` | `"\x05hello"` |
| `"\x03abc"` | `"abc"` | `"abc"` | `"\x03abc"` |
| `"\x01z"` | `"z"` | `"z"` | `"\x01z"` |
| `"\x0bhello world"` | `"hello world"` | `"hello world"` | `"\x0bhello world"` |

beem loses the byte **against its own encoder**, and so does every other client.

**In `comb`:** the prefix is written, as the ecosystem does, so the length is
unambiguous. [`memo::decode`] also accepts memos with no prefix, so anything beem
produced can still be read.

Note the residual ambiguity is inherent: a beem-written memo that begins with a
length-like byte cannot be told apart from a correctly-prefixed one. `comb` resolves it
the way every other client does, which means such a memo decodes the same way in `comb`
as it does in Keychain — consistent, even where it is not what beem's author intended.

---

<a id="25"></a>
## 25. The wallet encrypts keys with an unsalted SHA-256 and no MAC — High

**`beemgraphenebase/aes.py`**, used by **`beemstorage/masterpassword.py`** and
**`beemstorage/base.py`**

beem stores private keys encrypted under a random master password, which is itself
encrypted under the user's passphrase with `AESCipher`. That class is:

```python
class AESCipher(object):
    def __init__(self, key):
        self.bs = 32
        self.key = hashlib.sha256(AESCipher.str_to_bytes(key)).digest()

    def encrypt(self, raw):
        raw = self._pad(AESCipher.str_to_bytes(raw))
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw)).decode('utf-8')
```

Three problems, all in the same six lines:

1. **No key derivation function.** The encryption key is one SHA-256 of the passphrase
   — no iterations, no memory hardness, no work factor of any kind. An attacker holding
   the wallet file tests candidate passphrases at raw SHA-256 speed, which on commodity
   GPU hardware is billions per second.
2. **No salt.** Two users who choose the same passphrase get byte-identical encryption
   keys. One precomputed table therefore attacks every beem wallet in existence
   simultaneously, and a passphrase cracked once is cracked everywhere.
3. **No authentication.** AES-CBC with no MAC. Nothing detects a modified wallet file,
   and `_unpad` — like the memo one in [finding 15](#15) — does not validate its
   padding. The decrypt path is a padding-oracle shape.

For a file whose entire purpose is to hold private keys at rest, all three matter. The
IV is random, which is the one thing done right.

**In `comb`:** `wallet::Wallet` uses **scrypt** (`N = 2^15, r = 8, p = 1`, random
16-byte salt per wallet) to derive the key, and **AES-256-GCM** for every ciphertext, so
a tampered file fails authentication rather than decrypting to something. The file is
written to a temporary path and renamed, so an interrupted write cannot truncate a key
store, and is `0600` on Unix.

There is deliberately **no reader for beem's format**. Supporting it would mean shipping
the weak construction in order to read files this crate should be helping people leave.
Migrate with `beempy listkeys` / `beempy getkey` and `Wallet::add_key`.

---

## Not defects, but reasons this port exists

* **`beem` cannot sign without a node.** `blockchaininstance.py:496-549` calls
  `get_config` to fetch chain parameters. One of the two things signing needs from the
  network is a compile-time constant ([finding 5](#5)); the other, the block reference,
  is cacheable for far longer than a submit window. Putting a network round-trip in the
  signing path is what makes signing fail when nodes are slow.
* **The dependency tree is the oldest thing in the path** — `ecdsa`, `scrypt`,
  `pycryptodomex`, `websocket-client`, all pinned in shape by an unmaintained package
  that holds the posting key.
* **No support for post-HF25 operations** — see [finding 2](#2).

## Verification against beem

`tests/differential_beem.py` runs both implementations over a generated corpus and
compares `sha256(chain_id || serialized_tx)` byte for byte. Current result:

```
digest corpus     : 134 cases
  identical       : 108
  known divergence: 26  (comb is deliberately correct here)
  UNEXPECTED      : 0
public key        : match
cross-verification: ok
```

The 26 divergences are findings [16](#16) and [21](#21) — the cases where beem produces
bytes hived will not accept. Everything else is byte-identical, which is the evidence
that the port did not introduce serialization drift of its own.

Signature **byte**-equality is deliberately not the gate: any canonical signature is
valid, the chain does not care which one it gets, and beem's several backends need not
converge on the same one. What is asserted instead is that each implementation accepts
the other's signatures, and that public key derivation agrees exactly.

The corpus is a floor, not a ceiling. It covers varint boundaries (payloads past 1- and
2-byte length prefixes), `int16` boundaries, multi-byte UTF-8, empty and maximum-length
`custom_json` ids, unsorted and duplicated auth sets, and amounts on both sides of the
`2**53` threshold. Extend it rather than trusting it.

## Method and limits

Findings were read from the installed source. Findings 1, 2, 8, 10, 11, 12, 13, 14, 18
and 19 are mechanically verifiable from the code alone and are covered by regression
tests in `comb`. Findings 22 and 23 are field-by-field
comparisons against hived's `hive_operations.hpp` and are covered by regression tests.
Findings **16 and 21 were confirmed empirically** by running both
implementations against each other, with the measurements shown above. Findings 3, 4,
5, 6, 7, 9, 15, 17 and 20 are correct as descriptions of the code; whether each has
actually caused a failure in production is **not established here** — several of them
fail silently by construction, which is precisely why they are worth fixing rather than
waiting to observe.

No attempt was made to audit `beem/cli.py` (5198 lines), the storage layer, or the
higher-level `Account`/`Comment`/`Market` wrappers, none of which are on a signing
path.
