# hivecomb

Hive blockchain keys, serialization and **offline** transaction signing for Node.js —
a native addon over the [`hivecomb`](https://github.com/flosolcher/hivecomb) Rust
library.

```sh
npm install hivecomb
```

<!-- PRE-RELEASE-NOTICE: delete this block when the first release is published.
     RELEASING.md carries a checklist item for it. -->
> **Not published yet.** This name is reserved for the first release. Until then, build
> from the [repository](https://github.com/flosolcher/hivecomb) — see
> [RELEASING.md](https://github.com/flosolcher/hivecomb/blob/main/RELEASING.md).
<!-- /PRE-RELEASE-NOTICE -->

Prebuilt binaries for linux x64/arm64, macOS x64/arm64 and Windows x64. Node 20+.
TypeScript definitions are included; there is no `@types` package to install.

```js
import { PrivateKey, BlockRef, signTransaction, signMessage } from 'hivecomb'

// Login handshake.
const signature = signMessage('challenge string', postingWif)

// A transaction, signed without touching the network.
const tx = signTransaction(
  [['custom_json', {
    required_posting_auths: ['alice'],
    id: 'my_app',
    json: { hello: 'hive' },
  }]],
  BlockRef.fromBlockId(headBlockId),
  [postingWif],
)
// POST tx to network_broadcast_api.broadcast_transaction
```

## What this is, and is not

It is the **signing and serialization core** — the part that has to be exactly right.
### Staying inside hived's limits

Exceeding a consensus limit gets the **whole transaction** refused, not the offending
operation — so a batch that overflows loses everything sent with it. `signTransaction`
enforces every limit before signing, and `limits()` reports them for callers who need to
stay inside one while *building*:

```js
const { limits } = require('hivecomb')
const cap = limits().maxCustomDataLen        // 8192, inclusive
```

Two are worth reading rather than assuming. `maxCustomDataLen` is **inclusive** — hived's
own error says "must be less than 8192 bytes" over code that is `<=`, so chunking to
"less than 8192" quietly costs a byte. And `maxCustomOpsPerBlock` is per **account per
block**, shared by everything that broadcasts on that account: splitting an oversized
payload into chunks and sending them back to back spends the whole budget in one block,
which is a good way to trade one refusal for another.

### Going straight on the wire

`signTransaction` returns a JavaScript object. If the next thing you do is put it in an
HTTP body — which is usually the case — use `signTransactionJson` instead and skip a
round trip through an object that only exists to be serialized again:

```js
const trx = signTransactionJson(operations, blockRef, [key])
const body = `{"jsonrpc":"2.0","method":"network_broadcast_api.broadcast_transaction",`
           + `"params":{"trx":${trx}},"id":1}`
```

Identical work and identical signed bytes; it just stops at the string. Measured to the
same finish line against dhive 1.3.6 — the body an application would POST — that is
1.50× at one operation against 1.38× for the object form, and it moves the point where
dhive overtakes from about fifteen operations to about forty. See
[COMPARISON.md](../COMPARISON.md).

It is not an RPC client: [`dhive`](https://www.npmjs.com/package/@hiveio/dhive) and
[`hive-js`](https://www.npmjs.com/package/@hiveio/hive-js) already do that well, and
this is designed to sit underneath one of them or beside your own fetch calls.

**Signing never touches the network.** The chain id is a compile-time constant and the
block reference is cached with an explicit staleness bound, so producing a signature is
pure CPU. Fetching a block reference and broadcasting are yours to do, with whatever
HTTP client you already have.

## Why a native addon

The curve arithmetic is [libsecp256k1](https://github.com/bitcoin-core/secp256k1)
through the rust-bitcoin bindings — the same library Bitcoin Core uses, constant-time by
construction. Serialization is the Rust core, verified against **hived itself** --
a node is asked to serialize each of the 48 operations and the digests are
compared, 57/57 identical -- and against beem with a 150-case differential digest
oracle, rather than against its own
expectations.

The addon carries no HTTP client: Node has its own.

## Keys do not render

```js
const key = new PrivateKey(wif)
console.log(key)              // PrivateKey {}
`${key}`                      // '<PrivateKey redacted>'
JSON.stringify({ key })       // '{"key":"<PrivateKey redacted>"}'
key.toWif()                   // the actual WIF, only when you ask by name
```

That is deliberate. Every ordinary way JavaScript turns an object into text is covered
by a test, because a key reaching a log line is the failure mode that costs accounts.

## Stale block references throw

```js
const cache = new TaposCache(180)     // seconds
cache.storeBlockId(headBlockId)       // from a timer, not the signing path
cache.blockRef()                      // throws once past the bound
```

Signing against an expired reference produces a transaction the relay accepts and the
chain later rejects. The cache refuses rather than serving one.

## Operations

All 48 signable operations, including the two that older libraries cannot build at all —
`recurrent_transfer` (with the HF28 `pair_id`) and `collateralized_convert`. Amounts are
integers of the asset's smallest unit throughout, so a VESTS value past 2^53 units
survives, and excess precision is an error rather than a silent truncation.

## API

TypeScript definitions ship with the package. In brief:

| | |
|---|---|
| `PrivateKey` | `fromWif`, `generate`, `fromMnemonic`, `fromPassword`, `fromBrainKey`, `fromBip38`, `publicKey`, `toWif`, `toBip38`, `signMessage` |
| `PublicKey` | `toString`, `toStringWithPrefix`, `toHex`, `equals` |
| `BlockRef` | `fromBlockId`, `fromParts` |
| `TaposCache` | `store`, `storeBlockId`, `blockRef`, `isFresh`, `ageSeconds`, `invalidate` |
| signing | `signMessage`, `verifyMessage`, `recoverMessage` |
| transactions | `signTransaction` (WIF strings or `PrivateKey` instances, or a mix), `signTransactionJson`, `transactionDigest`, `transactionId` |
| protocol limits | `limits()` — hived's consensus bounds, so a caller building a payload reads them rather than restating them |
| memos | `encodeMemo`, `decodeMemo`, `isEncryptedMemo` |
| keys | `generateMnemonic`, `validateMnemonic` |
| authorities | `checkAuthority` |
| chain | `chainId`, `version` |

### `checkAuthority` answers three ways, not two

```js
const report = checkAuthority(account.posting, [pubkey])
report.satisfied    // met from these keys alone
report.conclusive   // false => depends on accounts not looked up
report.unresolvedAccounts
```

An authority can delegate to another account, and following that needs a fetch. Reading
such a case as a plain "no" is wrong for any account that shares posting rights, which
on Hive is most of them.

## How far this is proven

A transaction signed by this core was accepted by the Hive network, into block
[109242605](https://hivehub.dev/tx/ebb44fb5dedd544b7deeb62f81660983233a559f), and
the chain filed it under the transaction id computed offline.

That is a proof, not a track record: one accepted transaction, one operation, no
production exposure. What is and is not established is written down in
[BROADCAST.md](https://github.com/flosolcher/hivecomb/blob/main/BROADCAST.md).

The addon, the Python module and the Rust crate all assert the same pinned digest
vector in their own test suites, so a divergence between the three bindings fails
a test rather than reaching a user.

## Building from source

```sh
npm install
npm run build      # napi build --platform --release
npm test
```

## Licence

MIT. Derived from `beem` by Holger Nahrstaedt and `python-graphenelib` by Fabian Schuh;
see [CREDITS.md](https://github.com/flosolcher/hivecomb/blob/main/CREDITS.md).
