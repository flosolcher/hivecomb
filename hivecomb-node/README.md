# hivecomb

Hive blockchain keys, serialization and **offline** transaction signing for Node.js —
a native addon over the [`hivecomb`](https://github.com/flosolcher/hivecomb) Rust
library.

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
construction. Serialization is the Rust core, verified against a reference
implementation with a differential digest oracle rather than against its own
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
| transactions | `signTransaction`, `transactionDigest`, `transactionId` |
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

## Building from source

```sh
npm install
npm run build      # napi build --platform --release
npm test
```

## Licence

MIT. Derived from `beem` by Holger Nahrstaedt and `python-graphenelib` by Fabian Schuh;
see [CREDITS.md](https://github.com/flosolcher/hivecomb/blob/main/CREDITS.md).
