import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { test } from 'node:test'
import { inspect } from 'node:util'

import {
  PrivateKey, PublicKey, BlockRef, TaposCache,
  signMessage, verifyMessage, recoverMessage,
  signTransaction, signTransactionJson, transactionDigest, transactionId,
  encodeMemo, decodeMemo, isEncryptedMemo,
  generateMnemonic, validateMnemonic, checkAuthority, chainId, version, limits,
} from '../index.js'

// A fixed test key, published on purpose. Checked against
// account_by_key_api.get_key_references on 2026-08-22: no Hive account uses it.
// It must never hold value.
const WIF = '5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3'
const PUB = 'STM6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV'
const BOB_WIF = '5J4KCbg1G3my9b9hCaQXnHSm6vrwW9xQTJS6ZciW2Kek7cCkCEk'
const BLOCK_ID = '00000005aabbccdd00000000000000000000abcd'

// --------------------------------------------------------------------------
// Keys
// --------------------------------------------------------------------------

test('derives the public key from a WIF', () => {
  const key = new PrivateKey(WIF)
  assert.equal(key.publicKey().toString(), PUB)
  assert.equal(key.toWif(), WIF)
  assert.equal(PrivateKey.fromWif(WIF).publicKey().toString(), PUB)
})

test('a private key never renders its secret', () => {
  const key = new PrivateKey(WIF)
  // Every ordinary way JavaScript turns an object into text.
  const renderings = [
    String(key),
    `${key}`,
    key.toString(),
    JSON.stringify(key),
    JSON.stringify({ key }),
    inspect(key),
    inspect({ key }, { depth: 5 }),
  ]
  for (const text of renderings) {
    assert.ok(!text.includes(WIF), `leaked the WIF via: ${text}`)
    assert.ok(!text.includes('5KQwr'), `leaked a WIF prefix via: ${text}`)
  }
  assert.equal(key.toString(), '<PrivateKey redacted>')
  // toJSON must be spelled exactly that way or JSON.stringify ignores it.
  assert.equal(key.toJSON(), '<PrivateKey redacted>')
})

test('rejects a corrupted WIF rather than accepting it', () => {
  const last = WIF.slice(-1)
  const bad = WIF.slice(0, -1) + (last === 'a' ? 'b' : 'a')
  assert.throws(() => new PrivateKey(bad))
})

test('generates distinct keys', () => {
  assert.notEqual(PrivateKey.generate().toWif(), PrivateKey.generate().toWif())
})

test('public keys parse, render and compare', () => {
  const a = new PublicKey(PUB)
  assert.equal(a.toString(), PUB)
  assert.equal(a.toStringWithPrefix('STM'), PUB)
  assert.equal(a.toHex().length, 66)
  assert.ok(a.equals(new PrivateKey(WIF).publicKey()))
  assert.ok(!a.equals(PrivateKey.generate().publicKey()))
  assert.throws(() => new PublicKey('not a key'))
})

// --------------------------------------------------------------------------
// Signing
// --------------------------------------------------------------------------

test('signs and verifies a message', () => {
  const sig = signMessage('hello hive', WIF)
  assert.equal(sig.length, 130)
  assert.equal(recoverMessage('hello hive', sig).toString(), PUB)
  assert.equal(verifyMessage('hello hive', sig, new PublicKey(PUB)), true)
  assert.equal(verifyMessage('a different message', sig, new PublicKey(PUB)), false)
})

test('accepts a Buffer as well as a string', () => {
  assert.equal(signMessage(Buffer.from('bytes input'), WIF), signMessage('bytes input', WIF))
})

test('signing is deterministic', () => {
  assert.equal(signMessage('repeatable', WIF), signMessage('repeatable', WIF))
})

// --------------------------------------------------------------------------
// Transactions
// --------------------------------------------------------------------------

test('signs a transaction offline', () => {
  const ref = BlockRef.fromBlockId(BLOCK_ID)
  const tx = signTransaction(
    [['custom_json', {
      required_auths: [],
      required_posting_auths: ['alice'],
      id: 'my_app',
      json: { hello: 'hive' },
    }]],
    ref, [WIF],
  )
  assert.equal(tx.operations[0][0], 'custom_json')
  // A JS object for `json` is serialized compactly, because the string is signed.
  assert.equal(tx.operations[0][1].json, '{"hello":"hive"}')
  assert.equal(tx.signatures.length, 1)
  assert.equal(tx.trx_id.length, 40)
  assert.equal(tx.ref_block_num, ref.refBlockNum)
})

test('builds the operations beem cannot', () => {
  const ref = BlockRef.fromBlockId(BLOCK_ID)
  const tx = signTransaction(
    [['recurrent_transfer', {
      from: 'alice', to: 'bob', amount: '1.000 HIVE', memo: 'rent',
      recurrence: 24, executions: 12,
      extensions: [[1, { pair_id: 3 }]],
    }]],
    ref, [WIF],
  )
  const name = tx.operations[0][0]
  const fields = tx.operations[0][1]
  assert.equal(name, 'recurrent_transfer')
  // Object form, not [[1, {...}]]: hived rejects the array form for this
  // extension, so a transaction carrying it cannot be broadcast at all.
  assert.deepEqual(fields.extensions, [
    { type: 'recurrent_transfer_pair_id', value: { pair_id: 3 } },
  ])

  const conv = signTransaction(
    [['collateralized_convert', { owner: 'alice', requestid: 1, amount: '1.000 HIVE' }]],
    ref, [WIF],
  )
  assert.equal(conv.operations[0][0], 'collateralized_convert')
})

test('amounts past 2**53 units survive', () => {
  const tx = signTransaction(
    [['delegate_vesting_shares', {
      delegator: 'alice', delegatee: 'bob', vesting_shares: '50000000000.123456 VESTS',
    }]],
    BlockRef.fromBlockId(BLOCK_ID), [WIF],
  )
  assert.equal(tx.operations[0][1].vesting_shares, '50000000000.123456 VESTS')
})

test('refuses excess precision rather than truncating', () => {
  assert.throws(() => signTransaction(
    [['transfer', { from: 'a', to: 'b', amount: '1.2345 HIVE', memo: '' }]],
    BlockRef.fromBlockId(BLOCK_ID), [WIF],
  ), /precision|decimal/)
})

test('refuses unknown fields and empty operation lists', () => {
  const ref = BlockRef.fromBlockId(BLOCK_ID)
  assert.throws(() => signTransaction(
    [['custom_json', { required_posting_auths: ['a'], id: 'x', json: '{}', typo: 1 }]],
    ref, [WIF],
  ))
  assert.throws(() => signTransaction([], ref, [WIF]), /at least one operation/)
})

test('cross-binding vector: same digest as the Rust and Python suites', () => {
  // Pinned in all three test suites. Each asserts it independently, so a drift in
  // any one binding is caught without needing all three runtimes in one place.
  const ref = BlockRef.fromBlockId('00000005aabbccdd00000000000000000000abcd')
  const ops = [['custom_json', {
    required_auths: [], required_posting_auths: ['alice'],
    id: 'my_app', json: '{"a":1}',
  }]]
  assert.equal(
    transactionDigest(ops, ref, '2026-08-22T14:30:00').toString('hex'),
    'cef35a5b34e7ee9297de5153b363668245793c8ba719762ccacdde9fd85ad3d6',
  )
  assert.equal(
    transactionId(ops, ref, '2026-08-22T14:30:00'),
    '8e4d2bb0d665a855512abf702c2b8e1ad9f6719e',
  )
})

test('digest and id are computable without signing', () => {
  const ref = BlockRef.fromBlockId(BLOCK_ID)
  const ops = [['vote', { voter: 'a', author: 'b', permlink: 'p', weight: 10000 }]]
  const digest = transactionDigest(ops, ref, '2026-08-22T14:30:00')
  assert.equal(digest.length, 32)
  assert.equal(transactionId(ops, ref, '2026-08-22T14:30:00').length, 40)
})

// --------------------------------------------------------------------------
// TaPoS
// --------------------------------------------------------------------------

test('a stale block reference is refused, not served', async () => {
  // A one-second bound, so both transitions are observable. With a zero bound it
  // would be stale the instant it was stored, which is correct but proves less.
  const cache = new TaposCache(1)
  cache.storeBlockId(BLOCK_ID)
  assert.equal(cache.isFresh(), true, 'fresh immediately after storing')
  assert.equal(cache.blockRef().refBlockNum, 5)

  await new Promise((resolve) => setTimeout(resolve, 1200))
  assert.equal(cache.isFresh(), false, 'stale once past the bound')
  assert.throws(() => cache.blockRef(), /stale/i)
})

test('a zero bound means every read is stale', () => {
  const cache = new TaposCache(0)
  cache.storeBlockId(BLOCK_ID)
  assert.equal(cache.isFresh(), false)
  assert.throws(() => cache.blockRef(), /stale/i)
})

test('an empty cache refuses rather than guessing', () => {
  const cache = new TaposCache()
  assert.equal(cache.isFresh(), false)
  assert.equal(cache.ageSeconds(), null)
  assert.throws(() => cache.blockRef())
})

// --------------------------------------------------------------------------
// Memos
// --------------------------------------------------------------------------

test('memos round-trip from either side', () => {
  const bobPub = new PrivateKey(BOB_WIF).publicKey().toString()
  const memo = encodeMemo(WIF, bobPub, 'Hello Hive memo')
  assert.ok(memo.startsWith('#'))
  assert.ok(isEncryptedMemo(memo))
  assert.equal(decodeMemo(BOB_WIF, memo), 'Hello Hive memo')
  assert.equal(decodeMemo(WIF, memo), 'Hello Hive memo')
})

test('short memos survive, which is what the varint prefix is for', () => {
  const bobPub = new PrivateKey(BOB_WIF).publicKey().toString()
  for (const message of ['hello', 'abc', 'z', '']) {
    const memo = encodeMemo(WIF, bobPub, message)
    assert.equal(decodeMemo(BOB_WIF, memo), message)
  }
})

test('a fixed nonce makes a memo reproducible', () => {
  const bobPub = new PrivateKey(BOB_WIF).publicKey().toString()
  const a = encodeMemo(WIF, bobPub, 'same', 1234n)
  const b = encodeMemo(WIF, bobPub, 'same', 1234n)
  assert.equal(a, b)
  assert.notEqual(a, encodeMemo(WIF, bobPub, 'same'))
})

test('the wrong key cannot read a memo', () => {
  const bobPub = new PrivateKey(BOB_WIF).publicKey().toString()
  const memo = encodeMemo(WIF, bobPub, 'secret')
  assert.throws(() => decodeMemo(PrivateKey.generate().toWif(), memo))
})

// --------------------------------------------------------------------------
// Mnemonics and BIP-38
// --------------------------------------------------------------------------

test('generates and validates a mnemonic, and derives role keys', () => {
  const phrase = generateMnemonic(128)
  assert.equal(phrase.split(' ').length, 12)
  assert.equal(validateMnemonic(phrase), true)
  assert.equal(validateMnemonic('not a valid mnemonic at all thank you very much'), false)

  const posting = PrivateKey.fromMnemonic(phrase, 'posting', 0)
  const active = PrivateKey.fromMnemonic(phrase, 'active', 0)
  assert.notEqual(posting.toWif(), active.toWif())
  assert.equal(PrivateKey.fromMnemonic(phrase, 'posting', 0).toWif(), posting.toWif())
})

test('bip38 round-trips, and matches the pinned vector', () => {
  const encrypted = new PrivateKey(WIF).toBip38('correct horse battery staple')
  assert.equal(encrypted, '6PRWaUZmruY6rjNSJZ8G9yzdeU72VZmLgxMjADM7wuDaYknZCjot2JNmAc')
  assert.equal(PrivateKey.fromBip38(encrypted, 'correct horse battery staple').toWif(), WIF)
  assert.throws(() => PrivateKey.fromBip38(encrypted, 'wrong passphrase'))
})

// --------------------------------------------------------------------------
// Authorities
// --------------------------------------------------------------------------

test('reports authority weight, not just yes or no', () => {
  const a = new PrivateKey(WIF).publicKey().toString()
  const b = PrivateKey.generate().publicKey().toString()
  const authority = { weight_threshold: 2, account_auths: [], key_auths: [[a, 1], [b, 1]] }

  const one = checkAuthority(authority, [a])
  assert.equal(one.satisfied, false)
  assert.equal(one.weight, 1)
  assert.equal(one.shortfall, 1)
  assert.equal(one.conclusive, true, 'no delegations, so this is a real no')

  const both = checkAuthority(authority, [a, b])
  assert.equal(both.satisfied, true)
  assert.equal(both.shortfall, 0)
})

test('a delegated authority is inconclusive, not a plain no', () => {
  const a = new PrivateKey(WIF).publicKey().toString()
  const authority = { weight_threshold: 1, account_auths: [['bot', 1]], key_auths: [[a, 1]] }
  const stranger = checkAuthority(authority, [PrivateKey.generate().publicKey().toString()])
  assert.equal(stranger.satisfied, false)
  assert.equal(stranger.conclusive, false)
  assert.deepEqual(stranger.unresolvedAccounts, ['bot'])
})

// --------------------------------------------------------------------------
// Chain
// --------------------------------------------------------------------------

test('the chain id is a local constant, not a lookup', () => {
  assert.equal(chainId(), 'beeab0de' + '00'.repeat(28))
  assert.notEqual(chainId('TESTNET'), chainId())
  assert.throws(() => chainId('NOPE'))
})

test('reports its version', () => {
  assert.match(version(), /^\d+\.\d+\.\d+$/)
})

// --- signTransactionJson ----------------------------------------------------
// Same work and the same signed bytes as signTransaction, handed back as JSON text
// because a signed transaction's destination is almost always an HTTP body. The
// risk in having two entry points is that they drift, so these compare them.

test('signTransactionJson returns text that parses to the same transaction', () => {
  const ops = [['custom_json', {
    required_auths: [], required_posting_auths: ['alice'],
    id: 'my_app', json: '{"a":1}',
  }]]
  const ref = BlockRef.fromBlockId(BLOCK_ID)

  const text = signTransactionJson(ops, ref, [WIF], 600)
  assert.equal(typeof text, 'string', 'it must return text, not an object')
  const parsed = JSON.parse(text)
  const object = signTransaction(ops, ref, [WIF], 600)

  // Expiration is relative to now, so the two calls can land a second apart.
  // Everything else must be identical, signatures included: the digest is the
  // same whenever the expiration matches, and RFC-6979 makes signing
  // deterministic, so a difference here means the two paths built different
  // transactions.
  if (parsed.expiration === object.expiration) {
    assert.deepEqual(parsed, object, 'the two entry points disagree')
  } else {
    parsed.expiration = object.expiration
    parsed.signatures = object.signatures
    parsed.trx_id = object.trx_id
    assert.deepEqual(parsed, object, 'the two entry points disagree beyond the expiration')
  }

  assert.equal(parsed.signatures.length, 1)
  assert.match(parsed.signatures[0], /^[0-9a-f]{130}$/)
  assert.equal(parsed.ref_block_num, 5)
  assert.deepEqual(parsed.extensions, [])
})

test('signTransactionJson output splices into a broadcast envelope', () => {
  // The reason the string form exists: it goes straight into a request body.
  const ref = BlockRef.fromBlockId(BLOCK_ID)
  const trx = signTransactionJson(
    [['transfer', { from: 'alice', to: 'bob', amount: '1.234 HIVE', memo: 'hi' }]],
    ref, [WIF], 600,
  )
  const body = `{"jsonrpc":"2.0","method":"network_broadcast_api.broadcast_transaction","params":{"trx":${trx}},"id":1}`
  const decoded = JSON.parse(body)
  assert.equal(decoded.params.trx.operations[0][0], 'transfer')
  assert.equal(decoded.params.trx.operations[0][1].amount, '1.234 HIVE')
})

test('signTransactionJson normalises an object json field, as the object form does', () => {
  // The signature covers the *string* form of a json field. If the text form echoed
  // the caller's object back, the transaction would not match what was signed.
  const ref = BlockRef.fromBlockId(BLOCK_ID)
  const ops = [['comment', {
    parent_author: '', parent_permlink: 'hive-100', author: 'alice', permlink: 'p',
    title: 't', body: 'b', json_metadata: { tags: ['a', 'b'] },
  }]]
  const parsed = JSON.parse(signTransactionJson(ops, ref, [WIF], 600))
  assert.equal(typeof parsed.operations[0][1].json_metadata, 'string',
    'an object json_metadata must come back as the signed string')
  assert.equal(parsed.operations[0][1].json_metadata, '{"tags":["a","b"]}')
})

test('signTransactionJson accepts a pre-stringified operations array', () => {
  const ref = BlockRef.fromBlockId(BLOCK_ID)
  const ops = [['vote', { voter: 'alice', author: 'bob', permlink: 'p', weight: 10000 }]]
  const a = JSON.parse(signTransactionJson(ops, ref, [WIF], 600))
  const b = JSON.parse(signTransactionJson(JSON.stringify(ops), ref, [WIF], 600))
  assert.deepEqual(a.operations, b.operations)
})

test('signTransactionJson refuses what signTransaction refuses', () => {
  const ref = BlockRef.fromBlockId(BLOCK_ID)
  for (const bad of [[], [['not_an_operation', {}]], [['vote', { voter: 'alice' }]]]) {
    assert.throws(() => signTransactionJson(bad, ref, [WIF], 600),
      undefined, `signTransactionJson accepted ${inspect(bad)}`)
    assert.throws(() => signTransaction(bad, ref, [WIF], 600),
      undefined, `signTransaction accepted ${inspect(bad)}`)
  }
})

// --- protocol limits ----------------------------------------------------------
// Exported so a JS caller building a payload reads them rather than restating them.
// The addon enforces every one before signing; these are for staying inside a limit
// while constructing, which is where a caller would otherwise hard-code a number.

test('limits() reports hived\'s protocol bounds', () => {
  const l = limits()
  assert.equal(l.maxCustomDataLen, 8192, 'inclusive: hived is <=, despite its message')
  assert.equal(l.maxCustomOpsPerBlock, 5)
  assert.equal(l.maxCustomIdLen, 32)
  assert.equal(l.maxMemoLen, 2047)
  assert.equal(l.maxTitleLen, 255)
  assert.equal(l.maxPermlinkLen, 255)
  assert.equal(l.maxAuthorityMembership, 40)
  assert.equal(l.maxBeneficiaries, 127)
  assert.equal(l.maxProposalSubjectLen, 80)
  assert.equal(l.maxProposalIds, 5)
  assert.equal(l.maxWitnessUrlLen, 2048)
})

test('the limits reported are the limits enforced', () => {
  // The point of exporting them: a caller that chunks to `maxCustomDataLen` must not
  // then be refused by the signer. If these two ever disagree the export is worse than
  // useless, because it would be actively misleading.
  const l = limits()
  const ref = BlockRef.fromBlockId(BLOCK_ID)
  const op = (n) => [['custom_json', {
    required_auths: [], required_posting_auths: ['alice'],
    id: 'my_app', json: 'x'.repeat(n),
  }]]

  assert.doesNotThrow(() => signTransaction(op(l.maxCustomDataLen), ref, [WIF], 600),
    'exactly the reported limit must sign')
  assert.throws(() => signTransaction(op(l.maxCustomDataLen + 1), ref, [WIF], 600),
    undefined, 'one past it must not')

  const many = Array.from({ length: l.maxCustomOpsPerBlock + 1 }, () => op(4)[0])
  assert.throws(() => signTransaction(many, ref, [WIF], 600),
    undefined, 'one past the per-block budget must not sign')
})

// --- key redaction, every path -------------------------------------------------
// The module documentation claims console.log, template literals and JSON.stringify
// cannot leak a key. Two of those go through toString/toJSON, which are overridden.
// `util.inspect` -- which is what console.log actually uses for an object -- does NOT
// call toString on a class instance, so it is safe here only because napi exposes no
// fields to JavaScript. That is safety by construction, and a single getter added later
// would undo it silently. Hence this.

test('no path renders a private key', () => {
  const key = new PrivateKey(WIF)
  const shown = [
    String(key),
    `${key}`,
    JSON.stringify(key),
    JSON.stringify({ key }),
    inspect(key),
    inspect(key, { depth: null, showHidden: true }),
    JSON.stringify(Object.keys(key)),
    JSON.stringify(Object.entries(key)),
  ]
  for (const out of shown) {
    assert.ok(!String(out).includes(WIF), `a key leaked: ${out}`)
    // Twenty characters is far short of the whole WIF and still unrecoverable-from,
    // but a partial leak is a leak and would show a redaction that only half works.
    assert.ok(!String(out).includes(WIF.slice(0, 20)), `part of a key leaked: ${out}`)
  }
  assert.equal(inspect(key), 'PrivateKey {}', 'inspect must expose no fields')
})

test('the addon surfaces errors rather than panicking', () => {
  // A panic crossing napi aborts the process rather than raising, so every fallible
  // path has to return a JS Error. These are the inputs most likely to find one.
  const ref = BlockRef.fromBlockId(BLOCK_ID)
  const bad = [
    () => new PrivateKey(''),
    () => new PrivateKey('not-a-wif'),
    () => BlockRef.fromBlockId('zz'),
    () => transactionDigest('not json', ref, '2026-01-01T00:00:00'),
    () => transactionDigest([], ref, '2026-01-01T00:00:00'),
    () => signTransaction([['vote', {}]], ref, [WIF], 600),
    () => signTransaction([['custom_json', { id: 'x' }]], ref, [WIF], 600),
  ]
  for (const fn of bad) {
    assert.throws(fn, (e) => e instanceof Error, 'must throw a JS Error, not abort')
  }
})

// --- the TypeScript definitions describe the real module ------------------------
// index.d.ts is generated by napi, so it starts correct and can drift if anything is
// added by hand or a build is stale. The Python side has had this check for a while and
// caught twelve constants that were exported and stubbed nowhere; Node had no
// equivalent, which is the asymmetry this closes.

test('index.d.ts declares everything the module exports', async () => {
  const here = dirname(fileURLToPath(import.meta.url))
  const dts = readFileSync(join(here, '../index.d.ts'), 'utf8')
  const mod = await import('../index.js')

  const declared = new Set(
    [
      ...dts.matchAll(/^export declare (?:function|const) (\w+)/gm),
      ...dts.matchAll(/^export declare class (\w+)/gm),
      ...dts.matchAll(/^export (?:interface|type) (\w+)/gm),
    ].map((m) => m[1]),
  )
  // `default` and `module.exports` are Node's own CJS-to-ESM interop, not exports of
  // this addon: importing a CommonJS module gives its `module.exports` object under both
  // names. `module.exports` appeared in the namespace in Node 24 and is absent in 22, so
  // filtering only `default` made this test pass on one supported version and fail on
  // the other -- while the addon exported exactly the same thing on both.
  const INTEROP = new Set(['default', 'module.exports'])
  const runtime = Object.keys(mod).filter((n) => !INTEROP.has(n) && !n.startsWith('_'))

  const undeclared = runtime.filter((n) => !declared.has(n))
  assert.deepEqual(undeclared, [], 'exported at runtime but absent from index.d.ts')

  // Interfaces describe the shape of returned objects and are not runtime values, so
  // they are expected to appear only in the definitions. Anything else declared but not
  // exported would be a definition promising something that does not exist.
  const interfaces = new Set(
    [...dts.matchAll(/^export interface (\w+)/gm)].map((m) => m[1]),
  )
  const phantom = [...declared].filter((n) => !runtime.includes(n) && !interfaces.has(n))
  assert.deepEqual(phantom, [], 'declared in index.d.ts but not exported at runtime')
})
