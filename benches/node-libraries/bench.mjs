// hivecomb against every other Node Hive library, on identical work.
//
//     ./run.sh
//
// The documentation used to carry timings for one Node library. Publishing a partial
// set is not a fair way to present a comparison whatever the intent, so this measures
// all of them. These are real projects solving the same problem, most of them published
// and in use while this one is not; the numbers are here so a reader can judge for
// themselves rather than as a verdict on anyone's work.
//
// # What is checked before anything is timed
//
// Every library that can produce a transaction digest must produce the *same* one. That
// is the value the chain signs, so agreement means the serializers agree byte for byte.
// A mismatch stops the run: timing implementations that are not doing the same work
// measures nothing.
//
// # Method
//
// Minimum of interleaved windows — each library gets a window in turn rather than all of
// one library's windows and then the next, because this machine's governor ramps the
// clock during a run and whoever went first would be measured cold. The payload varies
// every iteration. Pinned to one core under a memory cap; see run.sh.
//
// The `spread` column is (median − minimum) / minimum across the libraries in that row.
// A difference smaller than the spread is not a difference.

import { createRequire } from 'node:module'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const require = createRequire(import.meta.url)
const here = dirname(fileURLToPath(import.meta.url))

const hivecomb = require(join(here, '../../hivecomb-node/index.js'))
const dhive = require('@hiveio/dhive')
const hiveTx = await import('hive-tx')
const pollen = await import('hive-pollen')
const hiveJs = require('@hiveio/hive-js')

// Versions are read from the installed packages, never written by hand: a table that
// names a version it did not actually measure is worse than one with no version at all.
// Read straight out of node_modules rather than through require.resolve: some packages
// do not expose ./package.json in their "exports" map, and a version that cannot be read
// must fail loudly rather than quietly become "unknown".
const pkgVersion = (name) =>
  JSON.parse(readFileSync(join(here, 'node_modules', name, 'package.json'), 'utf8')).version
const VERSIONS = {
  hivecomb: JSON.parse(readFileSync(join(here, '../../hivecomb-node/package.json'), 'utf8')).version,
  '@hiveio/dhive': pkgVersion('@hiveio/dhive'),
  'hive-tx': pkgVersion('hive-tx'),
  'hive-pollen': pkgVersion('hive-pollen'),
  '@hiveio/hive-js': pkgVersion('@hiveio/hive-js'),
}

const WIF = '5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3'
const NUM = 5
const PREFIX = 0xaabbccdd >>> 0
const EXPIRATION = '2026-01-01T00:00:00'

const ops = (n, i) =>
  Array.from({ length: n }, (_, k) => [
    'custom_json',
    {
      required_auths: [],
      // A distinct account per operation. hived allows five custom operations per
      // *account* per block and refuses the whole transaction beyond that, so ten
      // for one account is not a transaction any node would accept.
      required_posting_auths: [`alice${k}`],
      id: 'my_app',
      json: JSON.stringify({ n: i, k, items: [1, 2, 3, 4, 5], tag: 'x'.repeat(20) }),
    },
  ])

const trx = (n, i) => ({
  ref_block_num: NUM,
  ref_block_prefix: PREFIX,
  expiration: EXPIRATION,
  operations: ops(n, i),
  extensions: [],
})

const ref = hivecomb.BlockRef.fromParts(NUM, PREFIX)
const dhiveKey = dhive.PrivateKey.fromString(WIF)
const pollenKey = pollen.PrivateKey.fromString(WIF)
const hiveTxKey = hiveTx.PrivateKey.from(WIF)
const combKey = new hivecomb.PrivateKey(WIF)

// --- the libraries, in the idiom each one asks for -------------------------

const digesters = {
  hivecomb: (n, i) => hivecomb.transactionDigest(JSON.stringify(ops(n, i)), ref, EXPIRATION),
  '@hiveio/dhive': (n, i) => dhive.cryptoUtils.transactionDigest(trx(n, i)),
  'hive-tx': (n, i) => {
    const t = new hiveTx.Transaction({ transaction: { ...trx(n, i), signatures: [] } })
    return t.digest().digest
  },
  'hive-pollen': (n, i) => pollen.cryptoUtils.transactionDigest(trx(n, i)),
}

const signers = {
  hivecomb: (n, i) => hivecomb.signTransactionJson(JSON.stringify(ops(n, i)), ref, [combKey], 600),
  '@hiveio/dhive': (n, i) => dhive.cryptoUtils.signTransaction(trx(n, i), [dhiveKey]),
  'hive-tx': (n, i) => {
    const t = new hiveTx.Transaction({ transaction: { ...trx(n, i), signatures: [] } })
    return t.sign(hiveTxKey)
  },
  'hive-pollen': (n, i) => pollen.cryptoUtils.signTransaction(trx(n, i), [pollenKey]),
  // hive-js signs through its auth module and exposes no digest entry point, so it
  // appears in the signing rows only rather than being left out entirely.
  '@hiveio/hive-js': (n, i) => hiveJs.auth.signTransaction(trx(n, i), [WIF]),
}

// --- gate ------------------------------------------------------------------

console.log('hivecomb against the other Node Hive libraries\n')
console.log('  measured versions')
for (const [name, v] of Object.entries(VERSIONS)) console.log(`    ${name.padEnd(18)} ${v}`)

console.log('\n  gate: identical transaction, identical digest?')
let agreed = true
for (const n of [1, 10]) {
  const seen = Object.entries(digesters).map(([name, f]) => [name, Buffer.from(f(n, 7)).toString('hex')])
  const first = seen[0][1]
  const ok = seen.every(([, d]) => d === first)
  agreed &&= ok
  console.log(`    ${String(n).padStart(3)} operation(s): ${ok ? 'MATCH  ' : 'DIFFER '} ${first.slice(0, 24)}`)
  if (!ok) for (const [name, d] of seen) console.log(`        ${name.padEnd(18)} ${d}`)
}
if (!agreed) {
  console.error('\nThe libraries do not agree on what to sign. Nothing was timed:')
  console.error('a benchmark of implementations that disagree measures nothing.')
  process.exit(1)
}

// hive-js has no digest entry point, so it is checked the only way it can be: the
// signature it produces must recover the right key, under a different library.
{
  const signed = signers['@hiveio/hive-js'](1, 7)
  const digest = digesters.hivecomb(1, 7)
  const recovered = dhive.Signature.fromString(signed.signatures[0]).recover(digest).toString()
  const expected = dhiveKey.createPublic().toString()
  console.log(
    `  gate: hive-js signature recovers the right key: ${recovered === expected ? 'yes' : 'NO'}`,
  )
  if (recovered !== expected) {
    console.error('\nhive-js is signing something other than this digest. Nothing was timed.')
    process.exit(1)
  }
}

// --- timing ----------------------------------------------------------------

const stats = (samples) => {
  const s = [...samples].sort((a, b) => a - b)
  const best = s[0]
  return { best, spread: best > 0 ? (s[(s.length / 2) | 0] - best) / best : 0 }
}

// Windows are time-boxed rather than fixed-iteration. The libraries here span three
// orders of magnitude — a pure-JavaScript signer takes ~130 ms where a native one takes
// ~70 us — and any single iteration count either finishes instantly for one or runs for
// hours for another. Equal wall-clock per window, with the fast ones simply completing
// more iterations, is the only way to interleave them fairly.
function benchAll(warmMs, windowMs, windows, cases) {
  const names = Object.keys(cases)
  const elapsedMs = (from) => Number(process.hrtime.bigint() - from) / 1e6

  for (const name of names) {
    const started = process.hrtime.bigint()
    let i = 0
    // At least one call, so a library slower than the whole warmup budget still runs.
    do cases[name](i++)
    while (elapsedMs(started) < warmMs)
  }

  const samples = Object.fromEntries(names.map((n) => [n, []]))
  for (let w = 0; w < windows; w++) {
    for (const name of names) {
      const t = process.hrtime.bigint()
      let n = 0
      do cases[name](n++)
      while (elapsedMs(t) < windowMs)
      samples[name].push((elapsedMs(t) * 1000) / n)
    }
  }
  return Object.fromEntries(names.map((n) => [n, stats(samples[n])]))
}

const NAMES = ['hivecomb', '@hiveio/dhive', 'hive-tx', 'hive-pollen', '@hiveio/hive-js']

const SHORT = NAMES.map((n) => n.replace('@hiveio/', ''))
const WIDTH = 12

function report(label, results) {
  const spread = Math.max(...Object.values(results).map((r) => r.spread))
  const cells = NAMES.map((n) =>
    (results[n] ? results[n].best.toFixed(2) : '—').padStart(WIDTH),
  )
  console.log(`  ${label.padEnd(28)}${cells.join('')}  ${(spread * 100).toFixed(0).padStart(5)}%`)
}

console.log('\n  ' + 'microseconds'.padEnd(28) + SHORT.map((n) => n.padStart(WIDTH)).join('') + '  spread')
console.log('  ' + '-'.repeat(28 + NAMES.length * WIDTH + 8))

for (const [n, label] of [
  [1, 'serialize + digest, 1 op'],
  [10, 'serialize + digest, 10 ops'],
]) {
  const cases = Object.fromEntries(Object.entries(digesters).map(([k, f]) => [k, (i) => f(n, i)]))
  report(label, benchAll(200, 120, 13, cases))
}

for (const [n, label] of [
  [1, 'sign, 1 op'],
  [10, 'sign, 10 ops'],
]) {
  const cases = Object.fromEntries(Object.entries(signers).map(([k, f]) => [k, (i) => f(n, i)]))
  report(label, benchAll(200, 400, 7, cases))
}

console.log(`
  Reading these: the spread column is (median - minimum) / minimum across the
  row. A difference smaller than the spread is not a difference.

  The signing rows are dominated by secp256k1, and the libraries differ in how
  they get it — which is a deliberate trade rather than a quality difference:

    dhive        binds the native \`secp256k1\` package
    hivecomb     links libsecp256k1 through Rust
    hive-pollen  uses @noble/curves, an audited pure-JavaScript library
    hive-tx      has no runtime dependencies at all; its crypto is inlined
                 JavaScript, which is what lets it run in browsers, workers
                 and serverless runtimes unchanged
    hive-js      uses \`ecurve\`/\`bigi\` bigint arithmetic

  A library that chooses portability over a native binding pays for it here,
  and that is the choice working as intended rather than a defect.

  hive-js exposes no digest entry point, so it appears only in the signing
  rows; its signature was checked against the shared digest instead.`)
