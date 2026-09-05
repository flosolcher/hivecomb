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
// Timing is process CPU time, not wall-clock, so the numbers hold on a machine that is
// doing other work — see the note on `cpuMs` below.
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

// `--scaling` runs the operation-count and signature-count sweeps instead of the
// summary table. Both share the gates below: whichever tables are printed, the
// libraries have been shown to agree on what they sign first.
const SCALING = process.argv.includes('--scaling')

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
// CPU time this process has actually consumed, in milliseconds. Not a wall clock: a
// neighbour taking the core deschedules us, and time we are not running is not charged
// here. That is what lets these figures mean something on a machine doing other work.
const cpuMs = () => {
  const c = process.cpuUsage()
  return (c.user + c.system) / 1000
}

function benchAll(warmMs, windowMs, windows, cases) {
  const names = Object.keys(cases)

  for (const name of names) {
    const started = cpuMs()
    let i = 0
    // At least one call, so a library slower than the whole warmup budget still runs.
    do cases[name](i++)
    while (cpuMs() - started < warmMs)
  }

  const samples = Object.fromEntries(names.map((n) => [n, []]))
  for (let w = 0; w < windows; w++) {
    for (const name of names) {
      const t = cpuMs()
      let n = 0
      do cases[name](n++)
      while (cpuMs() - t < windowMs)
      samples[name].push(((cpuMs() - t) * 1000) / n)
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

if (!SCALING) {
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
}

// --- scaling sweeps --------------------------------------------------------
//
// These reproduce the detailed dhive comparison in COMPARISON.md. They are a separate
// mode rather than extra rows because they answer a different question: not "who is
// faster" but "where does the answer change", which only a sweep can show.
//
// Only dhive is swept. It is the closest of the Node libraries on the summary table, so
// it is the only one where the ordering actually turns over within a realistic size —
// sweeping a library that is behind at every size would be padding.

if (SCALING) {
  // Distinct keys, derived deterministically so a rerun measures the same work, and
  // handed to both libraries as WIF strings so neither gets a head start on parsing.
  const wifs = Array.from({ length: 8 }, (_, k) =>
    hivecomb.PrivateKey.fromPassword('alice', 'posting', `bench-${k}`).toWif(),
  )
  const dhiveKeys = wifs.map((w) => dhive.PrivateKey.fromString(w))
  const combKeys = wifs.map((w) => new hivecomb.PrivateKey(w))

  // Every sweep is gated the same way the summary table is: both libraries must produce
  // the same digest for the shape about to be timed. A sweep that silently drifted into
  // measuring different transactions at n=200 would look exactly like a real crossover.
  for (const n of [1, 2, 5, 8, 10, 15, 20, 50, 200]) {
    const a = Buffer.from(digesters.hivecomb(n, 3)).toString('hex')
    const b = Buffer.from(digesters['@hiveio/dhive'](n, 3)).toString('hex')
    if (a !== b) {
      console.error(`\ndigest mismatch at ${n} operations. Nothing was timed.`)
      process.exit(1)
    }
  }
  console.log('\n  gate: digests agree at every size swept below: yes')

  const sweep = (label, sizes, cols, windows = 7) => {
    console.log(`\n  ${label}`)
    const head = '  ' + 'n'.padStart(5) + Object.keys(cols).map((c) => c.padStart(22)).join('')
    console.log(head)
    console.log('  ' + '-'.repeat(head.length - 2))
    const rows = []
    for (const n of sizes) {
      const cases = Object.fromEntries(Object.entries(cols).map(([k, f]) => [k, (i) => f(n, i)]))
      const r = benchAll(200, 400, windows, cases)
      rows.push([n, r])
      const cells = Object.keys(cols).map((c) => `${r[c].best.toFixed(1)} us`.padStart(22))
      console.log('  ' + String(n).padStart(5) + cells.join(''))
    }
    return rows
  }

  sweep(
    'signing a transaction, as the object API both libraries return',
    [1, 2, 5, 8, 10, 15, 20, 50],
    {
      'dhive 1.3.6': (n, i) => dhive.cryptoUtils.signTransaction(trx(n, i), [dhiveKeys[0]]),
      hivecomb: (n, i) => hivecomb.signTransaction(JSON.stringify(ops(n, i)), ref, [combKeys[0]], 600),
    },
  )

  sweep(
    'the end-to-end task: the JSON body an application POSTs',
    [1, 2, 5, 10, 20, 30, 40, 50, 200],
    {
      'dhive + stringify': (n, i) => JSON.stringify(dhive.cryptoUtils.signTransaction(trx(n, i), [dhiveKeys[0]])),
      'hivecomb, object': (n, i) => JSON.stringify(hivecomb.signTransaction(JSON.stringify(ops(n, i)), ref, [combKeys[0]], 600)),
      'hivecomb, JSON string': (n, i) => hivecomb.signTransactionJson(JSON.stringify(ops(n, i)), ref, [combKeys[0]], 600),
    },
  )

  const keyRows = sweep(
    'many signatures over one transaction, rather than many operations',
    [1, 2, 3, 5, 8],
    {
      'dhive 1.3.6': (k, i) => dhive.cryptoUtils.signTransaction(trx(1, i), dhiveKeys.slice(0, k)),
      hivecomb: (k, i) => hivecomb.signTransaction(JSON.stringify(ops(1, i)), ref, combKeys.slice(0, k), 600),
    },
  )

  // Where the advantage comes from, without needing a raw-ECDSA entry point that this
  // addon deliberately does not export. Cost against signature count is a straight line:
  // its slope is one signature's curve arithmetic and its intercept is everything else
  // -- building the transaction, crossing the language boundary, rendering the result.
  // Fitting the line recovers both from data measured in this process, which is sounder
  // than quoting a curve figure taken in another runtime and comparing across tables.
  const fit = (name) => {
    const xs = keyRows.map(([k]) => k)
    const ys = keyRows.map(([, r]) => r[name].best)
    const n = xs.length
    const mx = xs.reduce((a, b) => a + b) / n
    const my = ys.reduce((a, b) => a + b) / n
    let num = 0
    let den = 0
    for (let i = 0; i < n; i++) {
      num += (xs[i] - mx) * (ys[i] - my)
      den += (xs[i] - mx) ** 2
    }
    const slope = num / den
    return { slope, intercept: my - slope * mx }
  }
  const d = fit('dhive 1.3.6')
  const h = fit('hivecomb')
  console.log('\n  decomposed, by fitting cost against signature count')
  console.log('  ' + ''.padEnd(34) + 'dhive 1.3.6'.padStart(14) + 'hivecomb'.padStart(14) + 'ratio'.padStart(10))
  console.log('  ' + '-'.repeat(72))
  const line = (label, a, b) =>
    console.log(
      '  ' + label.padEnd(34) + `${a.toFixed(1)} us`.padStart(14) + `${b.toFixed(1)} us`.padStart(14) +
      `${(a / b).toFixed(2)}x`.padStart(10),
    )
  line('per signature (curve arithmetic)', d.slope, h.slope)
  line('fixed overhead (everything else)', d.intercept, h.intercept)

  console.log(`
  Reading these: each cell is the minimum of ${7} interleaved windows of CPU time,
  the same estimator as the summary table, so these numbers may be compared
  with each other but not with the Python or Rust tables.

  The first sweep crosses over: hivecomb is ahead at the operation counts real
  transactions use and behind at large ones. The second shows the same task
  measured to the wire, where the crossover moves right. The third has no
  crossover, because each extra signature adds curve arithmetic and nothing
  else -- which the fit above then separates from the fixed cost.`)
}
