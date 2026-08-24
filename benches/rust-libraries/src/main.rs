//! `hivecomb` against every other Rust Hive library, on identical work.
//!
//!     cd benches/rust-libraries
//!     ../../benches/rust-libraries/run.sh          # pinned and memory-bounded
//!
//! # Why this exists
//!
//! The documentation carried speed numbers for some of the libraries it names and none
//! for others. Publishing a partial set is not a fair way to present a comparison,
//! whatever the intent, so this measures every Rust library the project names.
//!
//! These are all real projects solving the same problem, several of them published and
//! in use while this one is not. The numbers below are offered so a reader can judge for
//! themselves, not as a verdict on anyone's work.
//!
//! # Gates before timing
//!
//! Nothing is timed until the libraries are shown to be doing the same work:
//!
//! * all three general-purpose crates must produce the **same transaction digest** —
//!   that is the number the chain signs, so agreement means the serializers agree byte
//!   for byte;
//! * the memo crates are asked to **decrypt each other's output**, which is a stronger
//!   check than comparing ciphertext (the nonce is random, so ciphertext never matches)
//!   and is the property an ECDH derivation difference would break.
//!
//! A digest mismatch aborts: a benchmark of implementations that disagree about what to
//! sign measures nothing. A memo mismatch is reported and the run continues, because the
//! difference found there is a documented format disagreement rather than the libraries
//! doing different work — see the note at that gate.
//!
//! # Method
//!
//! Minimum of several windows with the payload varied every iteration, pinned to one
//! core, under a memory cap — see `run.sh`. The minimum is used because interference can
//! only ever make a window slower, so the fastest is closest to the true cost.

use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

/// The published test key. It secures no Hive account and must never hold value.
const WIF: &str = "5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3";
const REF_NUM: u16 = 5;
const REF_PREFIX: u32 = 0xaabb_ccdd;
const EXPIRATION: &str = "2026-01-01T00:00:00";
const CHAIN_HEX: &str = "beeab0de00000000000000000000000000000000000000000000000000000000";

// ---------------------------------------------------------------------------
// hivecomb
// ---------------------------------------------------------------------------

fn comb_tx(ops: usize, i: u32) -> hivecomb::Transaction {
    use hivecomb::operations::{CustomJson, Operation, Transfer};
    use hivecomb::types::PointInTime;
    use hivecomb::{Amount, Chain, Transaction};
    let operations = (0..ops)
        .map(|k| {
            if ops == 1 {
                Operation::Transfer(Transfer {
                    from: "alice".into(),
                    to: "bob".into(),
                    amount: Amount::parse("1.234 HIVE", Chain::Hive).unwrap(),
                    memo: format!("m{i}"),
                })
            } else {
                Operation::CustomJson(CustomJson {
                    required_auths: vec![],
                    required_posting_auths: vec!["alice".into()],
                    id: "my_app".into(),
                    json: format!(r#"{{"n":{i},"k":{k}}}"#),
                })
            }
        })
        .collect();
    Transaction {
        ref_block_num: REF_NUM,
        ref_block_prefix: REF_PREFIX,
        expiration: PointInTime::parse(EXPIRATION).unwrap(),
        operations,
    }
}

fn comb_digest(ops: usize, i: u32) -> [u8; 32] {
    comb_tx(ops, i).digest(hivecomb::Chain::Hive).unwrap()
}

// ---------------------------------------------------------------------------
// hive-xylem
// ---------------------------------------------------------------------------

fn xylem_tx(ops: usize, i: u32) -> hive_xylem::transaction::Transaction {
    use hive_xylem::operations::{CustomJson, Operation, Transfer};
    use hive_xylem::transaction::Transaction;
    use hive_xylem::types::HiveTime;
    let expiration = chrono::NaiveDateTime::parse_from_str(EXPIRATION, "%Y-%m-%dT%H:%M:%S").unwrap();
    let operations: Vec<Box<dyn Operation>> = (0..ops)
        .map(|k| -> Box<dyn Operation> {
            if ops == 1 {
                Box::new(Transfer {
                    from: "alice".into(),
                    to: "bob".into(),
                    amount: "1.234 HIVE".into(),
                    memo: format!("m{i}"),
                })
            } else {
                Box::new(CustomJson {
                    required_auths: vec![],
                    required_posting_auths: vec!["alice".into()],
                    id: "my_app".into(),
                    json: format!(r#"{{"n":{i},"k":{k}}}"#),
                })
            }
        })
        .collect();
    Transaction {
        ref_block_num: REF_NUM,
        ref_block_prefix: REF_PREFIX,
        expiration: HiveTime(expiration),
        operations,
        signatures: vec![],
    }
}

fn xylem_digest(ops: usize, i: u32) -> [u8; 32] {
    let body = xylem_tx(ops, i).to_bytes().unwrap();
    let mut h = Sha256::new();
    h.update(hex::decode(CHAIN_HEX).unwrap());
    h.update(&body);
    h.finalize().into()
}

// ---------------------------------------------------------------------------
// hive-rs
// ---------------------------------------------------------------------------

fn hive_rs_tx(ops: usize, i: u32) -> hive_rs::types::Transaction {
    use hive_rs::types::{
        Asset, CustomJsonOperation, Operation, Transaction, TransferOperation,
    };
    let operations = (0..ops)
        .map(|k| {
            if ops == 1 {
                Operation::Transfer(TransferOperation {
                    from: "alice".into(),
                    to: "bob".into(),
                    amount: Asset::hive(1.234),
                    memo: format!("m{i}"),
                })
            } else {
                Operation::CustomJson(CustomJsonOperation {
                    required_auths: vec![],
                    required_posting_auths: vec!["alice".into()],
                    id: "my_app".into(),
                    json: format!(r#"{{"n":{i},"k":{k}}}"#),
                })
            }
        })
        .collect();
    Transaction {
        ref_block_num: REF_NUM,
        ref_block_prefix: REF_PREFIX,
        expiration: EXPIRATION.to_string(),
        operations,
        extensions: vec![],
    }
}

fn hive_rs_digest(ops: usize, i: u32) -> [u8; 32] {
    hive_rs::serialization::transaction_digest(
        &hive_rs_tx(ops, i),
        &hive_rs::types::ChainId::mainnet(),
    )
    .unwrap()
}

// ---------------------------------------------------------------------------
// Timing
// ---------------------------------------------------------------------------

/// Minimum window, and the spread between it and the median.
///
/// The spread is returned rather than discarded so the report can show how much to
/// trust itself. Interference can only make a window slower, so the minimum is closest
/// to the true cost; if the median sits far above it, the machine was busy and the
/// ordering of two close results means nothing.
#[derive(Clone, Copy)]
struct Timing {
    best: f64,
    spread: f64,
}

/// Time several implementations of the same task, **interleaved**.
///
/// Every candidate gets one window, then the next round, and so on. Running all of one
/// candidate's windows before the next one's looks equivalent and is not: the CPU
/// governor on this machine is `powersave`, so the clock ramps during a run and whoever
/// goes first is measured cold. A first version of this harness did exactly that and
/// produced 40% spreads with ratios that flipped between runs.
///
/// Warmup is by wall clock rather than by iteration count, so a slow candidate is not
/// warmed less than a fast one.
fn bench_all(warm: Duration, iters: u32, windows: u32, cases: &mut [(&str, &mut dyn FnMut(u32))]) -> Vec<Timing> {
    for (_, f) in cases.iter_mut() {
        let started = Instant::now();
        let mut i = 0u32;
        while started.elapsed() < warm {
            f(i);
            i = i.wrapping_add(1);
        }
    }

    let mut samples: Vec<Vec<f64>> = vec![Vec::with_capacity(windows as usize); cases.len()];
    for _ in 0..windows {
        for (slot, (_, f)) in cases.iter_mut().enumerate() {
            let started = Instant::now();
            for i in 0..iters {
                f(i);
            }
            samples[slot].push(started.elapsed().as_secs_f64() / f64::from(iters) * 1e6);
        }
    }

    samples
        .into_iter()
        .map(|mut s| {
            s.sort_by(|a, b| a.partial_cmp(b).expect("no NaN from a clock"));
            let best = s[0];
            let median = s[s.len() / 2];
            Timing {
                best,
                spread: if best > 0.0 { (median - best) / best } else { 0.0 },
            }
        })
        .collect()
}

fn row(label: &str, comb: &Timing, xylem: &Timing, hive_rs: &Timing) {
    // The worst spread across the three, because a ratio is only as trustworthy as the
    // noisiest measurement in it.
    let spread = comb.spread.max(xylem.spread).max(hive_rs.spread);
    let ratio = |x: f64| {
        let r = x / comb.best;
        if r >= 1.0 {
            format!("{r:.2}x")
        } else {
            format!("{r:.2}x")
        }
    };
    println!(
        "  {label:<34} {:>9.2} {:>9.2} {:>9.2} | {:>7} {:>7} {:>6}",
        comb.best,
        xylem.best,
        hive_rs.best,
        ratio(xylem.best),
        ratio(hive_rs.best),
        format!("{:.0}%", spread * 100.0),
    );
}

fn main() {
    println!("hivecomb against the other Rust Hive libraries\n");

    // ---- gate 1: the general-purpose crates must agree on the digest ----
    println!("gate: identical transaction, identical digest?");
    let mut agreed = true;
    for ops in [1usize, 10] {
        let c = comb_digest(ops, 7);
        let x = xylem_digest(ops, 7);
        let h = hive_rs_digest(ops, 7);
        let ok = c == x && c == h;
        agreed &= ok;
        println!(
            "  {ops:>3} operation(s): {}  {}",
            if ok { "MATCH  " } else { "DIFFER " },
            hex::encode(&c[..12])
        );
        if !ok {
            println!("      hivecomb   {}", hex::encode(c));
            println!("      hive-xylem {}", hex::encode(x));
            println!("      hive-rs    {}", hex::encode(h));
        }
    }
    if !agreed {
        eprintln!("\nThe libraries do not agree on what to sign. Nothing was timed:");
        eprintln!("a benchmark of implementations that disagree measures nothing.");
        std::process::exit(1);
    }

    // ---- gate 2: the memo crates must read each other's output ----
    let comb_key = hivecomb::PrivateKey::from_wif(WIF).unwrap();
    let comb_pub = comb_key.public_key();
    let hm_secret = hive_memo::wif_to_secret_key(WIF).unwrap();
    let hm_public = hive_memo::public_key_from_string(&comb_pub.to_string()).unwrap();

    let from_comb = hivecomb::memo::encode(&comb_key, &comb_pub, "#interop check").unwrap();
    let from_hm = hive_memo::encrypt_memo(&hm_secret, &hm_public, "#interop check").unwrap();
    let comb_reads_hm = hivecomb::memo::decode(&comb_key, &from_hm).unwrap_or_default();
    let hm_reads_comb = hive_memo::decrypt_memo(&hm_secret, &from_comb).unwrap_or_default();
    let comb_ok = comb_reads_hm.trim_start_matches('#') == "interop check";
    let hm_ok = hm_reads_comb.trim_start_matches('#') == "interop check";

    println!("\ngate: encrypted memos, each library reading the other's");
    println!(
        "  hivecomb reads hive_memo   {}",
        if comb_ok { "ok".to_string() } else { format!("{comb_reads_hm:?}") }
    );
    println!(
        "  hive_memo reads hivecomb   {}",
        if hm_ok { "ok".to_string() } else { format!("{hm_reads_comb:?}") }
    );
    if !hm_ok {
        // Not a failure and not a verdict. The two write the memo plaintext
        // differently: measured with a 15-byte message, which pads to one AES block on
        // its own and to two behind a one-byte varint length prefix, hivecomb produces
        // 32 bytes of ciphertext and hive_memo 16. So hivecomb writes the prefix that
        // hived's memo format specifies and hive_memo does not.
        //
        // Both libraries round-trip their own memos, and an independent implementation
        // (hive-nectar) reads both, so nothing is unreadable in practice. What the line
        // above shows is a memo written by a prefix-writing client picking up one extra
        // leading character when hive_memo reads it.
        //
        // It is recorded here as an observation. Characterising someone else's crate is
        // not this harness's job, and anything of the sort belongs upstream first --
        // this project has published a finding about another project that turned out to
        // be wrong, and the lesson stuck.
        println!("  -> the two differ over the varint length prefix; see the note in this file");
    }
    if !comb_ok {
        eprintln!("\nhivecomb cannot read hive_memo's memos, which would be this crate's bug.");
        std::process::exit(1);
    }

    // ---- the numbers ----
    println!("\n  {:<34} {:>9} {:>9} {:>9} | {:>7} {:>7}", "", "hivecomb", "xylem", "hive-rs", "xylem", "hive-rs");
    println!("  {:<34} {:>9} {:>9} {:>9} | {:>15}", "task (microseconds)", "0.1.0", "0.1.6", "0.1.0", "relative");
    println!("  {}", "-".repeat(90));

    let warm = Duration::from_millis(300);

    let d1 = bench_all(warm, 20_000, 15, &mut [
        ("hivecomb", &mut |i| { std::hint::black_box(comb_digest(1, i)); }),
        ("xylem", &mut |i| { std::hint::black_box(xylem_digest(1, i)); }),
        ("hive-rs", &mut |i| { std::hint::black_box(hive_rs_digest(1, i)); }),
    ]);
    row("serialize + digest, 1 transfer", &d1[0], &d1[1], &d1[2]);

    let d10 = bench_all(warm, 5_000, 15, &mut [
        ("hivecomb", &mut |i| { std::hint::black_box(comb_digest(10, i)); }),
        ("xylem", &mut |i| { std::hint::black_box(xylem_digest(10, i)); }),
        ("hive-rs", &mut |i| { std::hint::black_box(hive_rs_digest(10, i)); }),
    ]);
    row("serialize + digest, 10 custom_json", &d10[0], &d10[1], &d10[2]);

    let comb_keys = [comb_key.clone()];
    let hs_key = hive_rs::crypto::PrivateKey::from_wif(WIF).unwrap();
    // Hoisted: `ChainId::mainnet()` hex-decodes, and leaving it inside the loop would
    // charge hive-rs for setup that hivecomb does once. Same reason the keys are parsed
    // outside.
    let hs_chain = hive_rs::types::ChainId::mainnet();
    let sg = bench_all(warm, 2_000, 15, &mut [
        ("hivecomb", &mut |i| {
            std::hint::black_box(comb_tx(1, i).sign(&comb_keys, hivecomb::Chain::Hive).unwrap());
        }),
        ("xylem", &mut |i| {
            let mut tx = xylem_tx(1, i);
            tx.sign(WIF, CHAIN_HEX).unwrap();
            std::hint::black_box(tx);
        }),
        ("hive-rs", &mut |i| {
            std::hint::black_box(
                hive_rs::crypto::sign_transaction(&hive_rs_tx(1, i), &[&hs_key], &hs_chain).unwrap(),
            );
        }),
    ]);
    row("sign a transfer", &sg[0], &sg[1], &sg[2]);

    // xylem's signing API takes the WIF and chain id as strings, so it re-parses both on
    // every call and there is no way to hand it a prepared key. That is an API difference
    // rather than an implementation one; measured here so a reader can subtract it rather
    // than left silently inside the row above.
    let wp = bench_all(warm, 20_000, 9, &mut [
        ("parse", &mut |_| { std::hint::black_box(hivecomb::PrivateKey::from_wif(WIF).unwrap()); }),
    ]);
    println!(
        "  {:<34} {:>9.2} {:>9} {:>9} |",
        "  of which xylem re-parses a WIF", wp[0].best, "per call", "once"
    );

    let mm = bench_all(warm, 1_000, 11, &mut [
        ("hivecomb", &mut |i| {
            std::hint::black_box(
                hivecomb::memo::encode(&comb_key, &comb_pub, &format!("#note {i}")).unwrap(),
            );
        }),
        ("hive_memo", &mut |i| {
            std::hint::black_box(
                hive_memo::encrypt_memo(&hm_secret, &hm_public, &format!("#note {i}")).unwrap(),
            );
        }),
    ]);
    println!("  {}", "-".repeat(90));
    println!(
        "  {:<34} {:>9.2} {:>9.2} {:>9} | {:>7} {:>7} {:>6}",
        "encrypt a memo",
        mm[0].best,
        mm[1].best,
        "—",
        format!("{:.2}x", mm[1].best / mm[0].best),
        "—",
        format!("{:.0}%", mm[0].spread.max(mm[1].spread) * 100.0),
    );

    println!("\n  the memo row is hive_memo 0.1.2, which does only memos, so the xylem and");
    println!("  hive-rs columns do not apply to it.");
    println!();
    println!("  Reading these: the spread column is (median - minimum) / minimum across the");
    println!("  three. A difference smaller than the spread is not a difference. On this");
    println!("  machine the CPU has no SHA extensions, so SHA-256 runs in software at about");
    println!("  180 MB/s and costs ~1.9 us of every 344-byte digest -- work every library");
    println!("  here does identically. That shared cost is most of the digest rows and is");
    println!("  why they converge as the payload grows.");
}
