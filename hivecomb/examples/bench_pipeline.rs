//! Where the time goes, stage by stage, from operations to a signed transaction.
//!
//!     cargo run --release --example bench_pipeline --features rpc,memo,bip32,wallet
//!
//! Pin it for stable numbers:
//!
//!     taskset -c 14 cargo run --release --example bench_pipeline --features ...
//!
//! # Why this exists
//!
//! Signing latency is a standing requirement here, not a one-off task, and a comparison
//! against other libraries does not tell you which of *your own* stages to attack. This
//! decomposes the path so a regression has somewhere to show up and an optimisation has
//! somewhere to aim.
//!
//! Every figure is the minimum of several windows with the payload varied per iteration.
//! The minimum is used because interference can only make a window slower, so the
//! fastest is closest to the true cost.

use std::hint::black_box;
use std::time::{Duration, Instant};

use hivecomb::operations::{CustomJson, Operation, Transfer};
use hivecomb::types::{GrapheneSerialize, PointInTime};
use hivecomb::{Amount, BlockRef, Chain, PrivateKey, Transaction};

/// The published test key. It secures no Hive account.
const WIF: &str = "5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3";

fn bench(
    label: &str,
    warm: Duration,
    window: Duration,
    rounds: u32,
    mut f: impl FnMut(u32),
) -> f64 {
    let started = Instant::now();
    let mut i = 0u32;
    while started.elapsed() < warm {
        f(i);
        i = i.wrapping_add(1);
    }
    let mut best = f64::MAX;
    for _ in 0..rounds {
        let start = Instant::now();
        let mut n = 0u32;
        while start.elapsed() < window {
            f(n);
            n = n.wrapping_add(1);
        }
        let per = start.elapsed().as_secs_f64() / f64::from(n) * 1e6;
        if per < best {
            best = per;
        }
    }
    println!("  {label:<46}{best:>9.3} us");
    best
}

fn transfer(i: u32) -> Operation {
    Operation::Transfer(Transfer {
        from: "alice".into(),
        to: "bob".into(),
        amount: Amount::parse("1.234 HIVE", Chain::Hive).expect("valid amount"),
        memo: format!("m{i}"),
    })
}

fn custom_json(i: u32, k: usize) -> Operation {
    Operation::CustomJson(CustomJson {
        required_auths: vec![],
        required_posting_auths: vec!["alice".into()],
        id: "my_app".into(),
        json: format!(r#"{{"n":{i},"k":{k},"tag":"{}"}}"#, "x".repeat(20)),
    })
}

/// How many elliptic-curve operations a single signature really costs.
///
/// Graphene will not accept a signature whose `r` or `s` has its top bit set, so signing
/// retries with fresh nonce entropy until one comes out canonical. libsecp256k1 already
/// normalises `s` to the low half, which leaves `r` as the coin flip — so the expected
/// number of attempts is the thing to measure rather than assume, because it multiplies
/// the single most expensive operation in the library.
fn grind_distribution(key: &PrivateKey) {
    use hivecomb::sign::is_canonical;
    use secp256k1::Message;

    let secp = secp256k1::SECP256K1;
    // Reconstructed from the public accessor rather than reaching inside `PrivateKey`;
    // the benchmark has no business widening the library's API.
    let secret = secp256k1::SecretKey::from_slice(&*key.expose_secret()).expect("valid key");
    let mut attempts = [0u32; 8];
    let mut total = 0u64;
    const SAMPLES: u32 = 20_000;

    for sample in 0..SAMPLES {
        let digest = <[u8; 32]>::from(<sha2::Sha256 as sha2::Digest>::digest(sample.to_le_bytes()));
        let msg = Message::from_digest_slice(&digest).expect("32 bytes");
        for counter in 1u32..=64 {
            let mut nonce = [0u8; 32];
            nonce[28..].copy_from_slice(&counter.to_be_bytes());
            let sig = secp.sign_ecdsa_recoverable_with_noncedata(&msg, &secret, &nonce);
            let (_, compact) = sig.serialize_compact();
            if is_canonical(&compact) {
                attempts[(counter as usize - 1).min(7)] += 1;
                total += u64::from(counter);
                break;
            }
        }
    }

    println!("\n  elliptic-curve operations per signature, over {SAMPLES} signatures");
    for (n, count) in attempts.iter().enumerate() {
        if *count > 0 {
            let label = if n == 7 {
                "8+".to_string()
            } else {
                (n + 1).to_string()
            };
            println!(
                "    {label:>3} attempt(s)  {count:>6}  {:>5.1}%",
                f64::from(*count) / f64::from(SAMPLES) * 100.0
            );
        }
    }
    println!(
        "    mean         {:>6.3} curve operations per signature",
        total as f64 / f64::from(SAMPLES)
    );
}

fn main() {
    let warm = Duration::from_millis(300);
    let window = Duration::from_millis(150);
    let rounds = 9;

    let key = PrivateKey::from_wif(WIF).expect("published test key");
    let block_ref = BlockRef::from_block_id("00000005aabbccdd00000000000000000000abcd")
        .expect("valid block id");
    let expiration = PointInTime::parse("2026-01-01T00:00:00").expect("valid time");
    let keys = [key.clone()];

    println!("hivecomb pipeline, stage by stage\n");

    println!("  --- inputs -------------------------------------------------");
    bench("PrivateKey::from_wif", warm, window, rounds, |_| {
        black_box(PrivateKey::from_wif(WIF).expect("valid"));
    });
    bench("PrivateKey::public_key", warm, window, rounds, |_| {
        black_box(key.public_key());
    });
    bench("Amount::parse", warm, window, rounds, |_| {
        black_box(Amount::parse("1.234 HIVE", Chain::Hive).expect("valid"));
    });
    bench("PointInTime::parse", warm, window, rounds, |_| {
        black_box(PointInTime::parse("2026-01-01T00:00:00").expect("valid"));
    });

    println!("\n  --- building and serializing -------------------------------");
    bench("build one transfer", warm, window, rounds, |i| {
        black_box(transfer(i));
    });
    let one = transfer(7);
    bench("serialize one transfer", warm, window, rounds, |_| {
        black_box(one.to_wire().expect("serializes"));
    });
    let ten: Vec<Operation> = (0..10).map(|k| custom_json(7, k)).collect();
    bench("serialize ten custom_json", warm, window, rounds, |_| {
        for op in &ten {
            black_box(op.to_wire().expect("serializes"));
        }
    });

    println!("\n  --- transaction --------------------------------------------");
    let tx1 = Transaction {
        ref_block_num: block_ref.ref_block_num,
        ref_block_prefix: block_ref.ref_block_prefix,
        expiration,
        operations: vec![transfer(7)],
    };
    let body = tx1.body_bytes().expect("serializes");
    println!("  {:<46}{:>9} bytes", "body size, one transfer", body.len());
    bench("body_bytes, one transfer", warm, window, rounds, |_| {
        black_box(tx1.body_bytes().expect("serializes"));
    });
    bench("digest, one transfer", warm, window, rounds, |_| {
        black_box(tx1.digest(Chain::Hive).expect("digests"));
    });

    println!("\n  --- signing ------------------------------------------------");
    // Vary the digest. Signing is deterministic per digest, so a fixed one always needs
    // the same number of grind attempts -- and a digest that happens to be canonical on
    // the first try measures one curve operation while a real workload averages two. A
    // first version of this benchmark did exactly that and made `Transaction::sign` look
    // like it had 34 microseconds of unexplained overhead.
    let digests: Vec<[u8; 32]> = (0..256u32)
        .map(|i| {
            let tx = Transaction {
                ref_block_num: block_ref.ref_block_num,
                ref_block_prefix: block_ref.ref_block_prefix,
                expiration,
                operations: vec![transfer(i)],
            };
            tx.digest(Chain::Hive).expect("digests")
        })
        .collect();
    bench(
        "sign_digest, one fixed digest (lucky)",
        warm,
        window,
        rounds,
        |_| {
            black_box(hivecomb::sign::sign_digest(&digests[0], &key).expect("signs"));
        },
    );
    bench(
        "sign_digest, varying digest (real)",
        warm,
        window,
        rounds,
        |i| {
            black_box(
                hivecomb::sign::sign_digest(&digests[(i as usize) & 255], &key).expect("signs"),
            );
        },
    );
    bench(
        "Transaction::sign, one transfer",
        warm,
        window,
        rounds,
        |i| {
            let tx = Transaction {
                ref_block_num: block_ref.ref_block_num,
                ref_block_prefix: block_ref.ref_block_prefix,
                expiration,
                operations: vec![transfer(i)],
            };
            black_box(tx.sign(&keys, Chain::Hive).expect("signs"));
        },
    );

    println!("\n  --- derivation and key material ----------------------------");
    let mnemonic = hivecomb::bip39::Mnemonic::parse(
        "abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon about",
    )
    .expect("published test vector");
    bench(
        "bip39 mnemonic -> seed (PBKDF2, 2048 rounds)",
        warm,
        window,
        5,
        |_| {
            black_box(mnemonic.to_seed(""));
        },
    );
    let seed = mnemonic.to_seed("");
    bench("bip32 master from seed", warm, window, rounds, |_| {
        black_box(hivecomb::bip32::ExtendedPrivateKey::from_seed(&*seed).expect("valid seed"));
    });
    let master = hivecomb::bip32::ExtendedPrivateKey::from_seed(&*seed).expect("valid seed");
    bench(
        "bip32 derive_hive_role (4 hardened levels)",
        warm,
        window,
        rounds,
        |_| {
            black_box(
                master
                    .derive_hive_role(hivecomb::keys::Role::Posting, 0, 0)
                    .expect("derives"),
            );
        },
    );

    bench(
        "bip32 derive m/0/1/2 (3 normal levels)",
        warm,
        window,
        rounds,
        |_| {
            black_box(master.derive_path("m/0/1/2").expect("derives"));
        },
    );

    println!("\n  --- memo ---------------------------------------------------");
    let public = key.public_key();
    bench("memo encode", warm, window, rounds, |i| {
        black_box(hivecomb::memo::encode(&key, &public, &format!("#note {i}")).expect("encodes"));
    });
    let encoded = hivecomb::memo::encode(&key, &public, "#note").expect("encodes");
    bench("memo decode", warm, window, rounds, |_| {
        black_box(hivecomb::memo::decode(&key, &encoded).expect("decodes"));
    });

    println!("\n  --- authority ----------------------------------------------");
    let authority = hivecomb::authority::Authority::new(
        1,
        vec![],
        vec![hivecomb::authority::KeyAuth {
            key: public,
            weight: 1,
        }],
    )
    .expect("valid authority");
    bench("Authority::check, one key", warm, window, rounds, |_| {
        black_box(authority.check(&[public]));
    });

    println!("\n  --- base58 and key text ------------------------------------");
    let pub_text = public.to_prefixed("STM");
    bench(
        "PublicKey::to_prefixed (encode + checksum)",
        warm,
        window,
        rounds,
        |_| {
            black_box(public.to_prefixed("STM"));
        },
    );
    bench("PublicKey::from_prefixed_any", warm, window, rounds, |_| {
        black_box(hivecomb::PublicKey::from_prefixed_any(&pub_text).expect("valid"));
    });
    let raw = [0x80u8; 37];
    bench(
        "base58 encode_check, 37 bytes",
        warm,
        window,
        rounds,
        |_| {
            black_box(hivecomb::base58::encode_check(&raw));
        },
    );
    let encoded58 = hivecomb::base58::encode_check(&raw);
    bench(
        "base58 decode_check, 37 bytes",
        warm,
        window,
        rounds,
        |_| {
            black_box(hivecomb::base58::decode_check(&encoded58).expect("valid"));
        },
    );

    println!("\n  --- wallet -------------------------------------------------");
    // scrypt is deliberately expensive: it is what stands between a stolen wallet file
    // and the keys inside it. It is paid once per unlock, not per key or per signature,
    // so it is reported here to be sure that stays true rather than to be optimised.
    let dir = std::env::temp_dir().join("hivecomb-bench-wallet");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    let path = dir.join("wallet.json");
    let mut wallet = hivecomb::wallet::Wallet::create(&path, "correct horse").expect("creates");
    wallet.unlock("correct horse").expect("unlocks");
    for n in 0..64 {
        wallet
            .add_key(
                &key,
                Some(&format!("acct{n}")),
                Some(hivecomb::keys::Role::Posting),
            )
            .expect("adds");
    }
    bench("Wallet::unlock (scrypt N=2^15)", warm, window, 3, |_| {
        let mut w = hivecomb::wallet::Wallet::open(&path).expect("opens");
        w.unlock("correct horse").expect("unlocks");
        black_box(w);
    });
    bench(
        "key_for_role, 64 keys, last one",
        warm,
        window,
        rounds,
        |_| {
            black_box(
                wallet
                    .key_for_role("acct63", hivecomb::keys::Role::Posting)
                    .expect("found"),
            );
        },
    );
    bench("key_for_public, 64 keys", warm, window, rounds, |_| {
        black_box(wallet.key_for_public(&public).expect("found"));
    });
    let _ = std::fs::remove_dir_all(&dir);

    println!("\n  --- rpc, no network ----------------------------------------");
    let signed = tx1.clone().sign(&keys, Chain::Hive).expect("signs");
    bench("SignedTransaction::to_json", warm, window, rounds, |_| {
        black_box(signed.to_json().expect("serializes"));
    });
    let params = serde_json::json!([signed.to_json().expect("serializes")]);
    bench("build broadcast request body", warm, window, rounds, |_| {
        let req = hivecomb::rpc::RpcRequest::new(
            "network_broadcast_api.broadcast_transaction",
            params.clone(),
            1,
        );
        black_box(serde_json::to_string(&req).expect("serializes"));
    });
    let gdp = r#"{"jsonrpc":"2.0","id":1,"result":{"head_block_number":94000000,
        "head_block_id":"059a53800000000000000000000000000000abcd",
        "time":"2026-08-25T00:00:00","last_irreversible_block_num":93999950}}"#;
    bench(
        "parse a global-properties response",
        warm,
        window,
        rounds,
        |_| {
            black_box(serde_json::from_str::<hivecomb::rpc::RpcResponse>(gdp).expect("parses"));
        },
    );

    grind_distribution(&key);

    println!("\n  Read the grind table first. Every attempt past the first is a whole");
    println!("  extra elliptic-curve operation, and the curve is ~90% of a signature.");
    println!("  It is inherent to Graphene's compact format rather than a choice this");
    println!("  crate makes: a signature whose r or s has the top bit set is rejected,");
    println!("  so every Hive library grinds. What is worth watching is the mean.");
    println!();
    println!("  Two rows here are slow on purpose and must stay that way. scrypt is what");
    println!("  stands between a stolen wallet file and the keys in it, and PBKDF2's 2048");
    println!("  rounds are fixed by BIP-39. Both are paid once, at unlock and at import,");
    println!("  never per transaction. Nothing else on this list is a password hash, so");
    println!("  anything else that grows is a regression.");
}
