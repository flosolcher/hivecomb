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
//!
//! # Why this does not need an idle machine
//!
//! Timing is `CLOCK_THREAD_CPUTIME_ID`, not a wall clock. When another process takes the
//! core this thread is descheduled, and a thread CPU clock does not tick while the thread
//! is not running -- so competing work is subtracted out rather than charged to whatever
//! was being measured. Run with `--verify-under-load` to have the program prove that on
//! the machine in front of you: it measures one operation, saturates every core, measures
//! again, and prints both. A claim like this is worth being able to reproduce.
//!
//! What it does *not* remove is cache and memory-bandwidth pressure from neighbours, or a
//! sibling hyperthread stealing execution units. Those inflate real CPU time, so a badly
//! contended machine still reads a little slow.

use std::hint::black_box;
use std::time::Duration;

/// CPU time consumed by *this thread*.
///
/// `Instant::now()` measures how much of the world went by; this measures how much work
/// the thread actually did. Under contention the two diverge badly, and only the second
/// is a property of the code being measured.
fn cpu_now() -> Duration {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `clock_gettime` writes a well-formed `timespec` through the pointer it is
    // given and touches nothing else.
    unsafe {
        libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut ts);
    }
    Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32)
}

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
    let best = measure(warm, window, rounds, &mut f);
    println!("  {label:<46}{best:>9.3} us");
    best
}

/// A hardware cycle counter for this process, when the kernel will give us one.
///
/// The thread CPU clock removes time spent descheduled, but it cannot remove *frequency*:
/// under all-core load an i9-10885H drops from 5.3 GHz towards 2.4, and the same work
/// then costs more CPU-microseconds without a single instruction changing. Cycles do not
/// move with frequency, so cycles per operation is the one absolute figure here that a
/// busy machine cannot distort.
///
/// Needs `perf_event_paranoid <= 2`, which is the common default. Returns `None` rather
/// than failing when the counter is unavailable, and the caller falls back to time.
struct Cycles(std::os::fd::OwnedFd);

impl Cycles {
    fn open() -> Option<Self> {
        use std::os::fd::FromRawFd;

        // `perf_event_attr` as of PERF_ATTR_SIZE_VER7. Only the leading fields are named;
        // the tail is zeroed padding, which is what the kernel expects for `size = 128`.
        #[repr(C)]
        struct Attr {
            type_: u32,
            size: u32,
            config: u64,
            sample_period: u64,
            sample_type: u64,
            read_format: u64,
            flags: u64,
            tail: [u8; 80],
        }
        const PERF_TYPE_HARDWARE: u32 = 0;
        const PERF_COUNT_HW_CPU_CYCLES: u64 = 0;
        // bit 5 = exclude_kernel, bit 6 = exclude_hv: count only this program's own work.
        const EXCLUDE_KERNEL_AND_HV: u64 = (1 << 5) | (1 << 6);

        let attr = Attr {
            type_: PERF_TYPE_HARDWARE,
            size: std::mem::size_of::<Attr>() as u32,
            config: PERF_COUNT_HW_CPU_CYCLES,
            sample_period: 0,
            sample_type: 0,
            read_format: 0,
            flags: EXCLUDE_KERNEL_AND_HV,
            tail: [0; 80],
        };
        // SAFETY: `perf_event_open` reads `size` bytes through the pointer and returns a
        // file descriptor or -1. pid 0 / cpu -1 means "this process, whichever core".
        let fd = unsafe {
            libc::syscall(
                libc::SYS_perf_event_open,
                &attr as *const Attr,
                0,
                -1,
                -1,
                0u64,
            )
        };
        if fd < 0 {
            return None;
        }
        // SAFETY: `fd` is a fresh descriptor the kernel just handed us and nothing else
        // owns it.
        Some(Cycles(unsafe {
            std::os::fd::OwnedFd::from_raw_fd(fd as i32)
        }))
    }

    fn read(&self) -> u64 {
        use std::os::fd::AsRawFd;
        let mut buf = 0u64;
        // SAFETY: reading 8 bytes into an 8-byte destination from a counter descriptor.
        let n = unsafe {
            libc::read(
                self.0.as_raw_fd(),
                (&mut buf as *mut u64).cast::<libc::c_void>(),
                8,
            )
        };
        if n == 8 {
            buf
        } else {
            0
        }
    }

    /// Cycles per call, averaged over a fixed number of iterations.
    fn per_op(&self, iters: u32, f: &mut impl FnMut(u32)) -> f64 {
        for i in 0..iters.min(1000) {
            f(i);
        }
        let before = self.read();
        for i in 0..iters {
            f(i);
        }
        (self.read() - before) as f64 / f64::from(iters)
    }
}

/// Wall-clock time since the process started, in the same shape as [`cpu_now`], so the
/// two can be swapped in the timing loop and compared.
fn wall_now() -> Duration {
    use std::sync::OnceLock;
    use std::time::Instant;
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed()
}

/// The timing loop without the printing, so the self-check below can reuse it.
fn measure(warm: Duration, window: Duration, rounds: u32, f: &mut impl FnMut(u32)) -> f64 {
    measure_using(cpu_now, warm, window, rounds, f)
}

fn measure_using(
    now: fn() -> Duration,
    warm: Duration,
    window: Duration,
    rounds: u32,
    f: &mut impl FnMut(u32),
) -> f64 {
    let started = now();
    let mut i = 0u32;
    while now() - started < warm {
        f(i);
        i = i.wrapping_add(1);
    }
    let mut best = f64::MAX;
    for _ in 0..rounds {
        let start = now();
        let mut n = 0u32;
        while now() - start < window {
            f(n);
            n = n.wrapping_add(1);
        }
        let per = (now() - start).as_secs_f64() / f64::from(n) * 1e6;
        if per < best {
            best = per;
        }
    }
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

/// Prove on this machine which clock survives a busy machine, rather than asserting it.
///
/// Measures the same signature as the machine is, then again with every core saturated,
/// on all three clocks. Two distinct things go wrong under load and they need separate
/// answers: being descheduled (the thread CPU clock removes it) and the CPU dropping
/// frequency (only cycles are immune -- this part is 5.3 GHz down towards 2.4 under
/// all-core load, and the same instructions then cost more microseconds).
///
/// The spinners deliberately clear their CPU affinity. Inheriting this process's pinning
/// would put them all on one core, which tests descheduling but never provokes a turbo
/// drop -- an easier test that a thread clock passes while still leaving the figures
/// wrong. Ask the harder question.
fn verify_under_load(key: &PrivateKey, digests: &[[u8; 32]]) {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    let warm = Duration::from_millis(200);
    let window = Duration::from_millis(120);
    let iters = 3_000u32;
    let mut sign = |i: u32| {
        black_box(hivecomb::sign::sign_digest(&digests[(i as usize) & 255], key).expect("signs"));
    };
    let cycles = Cycles::open();

    let quiet = (
        measure_using(wall_now, warm, window, 5, &mut sign),
        measure_using(cpu_now, warm, window, 5, &mut sign),
        cycles.as_ref().map(|c| c.per_op(iters, &mut sign)),
    );

    let stop = Arc::new(AtomicBool::new(false));
    // `available_parallelism` reports the *affinity mask*, which under `taskset -c 14` is
    // one core -- so it would spawn a single spinner and quietly test almost nothing. Ask
    // the machine how many CPUs it actually has.
    // SAFETY: `sysconf` takes a name and returns a long; no pointers involved.
    let cores = match unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) } {
        n if n > 0 => n as usize,
        _ => 8,
    };
    let threads: Vec<_> = (0..cores)
        .map(|_| {
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                // Escape any inherited pinning so the load is genuinely all-core.
                // SAFETY: `cpu_set_t` is zeroed and filled through libc's own helpers
                // before being handed back to `sched_setaffinity` for this thread.
                unsafe {
                    let mut set: libc::cpu_set_t = std::mem::zeroed();
                    for c in 0..cores {
                        libc::CPU_SET(c, &mut set);
                    }
                    libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set);
                }
                let mut x = 0u64;
                while !stop.load(Ordering::Relaxed) {
                    x = black_box(x.wrapping_mul(6364136223846793005).wrapping_add(1));
                }
            })
        })
        .collect();

    let loaded = (
        measure_using(wall_now, warm, window, 5, &mut sign),
        measure_using(cpu_now, warm, window, 5, &mut sign),
        cycles.as_ref().map(|c| c.per_op(iters, &mut sign)),
    );

    stop.store(true, Ordering::Relaxed);
    for t in threads {
        let _ = t.join();
    }

    let drift = |a: f64, b: f64| (b - a) / a * 100.0;
    println!("\n  --- which clock survives a busy machine? -------------------");
    println!("  signing one transfer, {cores} cores of competing work added\n");
    println!("     clock                 quiet       loaded     drift");
    println!(
        "     wall           {:11.2} {:12.2} {:8.0}%",
        quiet.0,
        loaded.0,
        drift(quiet.0, loaded.0)
    );
    println!(
        "     thread cpu     {:11.2} {:12.2} {:8.0}%",
        quiet.1,
        loaded.1,
        drift(quiet.1, loaded.1)
    );
    match (quiet.2, loaded.2) {
        (Some(q), Some(l)) => {
            println!("     cycles/op      {q:11.0} {l:12.0} {:8.0}%", drift(q, l));
            let ok = drift(q, l).abs() < 10.0;
            println!(
                "\n  wall - thread cpu = time spent descheduled, which the thread clock removes."
            );
            println!("  thread cpu - cycles = frequency scaling, which only cycles remove.");
            println!("  cycles that still move = the same instructions taking more cycles.");
            println!(
                "\n  Cycles drifted {:.0}%. {}",
                drift(q, l).abs(),
                if ok {
                    "These counts are a property of the code."
                } else {
                    "That is the SMT sibling stealing"
                }
            );
            if !ok {
                println!("  execution units, and no userspace clock can subtract it out. For");
                println!("  figures that hold on a saturated machine, a core and its sibling");
                println!("  have to be taken away from everything else, which needs root:");
                println!();
                println!("    sudo systemctl set-property --runtime user.slice \\");
                println!("        AllowedCPUs=0-5,7-13,15        # and system.slice, init.scope");
                println!("    taskset -c 14 <the benchmark>      # 6 and 14 are one core");
                println!();
                println!("  Without that, compare *ratios* between libraries measured in the");
                println!("  same run: contention hits both sides and divides out. Absolute");
                println!("  microseconds from a loaded machine are not worth publishing.");
            }
        }
        _ => println!(
            "     cycles/op          unavailable (perf_event_open refused; \
             needs perf_event_paranoid <= 2)"
        ),
    }
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

    if std::env::args().any(|a| a == "--verify-under-load") {
        verify_under_load(&key, &digests);
    }

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
