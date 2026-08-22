//! Encrypted memos, which arrive from strangers.
//!
//! A memo is written by whoever sent the transfer. Decoding one with the wrong key, or
//! decoding a deliberately malformed one, must fail cleanly — beem's `_unpad` returned
//! the input unchanged when the padding did not validate, handing padded bytes back as
//! though they were the message (finding 14 in SECURITY_FINDINGS.md).
#![no_main]

use hivecomb::memo::EncryptedMemo;
use hivecomb::PrivateKey;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Published on purpose, used by no Hive account.
    let key = PrivateKey::from_wif("5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3")
        .expect("the test key parses");

    let _ = EncryptedMemo::from_wire(data);

    if let Ok(text) = std::str::from_utf8(data) {
        let _ = EncryptedMemo::from_memo_string(text);
        let _ = hivecomb::memo::is_encrypted(text);
        // Decoding must never panic, whatever the ciphertext claims about itself.
        let _ = hivecomb::memo::decode(&key, text);
    }
});
