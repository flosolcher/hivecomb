//! The Graphene deserializer, given arbitrary bytes.
//!
//! `Reader` is what turns a node's response, or another client's transaction, into
//! typed values. Everything it consumes is attacker-influenced, and a panic here is a
//! denial of service in whatever process is parsing — which, in a signing service, is
//! the one holding the keys.
//!
//! The contract is narrow and absolute: **every input either deserializes or returns
//! an error, and nothing panics.** `hivecomb/tests/hostile_input.rs` asserts the same
//! thing over a fixed corpus on every commit; this explores the space properly.
#![no_main]

use hivecomb::operations::Operation;
use hivecomb::{Chain, GrapheneDeserialize, GrapheneSerialize, Reader};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut reader = Reader::new(data, Chain::Hive);
    if let Ok(op) = Operation::read_from(&mut reader) {
        let once = op.to_wire().expect("a parsed operation must re-serialize");

        // NOT asserted: that `once == data`. It is not true, and the fuzzer found
        // that within minutes of first running. A string field holding a raw byte
        // below 0x20 parses back as that byte, and re-serializing puts it through
        // `hived_transport_form`, which writes the five characters `u0000` instead.
        // The transform is correct -- hived's JSON parser does the same thing, so
        // those are the bytes a signature has to cover -- but it means parse and
        // serialize are not inverses. See types.rs.
        //
        // What must hold is that it settles after one pass: serialize, parse,
        // serialize again, and the bytes stop moving. If they did not, re-signing a
        // transaction would keep changing what the signature covers.
        let mut reader2 = Reader::new(&once, Chain::Hive);
        let reparsed = Operation::read_from(&mut reader2)
            .expect("our own output must parse");
        let twice = reparsed.to_wire().expect("and re-serialize");
        assert_eq!(once, twice, "serialization is not idempotent for {op:?}");
    }
});
