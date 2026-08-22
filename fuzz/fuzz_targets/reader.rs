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
        // Anything that parsed must re-serialize, and must do so to the same bytes.
        // A round trip that loses information means the wire format and the type
        // disagree, which is how a transaction ends up signing something other than
        // what it says.
        let reencoded = op.to_wire().expect("a parsed operation must re-serialize");
        let consumed = data.len() - reader.remaining();
        assert_eq!(
            &reencoded[..],
            &data[..consumed],
            "round trip changed the bytes for {op:?}"
        );
    }
});
