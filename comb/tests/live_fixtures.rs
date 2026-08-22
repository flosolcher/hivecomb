//! Parsing real responses captured from a live Hive node.
//!
//! Unit tests use hand-written JSON, which only ever contains what the author
//! remembered to include. These fixtures were captured from `api.hive.blog` and
//! contain whatever the chain actually sends — including the fields nobody thought
//! about, the sentinel timestamps, the numbers sent as strings because they exceed
//! JSON's safe integer range, and the retired witnesses whose signing key is not a
//! valid curve point.
//!
//! Every one of those was a bug found here rather than in production.
//!
//! Regenerate with the curl commands in `comb/tests/fixtures/README.md`.

use comb::chain::{Account, DynamicGlobalProperties, FeedHistory, RcAccount, RewardFund, Witness};

fn fixture(name: &str) -> serde_json::Value {
    let path = format!("{}/tests/fixtures/{name}.json", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("could not read fixture {path}: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("fixture {name} is not JSON: {e}"))
}

#[test]
fn parses_real_accounts() {
    let accounts: Vec<Account> =
        serde_json::from_value(fixture("account")).expect("real accounts must parse");
    assert_eq!(accounts.len(), 3);

    let names: Vec<&str> = accounts.iter().map(|a| a.name.as_str()).collect();
    assert!(names.contains(&"hiveio"));
    assert!(names.contains(&"blocktrades"));

    for account in &accounts {
        // Every account must have a usable identity and balances.
        assert!(!account.name.is_empty());
        assert_eq!(account.balance.symbol(), "HIVE");
        assert_eq!(account.hbd_balance.symbol(), "HBD");
        assert_eq!(account.vesting_shares.symbol(), "VESTS");
        assert!(
            account.owner.is_satisfiable(),
            "{} has an unsatisfiable owner",
            account.name
        );

        // Mana extrapolation must not overflow on real VESTS balances -- these are
        // the numbers that break a naive `current * 100 / max` in i64.
        let now = u64::from(
            account
                .last_vote_time
                .map(|t| t.unix())
                .unwrap_or(1_700_000_000),
        ) + 1;
        let power = account.voting_power(now);
        assert!(
            (0.0..=100.0).contains(&power),
            "{} has voting power {power}",
            account.name
        );

        // Effective vesting must be computable -- this subtracts and adds Amounts and
        // would error on an asset mismatch.
        account
            .effective_vesting_shares()
            .unwrap_or_else(|e| panic!("{}: {e}", account.name));
    }
}

#[test]
fn real_accounts_carry_the_never_sentinel() {
    // hived renders time_point_sec::maximum() as 1969-12-31T23:59:59. If parsing that
    // failed, most accounts would fail to parse at all.
    let accounts: Vec<Account> = serde_json::from_value(fixture("account")).unwrap();
    let saw_sentinel = accounts.iter().any(|a| {
        a.next_vesting_withdrawal.is_some_and(|t| t.is_maximum())
            || a.governance_vote_expiration_ts
                .is_some_and(|t| t.is_maximum())
            || a.last_owner_update.is_some_and(|t| t.is_maximum())
    });
    assert!(
        saw_sentinel,
        "expected at least one sentinel timestamp in a real account sample"
    );
}

#[test]
fn real_accounts_round_trip_through_json() {
    // Nothing is lost on the way in, including fields this build does not model.
    let raw = fixture("account");
    let accounts: Vec<Account> = serde_json::from_value(raw).unwrap();
    let reencoded = serde_json::to_value(&accounts).unwrap();
    let back: Vec<Account> = serde_json::from_value(reencoded).unwrap();
    assert_eq!(back, accounts);
}

#[test]
fn real_accounts_keep_unmodelled_fields() {
    let accounts: Vec<Account> = serde_json::from_value(fixture("account")).unwrap();
    // condenser_api returns history arrays and other fields this crate does not model;
    // they must survive in `extra` rather than being dropped.
    let total_extra: usize = accounts.iter().map(|a| a.extra.len()).sum();
    assert!(
        total_extra > 0,
        "real responses carry fields this build does not model; they must be kept"
    );
}

#[test]
fn parses_real_global_properties() {
    let props: DynamicGlobalProperties =
        serde_json::from_value(fixture("gprops")).expect("real global properties must parse");
    assert!(props.head_block_number > 100_000_000);
    assert_eq!(props.head_block_id.len(), 40);
    assert!(!props.current_witness.is_empty());

    // The block id must agree with the block number it is reported alongside.
    let block_ref = comb::BlockRef::from_block_id(&props.head_block_id).unwrap();
    assert_eq!(block_ref.block_num, props.head_block_number);
}

#[test]
fn vests_convert_using_real_totals() {
    let props: DynamicGlobalProperties = serde_json::from_value(fixture("gprops")).unwrap();
    let vests = comb::Amount::parse("1000000.000000 VESTS", comb::Chain::Hive).unwrap();

    let hive = props
        .vests_to_hive(&vests)
        .expect("global properties should carry the vesting totals")
        .unwrap();
    assert_eq!(hive.symbol(), "HIVE");
    assert!(hive.units() > 0, "a million VESTS is worth something");

    // Round-tripping should land close to where it started. Integer division loses at
    // most one unit per operation, so allow a small tolerance rather than requiring
    // exactness.
    let back = props.hive_to_vests(&hive).unwrap().unwrap();
    let drift = (back.units() - vests.units()).abs();
    assert!(
        drift <= vests.units() / 1_000_000 + 2,
        "round trip drifted by {drift} units"
    );
}

#[test]
fn parses_a_real_witness() {
    let witness: Witness =
        serde_json::from_value(fixture("witness")).expect("a real witness must parse");
    assert_eq!(witness.owner, "gtg");
    assert!(witness.votes() > 0, "an active witness has votes");
    // Vote weights exceed JSON's 2^53 safe range, which is why they arrive as strings.
    assert!(
        witness.votes() > (1i128 << 53),
        "witness votes should exceed the JSON safe integer range"
    );
    assert!(!witness.is_disabled());
    assert!(witness.signing_key.key().is_some());
}

#[test]
fn parses_real_resource_credits() {
    let value = fixture("rc");
    let accounts: Vec<RcAccount> =
        serde_json::from_value(value["rc_accounts"].clone()).expect("rc accounts must parse");
    assert_eq!(accounts.len(), 1);
    let rc = &accounts[0];
    assert_eq!(rc.account, "hiveio");

    // hived sends these as a bare number on this endpoint and as a string on others,
    // depending on magnitude and namespace. Both must work, which is why the field is
    // a serde_json::Value with an accessor rather than an i64.
    assert!(rc.max_rc() > 0, "max_rc should be positive");
    assert!(rc.rc_manabar.current_mana() > 0);

    let now = rc.rc_manabar.last_update_time + 1;
    let pct = rc.percentage(now);
    assert!((0.0..=100.0).contains(&pct), "rc percentage was {pct}");
    assert!(rc.current_rc(now) <= rc.max_rc());

    // max_rc_creation_adjustment arrives in the NAI object form, not as text.
    let adjustment = rc
        .max_rc_creation_adjustment
        .as_ref()
        .expect("rc_api sends max_rc_creation_adjustment");
    assert_eq!(adjustment.symbol(), "VESTS");
    assert_eq!(adjustment.precision(), 6);
}

#[test]
fn parses_the_real_price_feed() {
    let feed: FeedHistory =
        serde_json::from_value(fixture("feed")).expect("the feed history must parse");
    let rate = feed
        .current_median_history
        .rate()
        .expect("the median feed must have a non-zero quote");
    // A sanity band, not a price prediction: the feed is HBD per HIVE.
    assert!(
        rate > 0.0 && rate < 1000.0,
        "implausible median feed rate {rate}"
    );
    assert!(!feed.price_history.is_empty());
}

#[test]
fn parses_the_real_reward_funds() {
    let value = fixture("reward");
    let funds: Vec<RewardFund> =
        serde_json::from_value(value["funds"].clone()).expect("reward funds must parse");
    assert!(!funds.is_empty());
    let post = funds
        .iter()
        .find(|f| f.name == "post")
        .expect("a post reward fund");
    assert_eq!(post.reward_balance.symbol(), "HIVE");
    assert!(post.reward_balance.units() > 0);
}
