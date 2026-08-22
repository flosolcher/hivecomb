# Live fixtures

Real responses captured from a public Hive node, used by `tests/live_fixtures.rs`.

They exist because hand-written test JSON only contains what the author remembered.
These contain what the chain actually sends: sentinel timestamps rendered as
`1969-12-31T23:59:59`, numbers sent as strings because they exceed JSON's 53-bit safe
range, retired witnesses whose signing key is not a valid curve point, and fields added
by hardforks that this crate does not model yet.

Regenerate:

```sh
NODE=https://api.hive.blog
call() { curl -s -H 'Content-Type: application/json' \
  -d "{\"jsonrpc\":\"2.0\",\"method\":\"$1\",\"params\":$2,\"id\":1}" "$NODE" \
  | python3 -c 'import json,sys; json.dump(json.load(sys.stdin)["result"], sys.stdout, indent=1)'; }

call condenser_api.get_accounts '[["hiveio","blocktrades","gtg"]]'      > account.json
call database_api.get_dynamic_global_properties '{}'                    > gprops.json
call condenser_api.get_witness_by_account '["gtg"]'                     > witness.json
call rc_api.find_rc_accounts '{"accounts":["hiveio"]}'                  > rc.json
call database_api.get_feed_history '{}'                                 > feed.json
call database_api.get_reward_funds '{}'                                 > reward.json
```

The tests assert shapes and invariants, not specific balances, so a refreshed capture
should keep passing.
