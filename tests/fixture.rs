//! A receipt issued against live production data, frozen.
//!
//! This is the regression test that matters, and it is worth being clear about what it guards.
//!
//! The canonical hash is a **wire format**, not an implementation detail. Every receipt anyone has
//! ever issued is checked against it, so a change that looks like a harmless tidy-up — sorting rows
//! rather than row hashes, dropping a length prefix, formatting an integer differently — silently
//! invalidates every receipt in existence while every unit test in `canonical.rs` keeps passing.
//! Those tests only compare the implementation against itself.
//!
//! This one compares it against a value computed on a particular afternoon, from real rows the
//! Helsinki nest returned, and pinned here. If it fails, the format changed. That is allowed, but it
//! is a version bump and a note to anyone holding a receipt, not a refactor.

use tattler::{verify, Receipt, Verdict};

const FIXTURE: &str = include_str!("fixtures/receipt-staking-497000000.json");

/// Issued 2026-08-29 against the `staking` dataset on lodestar-dashboard.com, pinned at block
/// 497,000,000. The same hash was independently reproduced by the separately backfilled
/// `legacy-flows` nest, so it is not an artefact of one index.
const FROZEN_HASH: &str = "0x87bace01dd464438c431fdac73191fb479f5d2ffbf02a20b4e784978ae91bab4";

fn fixture() -> Receipt {
    serde_json::from_str(FIXTURE).expect("the fixture must parse")
}

#[test]
fn the_canonical_hash_has_not_changed_since_receipts_were_issued() {
    let r = fixture();
    assert_eq!(
        tattler::result_hash(&r.rows).unwrap(),
        FROZEN_HASH,
        "the canonical encoding changed: every receipt already issued now fails to verify. \
         If that is intended, bump the hash domain and say so; do not update this constant quietly."
    );
}

#[test]
fn a_real_receipt_still_verifies() {
    assert_eq!(verify(&fixture()).unwrap(), Verdict::Ok);
}

#[test]
fn the_body_says_what_it_was_pinned_to() {
    let b = fixture().body;
    assert_eq!(b.as_of_block, 497_000_000);
    assert_eq!(b.row_count, 5);
    // The pin is only meaningful if the nest had sealed past it; issuing refuses otherwise, and
    // this asserts the fixture is an example of the good case rather than of the refusal.
    assert!(b.sealed_through >= b.as_of_block);
    assert!(
        b.query.contains("497000000"),
        "the query must carry its own pin"
    );
}

/// Tampering with real data, not with a hand-built row.
#[test]
fn editing_the_real_receipt_is_caught() {
    let mut r = fixture();
    let tokens = r.rows[0]["tokens"].clone();
    r.rows[0]["tokens"] = serde_json::json!("999999999999999999999");
    assert_ne!(tokens, r.rows[0]["tokens"]);
    assert!(matches!(verify(&r).unwrap(), Verdict::RowsAltered { .. }));
}

// ── The named shape ─────────────────────────────────────────────────────────

const NAMED: &str = include_str!("fixtures/receipt-named-net-delegation.json");

/// Issued 2026-08-29 against `net_delegation_to_indexer`, and replayed by name to a match.
const NAMED_HASH: &str = "0x391879482d93e9984626f8b35e391a2f2b710aeb661f83328aca3eab3fdb25fd";

fn named() -> Receipt {
    serde_json::from_str(NAMED).expect("the named fixture must parse")
}

#[test]
fn a_named_receipt_from_production_still_verifies() {
    let r = named();
    assert_eq!(verify(&r).unwrap(), Verdict::Ok);
    assert_eq!(r.body.result_hash, NAMED_HASH);
    assert_eq!(
        r.body.query_name.as_deref(),
        Some("net_delegation_to_indexer")
    );
}

/// The pin must agree with the argument that produced it, or the receipt is unreplayable in a way
/// nobody would diagnose: `replay` would ask a different question and report a mismatch.
#[test]
fn the_pin_matches_the_argument_that_set_it() {
    let b = named().body;
    let args = b.query_args.expect("a named receipt records its arguments");
    assert_eq!(args["before_block"], b.as_of_block.to_string());
}

/// The receipt keeps the statement as well as the name. Only the name would mean trusting the
/// endpoint's definition never changed; only the statement would throw away the agreement.
#[test]
fn a_named_receipt_keeps_the_statement_it_ran() {
    let b = named().body;
    assert!(
        b.query.contains("497000000"),
        "the statement must carry the pin: {}",
        b.query
    );
    assert!(b.query.to_lowercase().contains("select"));
}
