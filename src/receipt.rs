//! The receipt: what gets signed, and what a stranger can check.
//!
//! **What a receipt proves.** That the holder of a particular key asserts these rows were the
//! answer this dataset gave to this question, pinned at this block, decoded by this registry. A
//! verifier with only the receipt can check the signature and that the rows still hash to the
//! claimed value — that is, that nobody edited a number after the fact.
//!
//! **What it does not prove, and this matters more than the part it does.** It does not make the
//! signer honest. A signed wrong answer is still a wrong answer, signed. What closes that gap is
//! `replay`: anyone with their own nest of the same dataset, sealed past the pinned block, can
//! re-run the query and compare hashes. The signature makes tampering detectable; replay makes
//! *lying* detectable, and only the second one is worth much. A receipt that has never been
//! replayed by someone else is a promise, not a proof.
//!
//! **Why the block pin is not optional.** nuthatch's `/sql` answers from sealed history plus the
//! unsealed tip. The tip moves: over one afternoon this dataset reported `as_of` 499,659,175 then
//! 499,659,807 then 499,666,752. An answer taken from a moving tip cannot be reproduced by anyone,
//! including the person who took it, ten seconds later. So a receipt carries the block it was
//! pinned to, and `replay` refuses to compare against a nest that has not sealed that far.

use anyhow::{bail, Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::canonical::result_hash;

/// The signed body. Field order is the signing order and must not be reshuffled.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Body {
    /// Which nest answered, by its nuthatch nest identity when it has one.
    pub nid: Option<String>,
    /// The dataset as the endpoint names it, for humans and for `replay` to aim at.
    pub dataset: String,
    /// The exact SQL. In the receipt because "the top 10" is only meaningful alongside the question
    /// that produced it.
    pub query: String,
    /// The block the answer is pinned to. Everything at or below this is sealed history.
    pub as_of_block: u64,
    /// How far the answering nest had sealed. Must be at least `as_of_block`, or the answer leaned
    /// on the moving tip and is not reproducible.
    pub sealed_through: u64,
    /// nuthatch's decode-registry content hash: *how* the rows were decoded, not just from where.
    pub registry_hash: Option<String>,
    /// The canonical hash of the rows. See `canonical.rs` for what it does and does not depend on.
    pub result_hash: String,
    /// How many rows. Redundant against `result_hash` and present so a mismatch says something
    /// useful ("47 rows, expected 48") rather than only "hashes differ".
    pub row_count: usize,
    /// RFC 3339, from the signer's clock. Evidence of when, not proof of when.
    pub issued_at: String,

    // ── Added after the first receipts were issued ───────────────────────────
    //
    // **Both fields must be absent from the serialised body when unset, and that is load-bearing
    // rather than tidy.** `signing_bytes` hashes this struct's own JSON; a field that serialises as
    // `null` would change those bytes and every receipt issued before today would stop verifying.
    // `skip_serializing_if` is what keeps the old ones valid, and the frozen fixture in
    // `tests/fixture.rs` is what proves it — it was issued before these existed.
    /// The declared query this answer came from, when it came from one.
    ///
    /// A name is the unit two parties can agree on. `delegations_to_indexer(0x…, 497000000)` means
    /// the same thing to both of them next year; somebody's ad-hoc SELECT does not, and reading it
    /// back is an act of interpretation rather than of verification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query_name: Option<String>,
    /// The arguments it was asked with, sorted by key so two identical questions serialise
    /// identically and therefore sign identically.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query_args: Option<std::collections::BTreeMap<String, String>>,
}

/// A receipt as written to disk: the signed body, the rows it attests to, and the signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    pub body: Body,
    /// Kept alongside so a receipt is self-contained. A verifier re-hashes these rather than
    /// trusting `body.result_hash`, which is the only reason including them is safe.
    pub rows: Vec<Value>,
    pub pubkey: String,
    pub signature: String,
}

/// Domain-separated preimage. Distinct from the result-hash domain so no signature over one can
/// ever be replayed as a signature over the other.
const DOMAIN: &[u8] = b"tattler:receipt:v1";

impl Body {
    /// The bytes actually signed.
    ///
    /// Built from the struct's own JSON with sorted keys rather than by hand-concatenating fields:
    /// a hand-written preimage silently stops covering any field added later, and a field that is
    /// in the receipt but outside the signature is a field an attacker can edit freely.
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        let value = serde_json::to_value(self)?;
        let mut buf = Vec::new();
        crate::canonical::encode_public(&value, &mut buf)?;
        let mut h = Sha256::new();
        h.update(DOMAIN);
        h.update(&buf);
        Ok(h.finalize().to_vec())
    }
}

/// Build and sign a receipt over an answer.
pub fn issue(body: Body, rows: Vec<Value>, key: &SigningKey) -> Result<Receipt> {
    let computed = result_hash(&rows)?;
    if computed != body.result_hash {
        bail!(
            "refusing to sign: the body claims {} but these rows hash to {computed}",
            body.result_hash
        );
    }
    if body.sealed_through < body.as_of_block {
        bail!(
            "refusing to sign: pinned at block {} but the nest has only sealed through {}, so this \
             answer includes unsealed tip data and nobody can reproduce it",
            body.as_of_block,
            body.sealed_through
        );
    }
    let sig = key.sign(&body.signing_bytes()?);
    Ok(Receipt {
        body,
        rows,
        pubkey: hex::encode(key.verifying_key().to_bytes()),
        signature: hex::encode(sig.to_bytes()),
    })
}

/// What checking a receipt can conclude.
#[derive(Debug, PartialEq)]
pub enum Verdict {
    Ok,
    /// The rows do not hash to what the body claims: something was edited after signing.
    RowsAltered {
        claimed: String,
        actual: String,
    },
    /// The signature does not match the body under the given key.
    BadSignature,
}

/// Check a receipt against itself. No network, no trust in the issuer.
///
/// Both checks are required and neither implies the other. A valid signature over a body whose
/// rows were swapped afterwards would pass the signature check alone, and re-hashing the rows alone
/// says nothing about who produced them.
pub fn verify(r: &Receipt) -> Result<Verdict> {
    let actual = result_hash(&r.rows)?;
    if actual != r.body.result_hash {
        return Ok(Verdict::RowsAltered {
            claimed: r.body.result_hash.clone(),
            actual,
        });
    }

    let key_bytes: [u8; 32] = hex::decode(&r.pubkey)
        .context("decoding the public key")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("a public key must be 32 bytes"))?;
    let sig_bytes: [u8; 64] = hex::decode(&r.signature)
        .context("decoding the signature")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("a signature must be 64 bytes"))?;

    let key = VerifyingKey::from_bytes(&key_bytes).context("parsing the public key")?;
    if key
        .verify(&r.body.signing_bytes()?, &Signature::from_bytes(&sig_bytes))
        .is_err()
    {
        return Ok(Verdict::BadSignature);
    }
    Ok(Verdict::Ok)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use serde_json::json;

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn rows() -> Vec<Value> {
        vec![json!({"block_number": 100, "tokens": "5000"})]
    }

    fn body(rows: &[Value]) -> Body {
        Body {
            nid: Some("nid-abc".into()),
            dataset: "staking".into(),
            query: "SELECT block_number, tokens FROM staking__tokens_delegated WHERE block_number <= 100".into(),
            as_of_block: 100,
            sealed_through: 200,
            registry_hash: Some("0xdeadbeef".into()),
            result_hash: result_hash(rows).unwrap(),
            row_count: rows.len(),
            issued_at: "2026-08-29T12:00:00Z".into(),
            query_name: None,
            query_args: None,
        }
    }

    #[test]
    fn a_freshly_issued_receipt_verifies() {
        let r = issue(body(&rows()), rows(), &key()).unwrap();
        assert_eq!(verify(&r).unwrap(), Verdict::Ok);
    }

    #[test]
    fn editing_a_row_after_signing_is_caught() {
        let mut r = issue(body(&rows()), rows(), &key()).unwrap();
        r.rows[0]["tokens"] = json!("9999");
        assert!(matches!(verify(&r).unwrap(), Verdict::RowsAltered { .. }));
    }

    #[test]
    fn deleting_a_row_after_signing_is_caught() {
        let two = vec![json!({"b": 1}), json!({"b": 2})];
        let mut r = issue(body(&two), two.clone(), &key()).unwrap();
        r.rows.pop();
        assert!(matches!(verify(&r).unwrap(), Verdict::RowsAltered { .. }));
    }

    /// The reason `signing_bytes` is derived from the struct rather than hand-written: every field
    /// in the body must be covered, so editing any of them breaks the signature.
    #[test]
    fn every_field_of_the_body_is_covered_by_the_signature() {
        let base = issue(body(&rows()), rows(), &key()).unwrap();

        type Mutation = (&'static str, fn(&mut Body));
        let mutate: Vec<Mutation> = vec![
            ("nid", |b| b.nid = Some("someone-else".into())),
            ("dataset", |b| b.dataset = "dips".into()),
            ("query", |b| b.query = "SELECT 1".into()),
            ("as_of_block", |b| b.as_of_block = 99),
            ("sealed_through", |b| b.sealed_through = 999),
            ("registry_hash", |b| b.registry_hash = Some("0xfeed".into())),
            ("row_count", |b| b.row_count = 42),
            ("issued_at", |b| b.issued_at = "2020-01-01T00:00:00Z".into()),
            // Without these, someone could relabel a receipt as the answer to a different declared
            // question while keeping the rows and the signature. The name is the part two parties
            // agree on, so it is the part most worth forging.
            ("query_name", |b| {
                b.query_name = Some("something_else".into())
            }),
            ("query_args", |b| {
                b.query_args = Some([("before_block".into(), "1".into())].into_iter().collect())
            }),
        ];

        for (name, f) in mutate {
            let mut r = base.clone();
            f(&mut r.body);
            assert_eq!(
                verify(&r).unwrap(),
                Verdict::BadSignature,
                "editing `{name}` was not caught, so it is outside the signature"
            );
        }
    }

    #[test]
    fn a_signature_from_another_key_does_not_pass() {
        let mut r = issue(body(&rows()), rows(), &key()).unwrap();
        r.pubkey = hex::encode(
            SigningKey::from_bytes(&[9u8; 32])
                .verifying_key()
                .to_bytes(),
        );
        assert_eq!(verify(&r).unwrap(), Verdict::BadSignature);
    }

    /// Signing an answer whose claimed hash does not match the rows would produce a receipt that
    /// fails verification the moment anyone looked. Fail at issue time instead.
    #[test]
    fn issuing_refuses_a_body_that_does_not_match_its_rows() {
        let mut b = body(&rows());
        b.result_hash = "0x00".into();
        assert!(issue(b, rows(), &key()).is_err());
    }

    /// The pin is the whole basis for reproducibility, so an unreproducible receipt must not exist.
    #[test]
    fn issuing_refuses_an_answer_that_leaned_on_the_unsealed_tip() {
        let mut b = body(&rows());
        b.as_of_block = 500;
        b.sealed_through = 499;
        let err = issue(b, rows(), &key()).unwrap_err().to_string();
        assert!(err.contains("unsealed"), "{err}");
    }

    fn named_body(rows: &[Value]) -> Body {
        let mut b = body(rows);
        b.query_name = Some("delegations_to_indexer".into());
        b.query_args = Some(
            [
                ("indexer".to_string(), "0xabc".to_string()),
                ("before_block".to_string(), "497000000".to_string()),
            ]
            .into_iter()
            .collect(),
        );
        b
    }

    #[test]
    fn a_named_receipt_verifies_and_keeps_its_question() {
        let r = issue(named_body(&rows()), rows(), &key()).unwrap();
        assert_eq!(verify(&r).unwrap(), Verdict::Ok);
        assert_eq!(r.body.query_name.as_deref(), Some("delegations_to_indexer"));
        assert_eq!(r.body.query_args.unwrap()["before_block"], "497000000");
    }

    /// The fields were added after receipts were already in the world. `skip_serializing_if` keeps
    /// an unnamed body serialising exactly as it did before, so the signature over it is unchanged
    /// and every existing receipt still verifies. Asserted directly rather than left to the fixture
    /// test to notice, because this is a property of the format, not of one file.
    #[test]
    fn adding_the_named_fields_did_not_change_an_unnamed_body() {
        let b = body(&rows());
        let json = serde_json::to_string(&b).unwrap();
        assert!(
            !json.contains("query_name"),
            "an unset field must not appear: {json}"
        );
        assert!(
            !json.contains("query_args"),
            "an unset field must not appear: {json}"
        );
    }

    /// Argument order must not change the signature, or the same question asked twice would produce
    /// receipts that disagree. A BTreeMap is what guarantees it; this is the test that says so.
    #[test]
    fn argument_order_does_not_change_the_signature() {
        let mut a = body(&rows());
        a.query_args = Some(
            [
                ("z".to_string(), "1".to_string()),
                ("a".to_string(), "2".to_string()),
            ]
            .into_iter()
            .collect(),
        );
        let mut b2 = body(&rows());
        b2.query_args = Some(
            [
                ("a".to_string(), "2".to_string()),
                ("z".to_string(), "1".to_string()),
            ]
            .into_iter()
            .collect(),
        );
        assert_eq!(a.signing_bytes().unwrap(), b2.signing_bytes().unwrap());
    }

    #[test]
    fn a_receipt_survives_a_round_trip_through_json() {
        let r = issue(body(&rows()), rows(), &key()).unwrap();
        let back: Receipt = serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
        assert_eq!(verify(&back).unwrap(), Verdict::Ok);
    }
}
