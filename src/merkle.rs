//! Selective disclosure: proving one row was in a signed answer without showing the rest of it.
//!
//! The problem this exists for is the ordinary institutional one. A counterparty wants to check a
//! single line: that a particular transfer, position or balance is real. The holder is willing to
//! prove that line and unwilling to hand over the book it came from. A receipt as it stands is
//! all-or-nothing, because [`crate::canonical::result_hash`] folds every row into one digest and
//! you cannot check any part of it without every part of it.
//!
//! A Merkle tree over the *same* sorted row hashes fixes that and costs nothing to the existing
//! design: the leaves are exactly the list `result_hash` already builds, so a receipt gains a
//! second commitment to the same facts rather than a different set of them.
//!
//! # The shape, and why this one
//!
//! [RFC 6962](https://www.rfc-editor.org/rfc/rfc6962#section-2.1)'s tree, near enough verbatim.
//! Two properties are worth the fidelity:
//!
//! 1. **Leaves and internal nodes are domain-separated** by a `0x00` / `0x01` prefix. Without it a
//!    verifier can be handed an internal node dressed up as a leaf, and "this row was in the
//!    answer" becomes provable for a row that never was. That is the second-preimage attack, and it
//!    is the entire reason the prefixes exist.
//! 2. **An odd node is promoted, never duplicated.** Bitcoin duplicates the last hash on an odd
//!    level, which makes two different leaf lists produce the same root (CVE-2012-2459). Splitting
//!    at the largest power of two below `n`, as RFC 6962 does, has no such ambiguity.
//!
//! # What a disclosure does not hide
//!
//! **The leaves are not salted.** A sibling in the audit path is `SHA256(0x00 ‖ domain ‖
//! row_hash)`, so anyone holding a proof can test a guess at the neighbouring row by hashing it. For
//! the rows this is built for that is not a real attack: a row carrying a 160-bit address or a
//! `uint256` amount has far too much entropy to guess. For a result set whose rows are drawn from a
//! small space, a single low-cardinality column say, it is trivial, and a disclosure over that data
//! leaks its neighbours.
//!
//! Salting the leaves would close it, at the cost of the issuer holding a per-receipt secret
//! forever and of the tree no longer being built from the hashes `result_hash` already commits to.
//! That trade is not obviously right, so it is not made here, and the limit is stated instead. The
//! rule for a caller: disclose from answers whose rows contain an address or an amount, not from
//! answers whose rows are a flag.

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Separate from the `result_hash` domain on purpose. The two commitments are over the same facts
/// and must still be impossible to confuse: a Merkle root that could be read as a result hash would
/// let one be presented as the other.
const DOMAIN: &[u8] = b"tattler:merkle:v1";

const LEAF: u8 = 0x00;
const NODE: u8 = 0x01;

fn leaf_hash(row_hash: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([LEAF]);
    h.update(DOMAIN);
    h.update(row_hash);
    h.finalize().into()
}

fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([NODE]);
    h.update(DOMAIN);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// The largest power of two strictly less than `n`. `n` must be at least 2.
fn split(n: usize) -> usize {
    debug_assert!(n >= 2);
    let mut k = 1;
    while k * 2 < n {
        k *= 2;
    }
    k
}

/// The Merkle root of a list of row hashes, which the caller must already have sorted.
///
/// Sorting is the caller's job because the sorted list is the thing `result_hash` commits to, and
/// re-sorting here would hide a caller that passed the wrong list.
fn root_of(leaves: &[[u8; 32]]) -> [u8; 32] {
    match leaves.len() {
        // An answer with no rows is still an answer, and it needs a root that is not the root of
        // any other answer. Not `SHA256("")`, which is a value that turns up everywhere.
        0 => Sha256::digest(DOMAIN).into(),
        1 => leaf_hash(&leaves[0]),
        n => {
            let k = split(n);
            node_hash(&root_of(&leaves[..k]), &root_of(&leaves[k..]))
        }
    }
}

/// One step of the path from a leaf to the root.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Step {
    /// The sibling subtree's hash, hex with an `0x` prefix.
    pub sibling: String,
    /// Whether the sibling sits on the left. Carried explicitly rather than derived from an index,
    /// because a verifier that has to reconstruct the tree shape to know which side to concatenate
    /// is a verifier with a second implementation of the tree in it.
    pub sibling_is_left: bool,
}

/// A proof that one row was among the rows a receipt was signed over.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Inclusion {
    /// The disclosed row itself, verbatim as the endpoint returned it.
    pub row: serde_json::Value,
    /// Leaf to root. Empty for a one-row answer, which is not a defect: the disclosure is then the
    /// whole answer, and says so.
    pub path: Vec<Step>,
}

fn hex32(b: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(b))
}

fn unhex32(s: &str) -> Result<[u8; 32]> {
    let raw = hex::decode(s.strip_prefix("0x").unwrap_or(s))
        .map_err(|e| anyhow::anyhow!("not hex: {e}"))?;
    let out: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("expected 32 bytes, got {}", raw.len()))?;
    Ok(out)
}

/// The Merkle root over a result set, as hex.
pub fn merkle_root(rows: &[serde_json::Value]) -> Result<String> {
    Ok(hex32(&root_of(&crate::canonical::sorted_row_hashes(rows)?)))
}

/// Build a proof that `row` was in `rows`.
///
/// Fails if the row is not there, rather than returning a proof of something else. A caller asking
/// to disclose a row it does not have is a caller with a bug, and handing it a valid-looking proof
/// of the wrong row would be the worst possible response.
pub fn prove(rows: &[serde_json::Value], row: &serde_json::Value) -> Result<Inclusion> {
    let leaves = crate::canonical::sorted_row_hashes(rows)?;
    let target = crate::canonical::row_hash_public(row)?;
    let Some(index) = leaves.iter().position(|h| *h == target) else {
        bail!("that row is not in this answer, so there is nothing to prove about it");
    };

    let mut path = Vec::new();
    collect(&leaves, index, &mut path);
    Ok(Inclusion {
        row: row.clone(),
        path,
    })
}

/// Walk down the same split the root walks down, recording the sibling of whichever half holds the
/// target. Leaf to root order is produced by pushing on the way back out.
fn collect(leaves: &[[u8; 32]], index: usize, path: &mut Vec<Step>) {
    if leaves.len() < 2 {
        return;
    }
    let k = split(leaves.len());
    if index < k {
        collect(&leaves[..k], index, path);
        path.push(Step {
            sibling: hex32(&root_of(&leaves[k..])),
            sibling_is_left: false,
        });
    } else {
        collect(&leaves[k..], index - k, path);
        path.push(Step {
            sibling: hex32(&root_of(&leaves[..k])),
            sibling_is_left: true,
        });
    }
}

/// Recompute the root a disclosure implies, so a caller can compare it with the one a receipt was
/// signed over.
///
/// This deliberately returns the root rather than a boolean against an expected value: the
/// comparison belongs next to the signature check, where the expected root comes from a body whose
/// signature has already been verified. A function that took the expected root as an argument would
/// make it easy to check a proof against a root nobody authenticated, which proves nothing at all.
pub fn root_from_proof(proof: &Inclusion) -> Result<String> {
    let mut acc = leaf_hash(&crate::canonical::row_hash_public(&proof.row)?);
    for step in &proof.path {
        let sib = unhex32(&step.sibling)?;
        acc = if step.sibling_is_left {
            node_hash(&sib, &acc)
        } else {
            node_hash(&acc, &sib)
        };
    }
    Ok(hex32(&acc))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    /// Rows with enough shape to be realistic: an address and a uint256 as a string.
    fn rows(n: usize) -> Vec<Value> {
        (0..n)
            .map(|i| json!({"who": format!("0x{:040x}", i), "tokens": format!("{}000000000000000000", i + 1)}))
            .collect()
    }

    #[test]
    fn every_row_proves_against_the_root() {
        // Every size up to 17 so the odd splits, the powers of two and the ones either side of
        // them are all covered rather than the happy case being covered seventeen times.
        for n in 1..=17 {
            let rs = rows(n);
            let root = merkle_root(&rs).unwrap();
            for r in &rs {
                let p = prove(&rs, r).unwrap();
                assert_eq!(root_from_proof(&p).unwrap(), root, "n={n}");
            }
        }
    }

    #[test]
    fn a_row_that_was_not_in_the_answer_cannot_be_proved() {
        let rs = rows(8);
        let err = prove(&rs, &json!({"who": "0xdeadbeef", "tokens": "1"}))
            .unwrap_err()
            .to_string();
        assert!(err.contains("not in this answer"), "{err}");
    }

    /// The forgery the whole thing has to stop: taking a real proof and swapping the row.
    #[test]
    fn swapping_the_row_breaks_the_proof() {
        let rs = rows(8);
        let root = merkle_root(&rs).unwrap();
        let mut p = prove(&rs, &rs[3]).unwrap();
        p.row = json!({"who": "0xdeadbeef", "tokens": "999"});
        assert_ne!(root_from_proof(&p).unwrap(), root);
    }

    #[test]
    fn tampering_with_the_path_breaks_the_proof() {
        let rs = rows(8);
        let root = merkle_root(&rs).unwrap();
        let mut p = prove(&rs, &rs[3]).unwrap();
        p.path[0].sibling = format!("0x{}", "11".repeat(32));
        assert_ne!(root_from_proof(&p).unwrap(), root);
    }

    /// Flipping a side is the mistake a hand-written verifier makes, and it must not verify.
    #[test]
    fn flipping_a_side_in_the_path_breaks_the_proof() {
        let rs = rows(8);
        let root = merkle_root(&rs).unwrap();
        let mut p = prove(&rs, &rs[3]).unwrap();
        p.path[0].sibling_is_left = !p.path[0].sibling_is_left;
        assert_ne!(root_from_proof(&p).unwrap(), root);
    }

    /// Second preimage. An internal node presented as a leaf must not verify, which is what the
    /// `0x00` / `0x01` prefixes buy and the only reason they are there.
    #[test]
    fn an_internal_node_cannot_be_passed_off_as_a_leaf() {
        let leaves = crate::canonical::sorted_row_hashes(&rows(4)).unwrap();
        let internal = root_of(&leaves[..2]);
        // The forger's claim: `internal` is itself a leaf, so its hash should be a valid leaf hash.
        assert_ne!(leaf_hash(&internal), internal);
        assert_ne!(leaf_hash(&internal), node_hash(&leaves[0], &leaves[1]));
    }

    /// CVE-2012-2459 in miniature: with Bitcoin's duplicate-the-odd-node rule, `[a, b, b]` and
    /// `[a, b]` collide. With RFC 6962's split they must not.
    #[test]
    fn duplicating_the_last_row_changes_the_root() {
        let two = rows(2);
        let mut three = two.clone();
        three.push(two[1].clone());
        assert_ne!(merkle_root(&two).unwrap(), merkle_root(&three).unwrap());
    }

    #[test]
    fn the_root_does_not_depend_on_the_order_rows_arrive_in() {
        let a = rows(6);
        let mut b = a.clone();
        b.reverse();
        assert_eq!(merkle_root(&a).unwrap(), merkle_root(&b).unwrap());
    }

    #[test]
    fn different_answers_have_different_roots() {
        assert_ne!(merkle_root(&rows(4)).unwrap(), merkle_root(&rows(5)).unwrap());
    }

    #[test]
    fn an_empty_answer_has_a_root_of_its_own() {
        let empty = merkle_root(&[]).unwrap();
        assert!(empty.starts_with("0x"));
        assert_ne!(empty, merkle_root(&rows(1)).unwrap());
        // And not the digest of nothing, which is a value with a life of its own.
        assert_ne!(empty, hex32(&Sha256::digest(b"").into()));
    }

    /// A one-row answer has an empty path, and that is the honest outcome: disclosing the only row
    /// discloses everything. It must still verify rather than being a special case that fails.
    #[test]
    fn a_single_row_answer_proves_with_an_empty_path() {
        let rs = rows(1);
        let p = prove(&rs, &rs[0]).unwrap();
        assert!(p.path.is_empty());
        assert_eq!(root_from_proof(&p).unwrap(), merkle_root(&rs).unwrap());
    }

    /// The tree is over the same hashes the result hash commits to, so a float is refused in both
    /// places rather than only in one.
    #[test]
    fn a_float_is_refused_here_too() {
        let err = merkle_root(&[json!({"tokens": 1.5})]).unwrap_err().to_string();
        assert!(err.contains("floating-point"), "{err}");
    }

    /// Two identical rows are two facts. Proving one of them is proving a fact that is there, and
    /// the proof must verify whichever of the two positions it was built from.
    #[test]
    fn a_duplicated_row_still_proves() {
        let mut rs = rows(3);
        rs.push(rs[0].clone());
        let root = merkle_root(&rs).unwrap();
        let p = prove(&rs, &rs[0]).unwrap();
        assert_eq!(root_from_proof(&p).unwrap(), root);
    }

    #[test]
    fn a_malformed_sibling_is_an_error_not_a_mismatch() {
        let rs = rows(4);
        let mut p = prove(&rs, &rs[0]).unwrap();
        p.path[0].sibling = "0xnothex".into();
        assert!(root_from_proof(&p).is_err());
    }
}
