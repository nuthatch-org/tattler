//! Turning a result set into one hash that two people can compute independently.
//!
//! This is the whole load-bearing idea, so it is worth being precise about what is being claimed.
//! A receipt says: *these rows are what this dataset returned for this question as of this block.*
//! For that to be checkable by someone who does not trust us, the hash has to depend on the
//! **answer** and on nothing else. Anything else that leaks in — key ordering from a hash map, the
//! order rows happened to come off disk, whether a number arrived as `1` or `1.0` — makes an honest
//! reproduction disagree with an honest original, and a verifier that cries wolf is a verifier
//! nobody runs.
//!
//! Three decisions, each of which could have gone the other way:
//!
//! 1. **Rows are sorted, so row order does not matter.** A SQL result has no defined order without
//!    a total `ORDER BY`, and even with one, ties are free to come back either way. The alternative
//!    was to refuse queries without an unambiguous ordering, which is honest but rejects most real
//!    questions. Sorting means the receipt attests to the *set* of rows, which is what "what did
//!    the chain say" actually means. `SELECT … LIMIT 10` still attests to the ten rows returned;
//!    it does not attest that they are *the* ten, which is why the query text is in the receipt.
//!
//! 2. **Keys are sorted within a row**, so a serialiser that preserves insertion order and one that
//!    does not agree.
//!
//! 3. **Numbers are hashed as their decimal text, never as floats.** Token amounts here are
//!    `uint256`, routinely past 2^53, and nuthatch already returns them as JSON strings for that
//!    reason. Anything that round-trips a balance through an f64 has silently changed it. If a
//!    value ever arrives as a JSON float, this refuses rather than guesses.

use anyhow::{bail, Result};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// The hash domain. Present so a receipt hash can never be confused with any other hash this
/// project or nuthatch computes, and so a future encoding change is a visible break rather than a
/// silent disagreement.
const DOMAIN: &[u8] = b"tattler:result:v1";

/// Encode one JSON value into the canonical byte form, length-prefixing everything.
///
/// Length prefixes rather than separators: with separators, `["ab","c"]` and `["a","bc"]` can
/// encode identically, and a receipt whose hash collides across different answers is worse than no
/// receipt at all.
pub(crate) fn encode_public(value: &Value, out: &mut Vec<u8>) -> Result<()> {
    encode(value, out)
}

fn encode(value: &Value, out: &mut Vec<u8>) -> Result<()> {
    match value {
        Value::Null => out.push(b'0'),
        Value::Bool(b) => {
            out.push(b'1');
            out.push(if *b { 1 } else { 0 });
        }
        Value::String(s) => {
            out.push(b'2');
            out.extend_from_slice(&(s.len() as u64).to_be_bytes());
            out.extend_from_slice(s.as_bytes());
        }
        Value::Number(n) => {
            // Integers keep their exact decimal text. A float has already lost precision by the
            // time it reaches here, and pretending otherwise is how a receipt attests to a balance
            // that is not the balance.
            if n.is_f64() {
                bail!(
                    "refusing to hash the floating-point value {n}: a uint256 that has been through \
                     an f64 is no longer the number the chain holds. Cast it to a string in SQL."
                );
            }
            let s = n.to_string();
            out.push(b'3');
            out.extend_from_slice(&(s.len() as u64).to_be_bytes());
            out.extend_from_slice(s.as_bytes());
        }
        Value::Array(items) => {
            out.push(b'4');
            out.extend_from_slice(&(items.len() as u64).to_be_bytes());
            for item in items {
                encode(item, out)?;
            }
        }
        Value::Object(map) => {
            out.push(b'5');
            out.extend_from_slice(&(map.len() as u64).to_be_bytes());
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for k in keys {
                out.extend_from_slice(&(k.len() as u64).to_be_bytes());
                out.extend_from_slice(k.as_bytes());
                encode(&map[k], out)?;
            }
        }
    }
    Ok(())
}

/// The canonical hash of one row.
fn row_hash(row: &Value) -> Result<[u8; 32]> {
    let mut buf = Vec::new();
    encode(row, &mut buf)?;
    Ok(Sha256::digest(&buf).into())
}

/// The canonical hash of a whole result set.
///
/// Rows are hashed individually, those hashes are sorted, and the sorted list is hashed. Sorting
/// the hashes rather than the rows means the ordering rule is over fixed-width bytes and cannot
/// itself be a source of disagreement (no locale, no collation, no "is `10` before `9`").
///
/// Duplicate rows are kept, not deduplicated: two identical events at different log indexes are two
/// facts, and a receipt that quietly collapsed them would understate the answer.
pub fn result_hash(rows: &[Value]) -> Result<String> {
    let mut hashes: Vec<[u8; 32]> = rows.iter().map(row_hash).collect::<Result<_>>()?;
    hashes.sort_unstable();

    let mut h = Sha256::new();
    h.update(DOMAIN);
    h.update((hashes.len() as u64).to_be_bytes());
    for rh in &hashes {
        h.update(rh);
    }
    Ok(format!("0x{}", hex::encode(h.finalize())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn rows(v: Value) -> Vec<Value> {
        v.as_array().unwrap().clone()
    }

    #[test]
    fn the_same_rows_hash_the_same_way() {
        let a = rows(json!([{"block": 1, "who": "0xab"}, {"block": 2, "who": "0xcd"}]));
        assert_eq!(result_hash(&a).unwrap(), result_hash(&a.clone()).unwrap());
    }

    /// The point of sorting: an honest reproduction that returns the same facts in a different
    /// order must not be reported as a mismatch.
    #[test]
    fn row_order_does_not_change_the_hash() {
        let a = rows(json!([{"block": 1}, {"block": 2}]));
        let b = rows(json!([{"block": 2}, {"block": 1}]));
        assert_eq!(result_hash(&a).unwrap(), result_hash(&b).unwrap());
    }

    #[test]
    fn key_order_within_a_row_does_not_change_the_hash() {
        let a = rows(json!([{"block": 1, "who": "0xab"}]));
        let b = rows(json!([{"who": "0xab", "block": 1}]));
        assert_eq!(result_hash(&a).unwrap(), result_hash(&b).unwrap());
    }

    #[test]
    fn different_facts_hash_differently() {
        let a = rows(json!([{"block": 1}]));
        let b = rows(json!([{"block": 2}]));
        assert_ne!(result_hash(&a).unwrap(), result_hash(&b).unwrap());
    }

    /// A duplicated event is a second fact, not a rounding error.
    #[test]
    fn a_repeated_row_is_not_collapsed() {
        let one = rows(json!([{"block": 1}]));
        let two = rows(json!([{"block": 1}, {"block": 1}]));
        assert_ne!(result_hash(&one).unwrap(), result_hash(&two).unwrap());
    }

    #[test]
    fn an_empty_answer_still_has_a_hash() {
        assert!(result_hash(&[]).unwrap().starts_with("0x"));
        assert_ne!(result_hash(&[]).unwrap(), result_hash(&rows(json!([{}]))).unwrap());
    }

    /// The failure length-prefixing exists to prevent. Without it these two encode to the same
    /// bytes and a receipt would attest to an answer that was never given.
    #[test]
    fn adjacent_strings_cannot_be_confused_for_each_other() {
        let a = rows(json!([{"x": "ab", "y": "c"}]));
        let b = rows(json!([{"x": "a", "y": "bc"}]));
        assert_ne!(result_hash(&a).unwrap(), result_hash(&b).unwrap());
    }

    /// A key and a value must not be interchangeable either.
    #[test]
    fn a_key_cannot_be_swapped_with_a_value() {
        let a = rows(json!([{"ab": "cd"}]));
        let b = rows(json!([{"abc": "d"}]));
        assert_ne!(result_hash(&a).unwrap(), result_hash(&b).unwrap());
    }

    /// uint256 comes back from nuthatch as a string. If it ever arrives as a float it has already
    /// been damaged, and the honest response is to stop rather than to attest to the damage.
    #[test]
    fn a_float_is_refused_rather_than_quietly_rounded() {
        let err = result_hash(&rows(json!([{"tokens": 1.5}]))).unwrap_err().to_string();
        assert!(err.contains("floating-point"), "{err}");
    }

    #[test]
    fn a_big_integer_as_a_string_survives_exactly() {
        let big = "62100000000000000000000";
        let a = rows(json!([{"tokens": big}]));
        let b = rows(json!([{"tokens": "62100000000000000000001"}]));
        assert_ne!(result_hash(&a).unwrap(), result_hash(&b).unwrap());
    }

    /// A number and its decimal text are different values, and must not collide: otherwise a nest
    /// that changed a column's type would keep producing "matching" receipts.
    #[test]
    fn a_number_and_the_same_digits_as_a_string_differ() {
        let a = rows(json!([{"n": 1}]));
        let b = rows(json!([{"n": "1"}]));
        assert_ne!(result_hash(&a).unwrap(), result_hash(&b).unwrap());
    }

    #[test]
    fn null_is_not_the_same_as_an_absent_column() {
        let a = rows(json!([{"x": 1, "y": null}]));
        let b = rows(json!([{"x": 1}]));
        assert_ne!(result_hash(&a).unwrap(), result_hash(&b).unwrap());
    }
}
