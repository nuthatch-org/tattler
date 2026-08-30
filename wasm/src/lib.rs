//! The tattler verifier, in the browser.
//!
//! **Why this is a WASM build and not a TypeScript rewrite.** Verification hinges on two parties
//! computing byte-identical canonical bytes. A second implementation in another language is a
//! second set of decisions about key ordering, integer formatting and length prefixes, and the day
//! the two disagree the verifier reports a forgery that never happened. Anyone chasing that would
//! be debugging the verifier while believing they were auditing the data. So the browser runs the
//! same compiled Rust the CLI runs; there is one canonicalisation and it lives in `canonical.rs`.
//!
//! The other property worth naming: this runs **entirely in the reader's browser**. Checking a
//! receipt against a server would mean trusting whoever runs the server, which is the exact thing
//! a receipt exists to avoid.

use wasm_bindgen::prelude::*;

/// Verify a receipt supplied as JSON text.
///
/// Returns JSON: `{ok, verdict, detail?, body?}`. A string rather than a rich type because the
/// failure cases are as important as the success and a thrown exception encourages callers to
/// treat "malformed" and "forged" as the same thing. They are not: one is a bad paste, the other
/// is somebody lying.
#[wasm_bindgen]
pub fn verify_receipt(json: &str) -> String {
    let parsed: Result<tattler::Receipt, _> = serde_json::from_str(json);
    let receipt = match parsed {
        Ok(r) => r,
        Err(e) => {
            return out(
                false,
                "malformed",
                Some(&format!("this is not a tattler receipt: {e}")),
                None,
            )
        }
    };

    match tattler::verify(&receipt) {
        Ok(tattler::Verdict::Ok) => {
            let body = serde_json::to_string(&receipt.body).unwrap_or_default();
            out(true, "ok", None, Some(&body))
        }
        Ok(tattler::Verdict::RowsAltered { claimed, actual }) => out(
            false,
            "rows_altered",
            Some(&format!(
                "the rows in this receipt hash to {actual}, but it claims {claimed}. Somebody \
                 changed the data after it was signed."
            )),
            None,
        ),
        Ok(tattler::Verdict::BadSignature) => out(
            false,
            "bad_signature",
            Some(
                "the signature does not cover this body. Either a field was edited, or this \
                 receipt was not signed by the key it names.",
            ),
            None,
        ),
        Err(e) => out(false, "error", Some(&e.to_string()), None),
    }
}

/// Verify a **disclosure**: one row proved to have been in a signed answer, without the answer.
///
/// A separate entry point from [`verify_receipt`] rather than one that sniffs the shape, because
/// the two say different things and a reader must not be left guessing which they were told. A
/// receipt says "these are all the rows". A disclosure says "this row was among rows you are not
/// being shown", and how many there were.
#[wasm_bindgen]
pub fn verify_disclosure(json: &str) -> String {
    use tattler::receipt::DisclosureVerdict as V;

    let parsed: Result<tattler::receipt::Disclosure, _> = serde_json::from_str(json);
    let d = match parsed {
        Ok(d) => d,
        Err(e) => {
            return out(
                false,
                "malformed",
                Some(&format!("this is not a tattler disclosure: {e}")),
                None,
            )
        }
    };

    match tattler::receipt::check_disclosure(&d) {
        Ok(V::Ok) => {
            let mut body = serde_json::to_value(&d.body).unwrap_or_default();
            // The disclosed row travels with the body so the page can show what was proved
            // alongside what it was proved against, rather than in a second parse.
            if let Some(obj) = body.as_object_mut() {
                obj.insert("disclosed_row".into(), d.proof.row.clone());
                obj.insert("path_len".into(), d.proof.path.len().into());
            }
            out(true, "ok", None, Some(&body.to_string()))
        }
        Ok(V::BadSignature) => out(
            false,
            "bad_signature",
            Some(
                "the signature does not cover this body, so nothing under it was checked. Either \
                 a field was edited or it was not signed by the key it names.",
            ),
            None,
        ),
        Ok(V::NotProven { committed, actual }) => out(
            false,
            "not_proven",
            Some(&format!(
                "the body is signed, and this row does not belong to it: the proof leads to \
                 {actual}, and the answer committed to {committed}. Either the row was not in the \
                 answer or the path was altered, and this cannot tell which."
            )),
            None,
        ),
        Ok(V::NoCommitment) => out(
            false,
            "no_commitment",
            Some(
                "the receipt this came from predates Merkle commitments, so it committed to \
                 nothing a proof could be checked against.",
            ),
            None,
        ),
        Err(e) => out(false, "error", Some(&e.to_string()), None),
    }
}

/// The canonical result hash of a JSON array of rows, for anyone wanting to check the hash of data
/// they hold against a receipt they were sent.
#[wasm_bindgen]
pub fn result_hash(rows_json: &str) -> String {
    match serde_json::from_str::<Vec<serde_json::Value>>(rows_json) {
        Ok(rows) => match tattler::result_hash(&rows) {
            Ok(h) => out(true, "ok", Some(&h), None),
            Err(e) => out(false, "error", Some(&e.to_string()), None),
        },
        Err(e) => out(
            false,
            "malformed",
            Some(&format!("expected a JSON array of rows: {e}")),
            None,
        ),
    }
}

fn out(ok: bool, verdict: &str, detail: Option<&str>, body: Option<&str>) -> String {
    let mut v = serde_json::json!({ "ok": ok, "verdict": verdict });
    if let Some(d) = detail {
        v["detail"] = serde_json::Value::String(d.to_string());
    }
    if let Some(b) = body {
        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(b) {
            v["body"] = parsed;
        }
    }
    v.to_string()
}

/// Sign an answer into a receipt.
///
/// **Here rather than in TypeScript, and that is the whole point of this crate.** A second
/// implementation of the canonical encoding would be a second set of decisions about key ordering,
/// integer formatting and length prefixes, and the day they disagree a verifier reports a forgery
/// that never happened. Issuing and verifying must share one implementation or neither is worth
/// anything.
///
/// Signing needs no randomness - Ed25519 is deterministic - so this stays inside the
/// `--no-default-features` build that cannot generate a key or open a socket.
///
/// `body_json` is the receipt body; `rows_json` the rows it attests to; `key_hex` 32 bytes of hex.
/// The key is a **server-side secret**: calling this in a browser would hand it to the reader.
#[wasm_bindgen]
pub fn issue_receipt(body_json: &str, rows_json: &str, key_hex: &str) -> String {
    let body: tattler::Body = match serde_json::from_str(body_json) {
        Ok(b) => b,
        Err(e) => return out(false, "malformed", Some(&format!("bad body: {e}")), None),
    };
    let rows: Vec<serde_json::Value> = match serde_json::from_str(rows_json) {
        Ok(r) => r,
        Err(e) => return out(false, "malformed", Some(&format!("bad rows: {e}")), None),
    };
    let bytes: [u8; 32] = match hex::decode(key_hex.trim()).ok().and_then(|v| v.try_into().ok()) {
        Some(b) => b,
        None => return out(false, "error", Some("the signing key must be 32 bytes of hex"), None),
    };
    let key = ed25519_dalek::SigningKey::from_bytes(&bytes);

    match tattler::issue(body, rows, &key) {
        Ok(receipt) => match serde_json::to_string(&receipt) {
            Ok(json) => json,
            Err(e) => out(false, "error", Some(&e.to_string()), None),
        },
        // `issue` refuses a body whose hash does not match its rows, and one pinned past what the
        // nest has sealed. Both are refusals to sign something unreproducible, and both should
        // reach the caller as themselves rather than as "failed".
        Err(e) => out(false, "refused", Some(&e.to_string()), None),
    }
}
