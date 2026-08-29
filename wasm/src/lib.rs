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

/// The canonical result hash of a JSON array of rows, for anyone wanting to check the hash of data
/// they hold against a receipt they were sent.
#[wasm_bindgen]
pub fn result_hash(rows_json: &str) -> String {
    match serde_json::from_str::<Vec<serde_json::Value>>(rows_json) {
        Ok(rows) => match tattler::result_hash(&rows) {
            Ok(h) => out(true, "ok", Some(&h), None),
            Err(e) => out(false, "error", Some(&e.to_string()), None),
        },
        Err(e) => out(false, "malformed", Some(&format!("expected a JSON array of rows: {e}")), None),
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
