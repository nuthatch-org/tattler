//! `tattler` — signed, replayable receipts for indexed chain data.
//!
//! Four verbs, and the ordering of their importance is not the ordering of their obviousness:
//! `replay` is the one that matters, because a signature only makes tampering detectable and it is
//! replay that makes *lying* detectable.

use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use serde_json::Value;

use tattler::canonical::result_hash;
use tattler::receipt::{issue, verify, Body, Receipt, Verdict};

#[derive(Parser)]
#[command(
    name = "tattler",
    version,
    about = "Receipts for indexed chain data that a stranger can check."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate a signing key. Writes 32 raw bytes, hex, mode 600.
    Keygen {
        #[arg(long)]
        out: PathBuf,
    },
    /// Ask a nest a question and sign the answer.
    ///
    /// The query must pin a block (`WHERE block_number <= N`) so the answer does not depend on
    /// where the chain tip happened to be. `--as-of` states which N you pinned.
    Attest {
        /// Base URL of the SQL surface, e.g. https://www.lodestar-dashboard.com
        #[arg(long)]
        endpoint: String,
        /// Dataset id as the endpoint names it.
        #[arg(long)]
        dataset: String,
        /// The SQL. Must be pinned at or below `--as-of`.
        #[arg(long)]
        query: String,
        /// The block the answer is pinned to.
        #[arg(long)]
        as_of: u64,
        /// File holding the signing key, hex. A file rather than a flag: argv is world-readable on
        /// Linux via /proc.
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Attest a **declared** query, by name and arguments.
    ///
    /// A separate verb rather than more optional flags on `attest`, because the two are genuinely
    /// different acts: one signs whatever SQL you wrote, the other signs the answer to a question
    /// the endpoint publishes and both sides can look up. Squeezing them together would produce a
    /// command where half the flags are illegal depending on the other half.
    AttestNamed {
        #[arg(long)]
        endpoint: String,
        /// The declared query. `tattler queries --endpoint …` lists them.
        #[arg(long)]
        name: String,
        /// `key=value`, repeated. Types are the endpoint's to enforce.
        #[arg(long = "arg", value_parser = parse_arg)]
        args: Vec<(String, String)>,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// List the declared queries an endpoint will answer by name.
    Queries {
        #[arg(long)]
        endpoint: String,
    },
    /// Check a receipt against itself. No network, no trust in whoever issued it.
    Verify {
        #[arg(long)]
        receipt: PathBuf,
    },
    /// Re-run the receipt's question against a nest and compare.
    ///
    /// **This is the verb that turns a promise into a proof**, but only if you point it somewhere
    /// the issuer does not control: a nest you run, or one run by someone with no reason to agree
    /// with them. Replaying against the issuer's own endpoint shows the answer is stable, which is
    /// a much smaller claim.
    Replay {
        #[arg(long)]
        receipt: PathBuf,
        /// The endpoint to re-run against. Use one you trust, which should not be the issuer's.
        #[arg(long)]
        endpoint: String,
        /// Override the dataset id if the replaying endpoint names it differently.
        #[arg(long)]
        dataset: Option<String>,
    },
}

/// What a nuthatch-backed SQL surface returns. Only the parts a receipt needs.
#[derive(serde::Deserialize)]
struct SqlResponse {
    #[serde(default)]
    rows: Vec<Value>,
    #[serde(default)]
    error: Option<String>,
    /// Only the named endpoint sends this, and only on a refusal: the set of declared names.
    #[serde(default)]
    allowed: Option<Vec<String>>,
    /// The statement the endpoint actually ran. Named responses carry it; free-form ones do not,
    /// because there the caller already has it.
    #[serde(default)]
    sql: Option<String>,
    /// Which dataset answered, so a named receipt records it without the caller having to know.
    #[serde(default)]
    dataset: Option<String>,
    #[serde(default)]
    truncated: bool,
    #[serde(default)]
    degraded: bool,
    #[serde(default)]
    provenance: Option<Provenance>,
}

#[derive(serde::Deserialize)]
struct Provenance {
    #[serde(default)]
    sealed_through: Option<u64>,
    #[serde(default)]
    registry_hash: Option<String>,
    #[serde(default)]
    nid: Option<String>,
}

/// Ask a declared query by name.
///
/// The endpoint returns the statement it actually ran, and the receipt records both: the name is
/// what two parties agree on, the statement is what the nest answered. Keeping only the name would
/// mean trusting the endpoint's definition never changed; keeping only the statement would throw
/// away the agreement.
fn ask_named(
    endpoint: &str,
    name: &str,
    args: &std::collections::BTreeMap<String, String>,
) -> Result<SqlResponse> {
    let url = format!("{}/api/sql/named", endpoint.trim_end_matches('/'));
    let res = ureq::post(&url)
        .set("Content-Type", "application/json")
        .send_json(ureq::json!({ "name": name, "args": args }));

    let body: SqlResponse = match res {
        Ok(r) => r.into_json().context("reading the response")?,
        Err(ureq::Error::Status(_, r)) => r.into_json().context("reading the error response")?,
        Err(e) => bail!("could not reach {url}: {e}"),
    };

    if let Some(err) = body.error {
        let allowed = body
            .allowed
            .as_ref()
            .map(|a| format!(" Allowed: {}.", a.join(", ")))
            .unwrap_or_default();
        bail!("the endpoint refused it: {err}{allowed}");
    }
    if body.truncated {
        bail!("the answer hit the row cap, so it is not the whole answer.");
    }
    if body.degraded {
        bail!(
            "the nest reported degraded tables, so this answer is missing data it should have had."
        );
    }
    Ok(body)
}

fn ask(endpoint: &str, dataset: &str, query: &str) -> Result<SqlResponse> {
    let url = format!("{}/api/sql/query", endpoint.trim_end_matches('/'));
    let res = ureq::post(&url)
        .set("Content-Type", "application/json")
        .send_json(ureq::json!({ "dataset": dataset, "q": query }));

    let body: SqlResponse = match res {
        Ok(r) => r.into_json().context("reading the response")?,
        // A 4xx carries the nest's own error text, which is the useful part.
        Err(ureq::Error::Status(_, r)) => r.into_json().context("reading the error response")?,
        Err(e) => bail!("could not reach {url}: {e}"),
    };

    if let Some(err) = body.error {
        bail!("the dataset refused the query: {err}");
    }
    // Both of these mean the answer is not the whole answer, and signing a partial answer as though
    // it were complete is the exact failure this tool exists to prevent.
    if body.truncated {
        bail!("the answer hit the row cap, so it is not the whole answer. Narrow the query.");
    }
    if body.degraded {
        bail!(
            "the nest reported degraded tables, so this answer is missing data it should have had."
        );
    }
    Ok(body)
}

/// `k=v`, split on the first `=` so a value may contain one.
fn parse_arg(s: &str) -> Result<(String, String), String> {
    match s.split_once('=') {
        Some((k, v)) if !k.is_empty() => Ok((k.to_string(), v.to_string())),
        _ => Err(format!("expected key=value, got `{s}`")),
    }
}

fn load_key(path: &PathBuf) -> Result<SigningKey> {
    let raw =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let bytes: [u8; 32] = hex::decode(raw.trim())
        .context("the key file must be 32 bytes of hex")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("a signing key must be 32 bytes"))?;
    Ok(SigningKey::from_bytes(&bytes))
}

fn read_receipt(path: &PathBuf) -> Result<Receipt> {
    let raw =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_str(&raw).context("parsing the receipt")
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Keygen { out } => {
            let key = SigningKey::generate(&mut rand_core::OsRng);
            std::fs::write(&out, hex::encode(key.to_bytes()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o600))?;
            }
            println!("key      {}", out.display());
            println!("pubkey   {}", hex::encode(key.verifying_key().to_bytes()));
        }

        Cmd::Attest {
            endpoint,
            dataset,
            query,
            as_of,
            key,
            out,
        } => {
            // Checked here rather than trusted: a receipt whose query is not actually pinned would
            // carry an `as_of_block` that describes nothing, and would fail replay for reasons
            // nobody could diagnose.
            if !query.contains(&as_of.to_string()) {
                bail!(
                    "the query does not mention block {as_of}, so it is probably not pinned to it. \
                     Add `WHERE block_number <= {as_of}` — without a pin the answer moves with the \
                     chain tip and nobody, including you, can reproduce it."
                );
            }

            let answer = ask(&endpoint, &dataset, &query)?;
            let prov = answer.provenance.as_ref();
            let sealed = prov.and_then(|p| p.sealed_through).context(
                "the endpoint returned no sealed_through, so reproducibility cannot be checked",
            )?;

            let body = Body {
                nid: prov.and_then(|p| p.nid.clone()),
                dataset: dataset.clone(),
                query: query.clone(),
                as_of_block: as_of,
                sealed_through: sealed,
                registry_hash: prov.and_then(|p| p.registry_hash.clone()),
                result_hash: result_hash(&answer.rows)?,
                row_count: answer.rows.len(),
                issued_at: time::OffsetDateTime::now_utc()
                    .format(&time::format_description::well_known::Rfc3339)?,
                // Free-form: there is no declared question to record, and inventing one would be
                // claiming an agreement that does not exist.
                query_name: None,
                query_args: None,
            };

            let receipt = issue(body, answer.rows, &load_key(&key)?)?;
            std::fs::write(&out, serde_json::to_string_pretty(&receipt)?)?;

            println!("receipt      {}", out.display());
            println!("rows         {}", receipt.body.row_count);
            println!("as of block  {}", receipt.body.as_of_block);
            println!("result       {}", receipt.body.result_hash);
            println!("pubkey       {}", receipt.pubkey);
            println!();
            println!("This is a promise until somebody else replays it:");
            println!(
                "  tattler replay --receipt {} --endpoint <a nest you trust>",
                out.display()
            );
        }

        Cmd::Queries { endpoint } => {
            let url = format!("{}/api/sql/named", endpoint.trim_end_matches('/'));
            let body: Value = ureq::get(&url)
                .call()
                .with_context(|| format!("could not reach {url}"))?
                .into_json()?;
            let queries = body["queries"].as_array().cloned().unwrap_or_default();
            if queries.is_empty() {
                println!("This endpoint declares no named queries.");
            }
            for q in queries {
                println!(
                    "{}  [{}]",
                    q["name"].as_str().unwrap_or("?"),
                    q["dataset"].as_str().unwrap_or("?")
                );
                if let Some(d) = q["description"].as_str() {
                    println!("    {d}");
                }
                for p in q["params"].as_array().cloned().unwrap_or_default() {
                    println!(
                        "    --arg {}=<{}>",
                        p["name"].as_str().unwrap_or("?"),
                        p["type"].as_str().unwrap_or("?")
                    );
                }
                println!();
            }
        }

        Cmd::AttestNamed {
            endpoint,
            name,
            args,
            key,
            out,
        } => {
            let args: std::collections::BTreeMap<String, String> = args.into_iter().collect();
            let answer = ask_named(&endpoint, &name, &args)?;
            let prov = answer.provenance.as_ref();
            let sealed = prov.and_then(|p| p.sealed_through).context(
                "the endpoint returned no sealed_through, so reproducibility cannot be checked",
            )?;

            // Every declared query pins itself, and the endpoint enforces that. Read the pin back
            // out of the argument rather than asking for it twice: a receipt whose `as_of_block`
            // disagreed with the argument that produced it would be quietly unreplayable.
            let as_of: u64 = args
                .get("before_block")
                .context("this query has no `before_block`, so its answer is not reproducible")?
                .parse()
                .context("`before_block` must be a whole number")?;

            let body = Body {
                nid: prov.and_then(|p| p.nid.clone()),
                dataset: answer.dataset.clone().unwrap_or_else(|| "unknown".into()),
                query: answer
                    .sql
                    .clone()
                    .context("the endpoint did not return the statement it ran")?,
                as_of_block: as_of,
                sealed_through: sealed,
                registry_hash: prov.and_then(|p| p.registry_hash.clone()),
                result_hash: result_hash(&answer.rows)?,
                row_count: answer.rows.len(),
                issued_at: time::OffsetDateTime::now_utc()
                    .format(&time::format_description::well_known::Rfc3339)?,
                query_name: Some(name.clone()),
                query_args: Some(args),
            };

            let receipt = issue(body, answer.rows, &load_key(&key)?)?;
            std::fs::write(&out, serde_json::to_string_pretty(&receipt)?)?;

            println!("receipt      {}", out.display());
            println!("query        {name}");
            println!("rows         {}", receipt.body.row_count);
            println!("as of block  {}", receipt.body.as_of_block);
            println!("result       {}", receipt.body.result_hash);
            println!();
            println!(
                "A named receipt replays by name, so the other side does not have to agree with"
            );
            println!("your SQL, only with the question:");
            println!(
                "  tattler replay --receipt {} --endpoint <a nest you trust>",
                out.display()
            );
        }

        Cmd::Verify { receipt } => {
            let r = read_receipt(&receipt)?;
            match verify(&r)? {
                Verdict::Ok => {
                    println!("signature    ok");
                    println!(
                        "rows         {}, hashing to {}",
                        r.body.row_count, r.body.result_hash
                    );
                    println!("pubkey       {}", r.pubkey);
                    println!();
                    println!("This says the rows are unedited since signing. It does NOT say they are true.");
                    println!("For that, replay against a nest the issuer does not run.");
                }
                Verdict::RowsAltered { claimed, actual } => {
                    eprintln!("ROWS ALTERED");
                    eprintln!("  claimed  {claimed}");
                    eprintln!("  actual   {actual}");
                    std::process::exit(1);
                }
                Verdict::BadSignature => {
                    eprintln!(
                        "BAD SIGNATURE - the body was changed, or this is not that key's receipt"
                    );
                    std::process::exit(1);
                }
            }
        }

        Cmd::Replay {
            receipt,
            endpoint,
            dataset,
        } => {
            let r = read_receipt(&receipt)?;
            if verify(&r)? != Verdict::Ok {
                bail!(
                    "the receipt does not verify against itself; replaying it would prove nothing"
                );
            }
            let ds = dataset.unwrap_or_else(|| r.body.dataset.clone());

            // A named receipt replays **by name**, and that is a stronger check than replaying its
            // SQL. Re-sending the stored statement asks the other nest to agree with our text;
            // asking by name asks it to answer the same declared question with its own definition.
            // If the two endpoints disagree about what `delegations_to_indexer` means, that is
            // exactly the disagreement worth surfacing, and replaying raw SQL would hide it.
            let answer = match (&r.body.query_name, &r.body.query_args) {
                (Some(name), Some(args)) => {
                    println!("asking      {name} by name");
                    ask_named(&endpoint, name, args)?
                }
                _ => ask(&endpoint, &ds, &r.body.query)?,
            };

            // A named replay whose statement differs is not automatically wrong — the other side
            // may define the query differently — but the reader must be told, or a hash match would
            // imply an agreement about the question that was never checked.
            if let (Some(name), Some(theirs)) = (&r.body.query_name, &answer.sql) {
                if theirs != &r.body.query {
                    eprintln!("note: this endpoint defines `{name}` differently:");
                    eprintln!("  receipt: {}", r.body.query.replace('\n', " "));
                    eprintln!("  here:    {}", theirs.replace('\n', " "));
                }
            }
            let sealed = answer
                .provenance
                .as_ref()
                .and_then(|p| p.sealed_through)
                .unwrap_or(0);

            // Comparing against a nest that has not reached the pinned block would produce a
            // mismatch that means "not caught up", not "the issuer lied". Refuse rather than
            // report a disagreement the operator would take at face value.
            if sealed < r.body.as_of_block {
                bail!(
                    "this nest has sealed through {sealed} but the receipt is pinned at {}. It has \
                     not indexed far enough to have an opinion; wait, and try again.",
                    r.body.as_of_block
                );
            }

            let actual = result_hash(&answer.rows)?;
            println!("receipt      {}", r.body.result_hash);
            println!("replay       {actual}");
            println!("rows         {} vs {}", r.body.row_count, answer.rows.len());
            if actual == r.body.result_hash {
                println!();
                println!("MATCH - this nest computed the same answer from its own sealed history.");
                // Deliberately not "two independent parties". The receipt does not record where it
                // was issued from, and it could not usefully: an issuer would be free to write
                // anything there. So this tool cannot tell a genuine cross-check from a replay
                // against the issuer's own box, and asserting independence it has not established
                // would be the same species of unearned claim the receipt exists to make
                // detectable.
                println!(
                    "Whether that is worth anything depends on who runs {endpoint}. Independence is\n\
                     yours to arrange; this tool cannot check it."
                );
            } else {
                eprintln!();
                eprintln!("MISMATCH - this nest does not agree with the receipt.");
                eprintln!(
                    "Both may be honest: a different registry decodes the same logs differently."
                );
                eprintln!("  receipt registry  {:?}", r.body.registry_hash);
                eprintln!(
                    "  replay registry   {:?}",
                    answer
                        .provenance
                        .as_ref()
                        .and_then(|p| p.registry_hash.clone())
                );
                std::process::exit(1);
            }
        }
    }
    Ok(())
}
