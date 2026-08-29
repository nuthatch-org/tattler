# tattler

**Signed, replayable receipts for indexed chain data.** An answer you can hand to someone who has
no reason to trust you.

Named for the tattler, a shorebird that will not shut up when something approaches.

## The problem

An auditor asks what a contract paid out before a given block. Somebody runs a query and sends a
spreadsheet. Nothing in that spreadsheet says which dataset answered, how far it had indexed, how
the logs were decoded, or whether a number was edited on the way. The recipient's only options are
to trust the sender or to rebuild the whole index themselves.

## What a receipt is, and what it is not

A receipt says: *these rows are what this dataset returned for this question, pinned at this block,
decoded by this registry, signed by this key.*

- **`verify` proves nothing was edited after signing.** It is offline: no network, no trust in the
  issuer. It catches a changed number, a deleted row, a swapped field.
- **`verify` does not prove the answer is true.** A signed wrong answer is a wrong answer, signed.
- **`replay` is what closes that**, and it is the only verb that matters. Anyone with a nest of the
  same data, sealed past the pinned block, re-runs the question and compares hashes. Agreement
  between two parties who did not coordinate is evidence; a signature on its own is a promise.

A receipt nobody has replayed is a promise. The tool says so in its own output rather than letting
you forget.

## The block pin is not optional

nuthatch answers from sealed history **plus the unsealed tip**, and the tip moves. Over one
afternoon the same dataset reported `as_of` 499,659,175, then 499,659,807, then 499,666,752. An
answer taken from a moving tip cannot be reproduced by anyone, including the person who took it,
ten seconds later.

So a query must pin itself (`WHERE block_number <= N`), `attest` refuses if it cannot see the pin in
the query text, and it refuses to sign at all when the nest has not sealed that far. `replay`
refuses to compare against a nest that has not reached the pinned block: that mismatch would mean
"not caught up", and reporting it as a disagreement would train people to ignore real ones.

That guard fired on the first real use. `legacy-flows` had sealed through 497,855,497 against a
receipt pinned at 499,000,000, and it declined to render a verdict.

## Use

```sh
tattler keygen --out issuer.key

tattler attest \
  --endpoint https://www.lodestar-dashboard.com \
  --dataset staking \
  --query "SELECT block_number, delegator, tokens FROM staking__tokens_delegated
           WHERE block_number <= 497000000 ORDER BY block_number DESC LIMIT 5" \
  --as-of 497000000 \
  --key issuer.key --out receipt.json

tattler verify --receipt receipt.json                        # offline, no trust required
tattler replay --receipt receipt.json --endpoint <not theirs>  # the one that counts
```

Keys are read from a **file**, never a flag: argv is world-readable on Linux via `/proc`.

## Proven across two independent nests

The Helsinki box runs `staking` and `legacy-flows` as separately backfilled nests that both index
`TokensDelegated`. A receipt issued against one replays clean against the other:

```
receipt      0x87bace01dd464438c431fdac73191fb479f5d2ffbf02a20b4e784978ae91bab4
replay       0x87bace01dd464438c431fdac73191fb479f5d2ffbf02a20b4e784978ae91bab4
rows         5 vs 5
MATCH
```

Two indexes, built at different times from different configurations, computed the same answer.

## The canonical hash

The hash must depend on the answer and on nothing else, or an honest reproduction disagrees with an
honest original and nobody runs the verifier twice. See `src/canonical.rs`; the three decisions are:

- **Rows are sorted**, so row order does not matter. A SQL result has no defined order without a
  total `ORDER BY`, and ties are free either way. The receipt attests to the *set* of rows, which is
  what "what did the chain say" means. `LIMIT 10` attests to the ten rows returned, not that they
  are *the* ten, which is why the query text is in the signed body.
- **Keys are sorted within a row**, so an insertion-order serialiser and a sorted one agree.
- **Numbers are hashed as decimal text and floats are refused.** Token amounts are `uint256`,
  routinely past 2^53. A balance that has been through an `f64` is no longer the balance, and
  attesting to it would be attesting to the damage.

Everything is length-prefixed. With separators instead, `{"x":"ab","y":"c"}` and
`{"x":"a","y":"bc"}` encode identically, and a receipt whose hash collides across different answers
is worse than no receipt.

The signing preimage is derived from the body struct rather than hand-concatenated, because a
hand-written preimage silently stops covering any field added later, and a field inside the receipt
but outside the signature is a field an attacker edits for free. A test mutates **every** field in
turn and requires each one to break the signature.

## Tests

24, `cargo test`. The ones worth reading are the negatives: adjacent strings that must not be
confusable, a key that must not be swappable with a value, a repeated row that must not be
collapsed, a float that must be refused rather than rounded, the field-coverage test above, and the frozen fixture below.

## Verify in a browser

`wasm/` compiles the same crate to WebAssembly, so the browser runs the **same** canonicalisation
the CLI runs. A TypeScript reimplementation would be a second set of decisions about key ordering,
integer formatting and length prefixes, and the day the two disagree the verifier reports a forgery
that never happened. Anyone chasing that would be debugging the verifier while believing they were
auditing the data.

```sh
cargo build --release --target wasm32-unknown-unknown -p tattler-wasm
wasm-bindgen --target web --out-dir pkg --no-typescript \
  target/wasm32-unknown-unknown/release/tattler_wasm.wasm
```

The library carries no clock, no network and no randomness; everything needed to *issue* a receipt
sits behind the `cli` feature. So the browser build cannot generate a key and cannot make a request,
and therefore cannot report home about what it was asked to check. Not that it does not: that it
cannot, and `cargo tree` is the proof.

Live at [lodestar-dashboard.com/verify](https://www.lodestar-dashboard.com/verify), which is
convenience only — the page verifies entirely client-side, and checking a receipt against somebody's
server would mean trusting whoever runs it.

## The frozen fixture

`tests/fixtures/` holds a receipt issued against live production data, with its hash pinned in
`tests/fixture.rs`. The canonical hash is a **wire format**, not an implementation detail: a tidy-up
that looks harmless invalidates every receipt ever issued while every unit test in `canonical.rs`
keeps passing, because those only compare the implementation against itself. Deleting the row sort
fails the fixture test; that has been checked rather than assumed.

## Status

Early. It does what is written here and no more. In particular it does not verify ZK proofs or
view-key disclosures: it establishes the ground truth such a scheme would be checked *against*,
which is the half that did not exist.


Apache-2.0.
