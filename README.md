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
tattler disclose --receipt receipt.json --matching k=v --out d.json  # one row, not the answer
tattler check-disclosure --disclosure d.json                  # offline, no rows required
```

Keys are read from a **file**, never a flag: argv is world-readable on Linux via `/proc`.

## Named queries, which are the better unit

An endpoint may publish declared queries a caller asks **by name and typed arguments**, never by
sending SQL. Attesting one of those is a stronger thing than attesting a statement you wrote:

```sh
tattler queries --endpoint https://www.lodestar-dashboard.com

tattler attest-named \
  --endpoint https://www.lodestar-dashboard.com \
  --name net_delegation_to_indexer \
  --arg indexer=0xf92f430dd8567b0d466358c79594ab58d919a6d4 \
  --arg before_block=497000000 \
  --key issuer.key --out receipt.json
```

**Why it is stronger.** A name is the unit two parties can agree on.
`net_delegation_to_indexer(0x…, 497000000)` means the same thing to both of them next year;
somebody's ad-hoc SELECT does not, and reading it back is an act of interpretation rather than of
verification. So a named receipt **replays by name**: the other endpoint answers the same declared
question using *its own* definition, rather than being asked to agree with your text. If the two
sides define the query differently, that is precisely the disagreement worth surfacing, and
replaying raw SQL would have hidden it — so `replay` prints both definitions when they differ.

The receipt keeps the statement as well as the name. Only the name would mean trusting the
endpoint's definition never changed; only the statement would throw away the agreement.

Arguments are sorted, so the same question asked twice signs identically.

### Adding these fields did not invalidate anything

`query_name` and `query_args` arrived after receipts were already in the world. Both are omitted
from the serialised body when unset, so an unnamed body signs exactly as it did before and every
receipt issued earlier still verifies. That is asserted directly, and the frozen fixture — issued
before either field existed — is checked by the current binary on every run.

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

## Showing one row and not the rest

A receipt is all-or-nothing: it carries its rows, so handing one over publishes the whole answer.
That is the wrong shape for the ordinary institutional case, where a counterparty wants to check a
single line and the holder will prove that line without publishing the book it came from.

Every receipt now also commits to a **Merkle root over the same sorted row hashes** the result hash
folds together. Not a second set of facts, the same ones, so the two commitments cannot disagree.

```sh
tattler disclose --receipt receipt.json --matching delegator=0x9ebe... --out disclosure.json
tattler check-disclosure --disclosure disclosure.json
```

A disclosure is the signed body and signature **with the rows removed**, plus the one chosen row and
its path to the root. Checking it establishes that the body is authentic and that the row was among
the rows it was signed over. A real disclosure of one delegation out of 34 is 1,991 bytes against
the receipt's 10,271, and carries six sibling hashes.

What the recipient learns: that row, how many rows there were, and the question. What they do not
learn is any other row, which is asserted against the bytes rather than described.

**The signature is checked before the proof, and the order is load-bearing.** The committed root is
a field in the body, so checking a proof first would be checking it against a number the presenter
chose.

**Two limits, both real.**

The leaves are **not salted**. Anyone holding a disclosure can test a guess at a neighbouring row by
hashing it. Against rows carrying an address or a `uint256` that is no help; against rows drawn from
a small set it is trivial. Salting would close it at the cost of the issuer holding a per-receipt
secret forever and of the tree no longer being built from the hashes the result hash already commits
to, and that trade is not obviously right, so the limit is stated instead.

Receipts issued before this existed **committed to no root**, so nothing can be disclosed from them.
`disclose` says so rather than computing a root now: a commitment chosen after the fact by whoever
wants to use it is not a commitment. Those receipts still verify exactly as they always did.

The tree is [RFC 6962](https://www.rfc-editor.org/rfc/rfc6962#section-2.1)'s, near enough verbatim,
for two properties worth the fidelity. Leaves and internal nodes are domain-separated by a `0x00` /
`0x01` prefix, without which an internal node can be passed off as a leaf and a row that was never in
the answer becomes provable. And an odd node is promoted rather than duplicated, which is what
Bitcoin does and what makes two different leaf lists produce one root (CVE-2012-2459). Both are
pinned by tests that fail if either property is removed.

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

27 in this repo plus 5 in Lodestar that run the *shipped* `.wasm` against the frozen fixture, so a
stale browser build cannot silently disagree with the CLI. `cargo test`. The ones worth reading are the negatives: adjacent strings that must not be
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
