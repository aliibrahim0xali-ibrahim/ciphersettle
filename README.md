# CipherSettle — Phase 1 PoC

## Round 5: full test pass, and a spec/implementation drift found

A from-scratch clean rebuild (`rm -rf target`, full `cargo build`/`test`/`clippy`
on the whole workspace) confirmed round 4's results still hold, and turned
up one real gap manual review across four rounds had missed: `ProtocolState`
is documented (see "Treat `ProtocolState` as the executable spec" below) as
the source of truth to change first, with the canister following -- but
round 3's `register_invoice` oracle fix (collapsing the "duplicate
fingerprint" and "duplicate invoice_id" error messages into one, see round
3's §1) had only ever been applied to `ciphersettle_backend` directly. The
spec itself still had the old, distinguishable error messages, meaning
anyone extending the protocol by changing `ProtocolState` first -- exactly
the workflow this repo tells you to use -- risked reintroducing the exact
oracle round 3 closed, without realizing the spec no longer matched
deployed behavior. **Fixed**: `ProtocolState::register_invoice` now
collapses the same way the canister does, with two new tests locking in
that the messages stay identical and that the specific reason is still
logged for admin diagnosis. 84 tests now pass in `ciphersettle_core` (was
82), 85 across the workspace.

## Round 4: first review with a working compiler on the full workspace

Every prior round's review of `ciphersettle_backend` was a manual trace
against Rust's type system, since the crate had never compiled in this
environment. That wall came down this round (see the pin block in
`src/ciphersettle_backend/Cargo.toml`), which made three new things
possible: an actual `cargo build`/`test`/`clippy` on the whole workspace,
a mechanically-generated Candid interface to check `ciphersettle_backend.did`
against instead of reading both by hand, and a fresh compiler-backed trace
of round 3's fixes rather than re-reading them in isolation.

| Round 4 finding | Status |
|---|---|
| `get_audit_log`'s `offset: Option<u64>` was cast `as usize` with no bounds check. IC canisters compile to `wasm32-unknown-unknown`, where `usize` is 32 bits -- an offset past `u32::MAX` would silently wrap instead of erroring, returning a page computed from the wrong offset rather than an empty result | **Fixed** -- `usize::try_from(offset).unwrap_or(usize::MAX)`; an out-of-range offset now degrades to "skip past everything" instead of wrapping. Not an access-control issue (the endpoint is already fully gated), but a real correctness bug host-target testing alone can't surface. Found by `clippy::pedantic`'s `cast_possible_truncation` lint. |
| `get_encrypted_invoice` cloned up to 64 KB of ciphertext unnecessarily on every read | **Fixed** -- `StableBTreeMap::get` already returns an owned value; `.clone()` was redundant. Found by `clippy::nursery`'s `redundant_clone` lint. Efficiency fix, not a security one. |
| `ciphersettle_backend.did` had only ever been checked against Rust signatures by hand, across three prior rounds | **Now mechanically verified** -- a `#[cfg(test)]` module generates the real interface via `candid::export_service!()` and cross-checks its method set against the `.did` file (`cargo test -p ciphersettle_backend candid_interface`). Manually cross-checked every parameter and result type against that generated output this round: full match across all 12 methods. |
| Round 3's `register_invoice` oracle fix (collapsed error messages) | **Re-traced against actual compiled control flow, holds up** -- confirmed no side channel (message or timing) survives the collapse; see the round-4 review doc §4. |
| `cargo clippy` at default lint level | **Zero warnings**, confirmed this round on the full workspace. |
| `cargo clippy` at `pedantic`/`nursery`/`cargo` levels | ~30 warnings, all reviewed individually -- style only (missing doc sections, `&str` vs `String` params, etc.), left as accepted debt rather than fixed wholesale; see the round-4 review doc §5. |

Full writeup: `CipherSettle_Cryptography_Review_Round4.md`.

## Round 3: applied-cryptography review findings

Round 3 went further than reviewing the code's logic: it independently
re-derived and stress-tested the SHA-256 primitive itself, and traced the
actual on-chain call graph for information leakage rather than reasoning
about it in the abstract. That surfaced two concrete findings no prior
round documented, both now addressed.

| Round 3 finding | Status |
|---|---|
| `register_invoice` was an unauthenticated oracle for nullifier-set membership -- its error message distinguished "already registered" from every other failure, letting anyone with no relationship to an invoice learn whether guessed/partially-known fields matched an already-registered one, without ever holding a decryption key | **Fixed** -- rejections past field validation (duplicate nullifier vs. duplicate invoice_id) now return the same generic error; the specific reason is still written to the audit log (admin-only for unscoped reads). See the doc comment on `register_invoice`. |
| `register_invoice` had no rate limit at all -- the only update call in the canister without one | **Fixed** -- rate-limited per caller (20 calls / 60s by default), same mechanism as `derive_invoice_key`. Doesn't close the oracle on its own; raises the cost of bulk guessing. |
| vetKD-derived keys are not actually invalidated by `revoke_settlement_access` -- a party that already derived a key keeps working decryption capability indefinitely, even after access is pulled | **Documented, not fixed** -- this is structural to granting symmetric decryption capability at all, not a bug a canister-side check can close. True revocation would need a generation counter mixed into the vetKD `input` plus client-side re-encryption on every meaningful revocation -- real, unbuilt, out-of-scope work. See the doc comment on `derive_invoice_key`. |
| Hand-rolled SHA-256 had no production audit trail beyond this project's own review | **Replaced** -- swapped to the audited `sha2` crate (RustCrypto). The prior implementation was independently verified correct (4 NIST vectors, plus 26 additional padding-boundary vectors covering every classic SHA-256 block-boundary length) before being retired; "don't roll your own crypto" is a process rule about who bears the burden of catching the *next* bug, not a one-time correctness check a single review can fully discharge. |
| `resolve_access` materialized the entire regulator set into a `Vec` on every `derive_invoice_key` call and every per-invoice `get_audit_log` read, regardless of invoice | **Fixed** -- `resolve_access` now takes a pre-resolved `bool` (a direct `is_regulator`/`contains_key` lookup) instead of a list to scan. |
| Unscoped `get_audit_log(None)` returned the entire audit log in one response with no bound | **Fixed** -- added `offset`/`limit` parameters; `limit` is always clamped to `AUDIT_LOG_MAX_PAGE` (500) server-side regardless of what's requested. This is a breaking interface change, reflected in the `.did` file. |

## Round 2: responding to the addendum review

Round 1 fixed nullifier binding, audit-log gating, and confidential-read
transport. Round 2 re-reviewed that fix itself (rather than taking it on
faith) and found — then closed — a real gap: the round-1 nullifier hashed
caller-declared fields with no normalization, so `"USD"` vs `"usd"`, or
`"INV-001"` vs `" INV-001 "`, produced different nullifiers for what's
obviously the same invoice, letting anyone dodge the double-financing check
by varying case or whitespace. Round 2 also found and fixed an unrelated
privilege-creep/missing-audit-trail pair in `get_encrypted_invoice`, and
surfaces (without unilaterally resolving) two open design questions.

| Round 2 finding | Status |
|---|---|
| Nullifier fields hashed with no canonicalization (case/whitespace bypass) | **Fixed** — `InvoiceFingerprint::canonicalize` trims whitespace, upper-cases and shape-validates `currency_code`, and rejects non-ASCII content. See `ciphersettle_core::nullifier`. |
| Non-ASCII handling | **Deliberate blunt instrument** — rejected outright rather than attempting partial Unicode normalization; a real limitation for non-Latin issuer/invoice identifiers, documented rather than silently accepted. |
| Deterministic nullifiers are front-runnable by a third party who guesses/observes the declared fields | **Still open — flagged, not fixed here.** Closing it needs external attestation (already on round 1's "still open" list) or, as a smaller interim step, requiring `register_invoice`'s caller to be pre-registered as *the* issuer for the declared `issuer_identifier`. See "Still open," item 1a below. |
| Which fields belong in the nullifier identity hash (amount/due-date vs. issuer+invoice-number only) | **Flagged as a product decision, not resolved unilaterally.** See "Still open," item 1b below. |
| `get_encrypted_invoice` granted admin an unnecessary read (privilege creep) | **Fixed** — admin removed from the allowed-readers set; no current admin function needs raw ciphertext bytes. |
| `get_encrypted_invoice` never logged an access event | **Fixed** — every successful call now logs a `ciphertext_accessed` event. |
| `MIN`/`MAX_TRANSPORT_KEY_BYTES` still a placeholder range | **Unchanged, still open** — confirm the exact expected byte length against your pinned `@dfinity/vetkeys` / `ic_vetkd_sdk_utils` version before mainnet; see the `TODO` next to the constants. |

### Round 1 findings, for context

| Review finding | Status |
|---|---|
| Nullifier had no cryptographic binding to the invoice | **Fixed in round 1, with a round-2 caveat** (see table above) -- nullifier is derived on-chain from declared, now-canonicalized fields. See `ciphersettle_core::nullifier`. |
| Audit log was fully public, unauthenticated | **Fixed** -- `get_audit_log` is access-gated the same way `get_encrypted_invoice` is. |
| Confidential reads served over uncertified query calls | **Fixed** -- `get_encrypted_invoice` and `get_audit_log` are update calls, which go through consensus. |
| Single admin principal, no rotation path | **Fixed** -- `transfer_admin` added. |
| `transport_public_key` forwarded unvalidated | **Fixed (loose bound)** -- length-checked before use; exact expected length still needs confirming against your pinned vetkeys library version (see the `TODO` next to `MIN_TRANSPORT_KEY_BYTES`). |
| `invoice_id` / fingerprint fields unbounded in size | **Fixed** -- explicit length caps. |
| `DERIVE_CALL_TIMES` grows one entry per caller forever | **Improved** -- empty entries are now removed after trimming; doesn't fully close a Sybil-style bypass (see "Still open"). |
| The actual encryption scheme doesn't exist yet | **Still open** -- genuinely out of this repo's scope; see below. |
| Upgrade-governance model undocumented | **Partially addressed** -- admin rotation now exists; the actual governance policy (who controls upgrades, single key vs. multisig vs. DAO) is a deployment decision this repo can't make for you. |
| `Decode!(...).unwrap()` panics on corrupted stable memory | **Documented, not fully fixed** -- see "Still open." |

---

## What has actually been built and tested vs. not

- **`src/ciphersettle_core`** — logic actually compiled and tested in this
  environment: **84 tests, all passing**
  (`cargo test -p ciphersettle_core`; verified this round against Ubuntu-packaged
  rustc 1.75, which is sufficient for this crate even though the backend
  crate needs a newer toolchain -- see below). New this round:

  - **`resolve_access` no longer takes a full regulator list.** It now
    takes a pre-resolved `caller_is_regulator: bool`, so the canister does
    a direct `contains_key` lookup against its `StableBTreeMap` instead of
    materializing the entire regulator set into a `Vec` on every single
    key derivation or per-invoice audit-log read (round 3 review, §4).
    `ProtocolState`'s two call sites and every test were updated to match;
    added a regression test (`caller_is_regulator_flag_takes_priority...`)
    specifically guarding against a future refactor accidentally passing
    the wrong caller's regulator status.

  Carried over from round 2 -- **field canonicalization**, the fix for the
  round-2 "no normalization" gap: `InvoiceFingerprint::canonicalize` trims
  whitespace from every field, upper-cases and shape-validates
  `currency_code` as exactly three ASCII letters (a shape check, not a
  real ISO-4217 membership check), and rejects any field containing a
  non-ASCII byte. `compute_nullifier` always canonicalizes before
  validating and hashing. Deliberately does **not** case-fold
  `issuer_identifier` or `invoice_number` -- there's no universal rule for
  "the same" tax ID or invoice number the way there is for a 3-letter
  currency code; a deployment with its own canonical form should apply it
  before constructing the fingerprint. Tested: case-insensitivity,
  whitespace-trimming (including that the length bound applies *after*
  trimming, not before), whitespace-only fields still counting as empty,
  invalid currency-code shape, and non-ASCII rejection per field.

- **`sha256` module — now backed by the audited `sha2` crate (RustCrypto),
  not a hand-rolled implementation** (round 3 review, §2). The prior
  from-scratch implementation was verified correct against the 4 standard
  NIST vectors plus, in the review that led to this replacement, 26
  additional vectors independently generated to hit every classic SHA-256
  padding boundary (lengths 0, 1, 54-57, 63-65, 111-113, 119-121, 127-129,
  183-185, 191-193, 1000, 4096) -- all cross-checked against Python's
  `hashlib.sha256`. It was replaced anyway: correctness was never the
  problem, but "don't roll your own crypto" is a process rule about who
  bears the ongoing burden of catching the *next* subtle bug, and no
  amount of single-reviewer scrutiny replicates years of public fuzzing on
  a widely-deployed crate. The public API (`sha256`, `to_hex`) is
  unchanged, so nothing that depends on this module -- including
  `nullifier.rs` -- needed to change. This does mean `ciphersettle_core`
  is no longer literally dependency-free; that constraint existed to keep
  this crate buildable on the constrained sandbox toolchain used to test
  it, not as a production requirement, and the canister crate already
  depends on `ic-cdk`/`candid`/`ic-stable-structures` regardless.
  - **`nullifier` module — the round-1 fix for the "nullifier has no
    cryptographic binding" finding, now with round-2 canonicalization.**
    `InvoiceFingerprint` defines five canonical, jurisdiction-agnostic
    identifying fields (issuer identifier, invoice number, currency, amount
    in minor units, due date). `compute_nullifier` canonicalizes, validates
    (non-empty, bounded length), and hashes a length-prefixed canonical
    encoding (with a dedicated domain separator, distinct from the vetKD
    one) to produce a 32-byte `Nullifier`. Tested: identical fields always
    produce the identical nullifier; changing any one field changes it; two
    different issuers declaring the same invoice number don't collide; and,
    specifically, that length-prefixing actually prevents the classic
    concatenation-ambiguity bug (`("ab","c")` vs. `("a","bc")` must not
    collide -- and previously would have, without the length prefix). See
    "Still open" below for the front-running consequence this fix
    reintroduces, and the open question of which fields belong in the hash
    at all.
  - **Gated audit-log access** — `get_audit_log_authorized` replaces
    unauthenticated log reads: admin, an invoice's issuer/bank, or a
    registered regulator may read that invoice's log; an unscoped
    (cross-invoice) read is admin-only. Tested for every role, including
    that an unrelated caller is denied.
  - **Admin rotation** — `transfer_admin`, admin-only, tested both that the
    new admin gains admin-only capabilities and the old admin loses them.
  - **Transport-key and rate-limit refinements** — `check_transport_key_length`
    (boundary-tested) and the existing rate limiter, unchanged in logic.

  All of the previously-existing coverage (access-decision rules, full
  lifecycle simulation, revocation, settlement lifecycle, pruning
  eligibility, rate limiting, payload size) still passes under the new
  nullifier scheme -- the test helper that used to pass a raw nullifier
  string now builds an `InvoiceFingerprint` instead, but the properties
  being tested are the same ones as before, plus the new ones above.

  Treat `ProtocolState` as the executable spec for the canister — change a
  rule here first, get it green, then port it to `ciphersettle_backend`.

- **`src/ciphersettle_backend`** — wired to call into all of the above.
  New/changed this round (round 3 review, §1 and §4):
  - `register_invoice` is now rate-limited per caller (`REGISTER_RATE_LIMIT`,
    20 calls/60s by default -- own `REGISTER_CALL_TIMES` stable map,
    separate from `derive_invoice_key`'s), and, more importantly, no longer
    returns a distinguishable error for "this nullifier is already claimed"
    versus "this invoice_id is already taken." Both now return the same
    generic `"registration was not completed"`, with the specific reason
    written only to the audit log under invoice_id `"*"`. Previously, since
    `register_invoice` has no caller-identity gate at all, the specific
    error text made it an unauthenticated oracle: anyone could submit
    guessed or partially-known invoice fields and learn, from the response
    alone, whether that exact invoice already existed -- without a
    decryption key, without being a regulator, and without it appearing as
    a logged access event. See the doc comment on `register_invoice`.
  - `derive_invoice_key` and `get_audit_log` now call `resolve_access` with
    a direct `is_regulator(caller)` lookup instead of collecting the full
    regulator set on every call.
  - `get_audit_log` takes two new optional parameters, `offset` and
    `limit` (both `opt nat64` in the `.did` file -- a breaking interface
    change), so an admin's unscoped read of a long-lived canister's full
    history can't grow into a response that exceeds the IC's practical
    message-size limit and simply fails. `limit` is clamped server-side to
    `AUDIT_LOG_MAX_PAGE` (500) regardless of what's requested.
  - `derive_invoice_key`'s doc comment now states explicitly that
    `revoke_settlement_access` only prevents *future* key derivation --
    it cannot and does not invalidate a key some party already derived
    and decrypted client-side. This was always true (it's structural to
    handing out symmetric decryption capability at all) but was previously
    undocumented, which made "revoke" read like a stronger guarantee than
    it actually provides.

  **Now actually compiled and tested in this environment — not just
  reviewed by hand.** Every prior round noted that `ic-cdk` 0.17.x requires
  rustc 1.78+ and this sandbox only had 1.75, with no route to rustup, so
  every backend change up to this point was verified by manual trace only.
  That wall is now down: `ic-cdk` publishes a still-non-yanked `0.18.5`
  release whose declared `rust_version` is `1.75.0`, and pinning every
  transitive dependency that would otherwise resolve to a newer,
  edition2024-requiring version (`ic0`, `ic-cdk-executor`,
  `ic-management-canister-types`, `candid`, `ic_principal`, `cc` -- see the
  comment block above the pins in `ciphersettle_backend/Cargo.toml` for
  exactly which version of each and why) gets the whole dependency graph,
  vetKD management-canister API included, building on this exact
  toolchain. `Cargo.lock` is checked in so this resolution doesn't need to
  be re-derived.

  Confirmed in this session:
  - `cargo build --workspace` — succeeds, **zero warnings**.
  - `cargo test --workspace` — **85 tests pass** (84 from `ciphersettle_core`,
    plus one new round-4 test in `ciphersettle_backend` -- see below;
    `ciphersettle_backend` otherwise has no unit tests of its own, by
    design -- see "Treat `ProtocolState` as the executable spec" above).
  - `cargo clippy --workspace` — **zero warnings** at the default lint
    level, using the version-matched `rust-clippy` 1.75.0 package. At
    `pedantic`/`nursery`/`cargo` levels: two real, low-severity issues
    found and fixed in round 4 (a `u64`→`usize` truncation on
    `get_audit_log`'s `offset` param, dangerous specifically because
    `usize` is 32 bits on the actual `wasm32` deployment target even
    though it's 64 bits on this sandbox's host-target build; and a
    redundant 64 KB ciphertext clone in `get_encrypted_invoice`) — the
    remaining ~30 warnings at those stricter levels are style-only and
    left as accepted debt, reviewed individually rather than suppressed;
    see the round-4 review doc.
  - **Candid interface, mechanically checked for the first time**: a
    `#[cfg(test)]` module (round 4) generates the real interface via
    `candid::export_service!()` and cross-checks its method set against
    `ciphersettle_backend.did`. Manually cross-checked every parameter and
    result type against that generated output: full match across all 12
    methods (see the round-4 review doc §3 for the one cosmetic,
    non-functional difference found: `service : { ... }` vs. the
    compiler's `service : () -> { ... }` prologue form -- both valid
    Candid for a zero-init-arg service).
  - The one bug the compiler itself caught that manual review hadn't
    (round 3): an earlier draft of the shared rate-limit helper called
    `.with_borrow_mut()` on a plain `&RefCell<...>` reference -- a method
    that only exists on `thread_local!`'s `LocalKey`, not on `RefCell`
    itself. Manual review had already caught and fixed this before the
    compiler was available (see the round-3 changelog above); round 4
    confirmed nothing else like it had slipped through, and separately
    found the two clippy-only issues above that manual review genuinely
    missed across three rounds.

  **Still not verified, and still real gaps:**
  - **`wasm32-unknown-unknown`, the actual IC deployment target, was not
    built.** This sandbox has no `rustup` (needed to add the target) and no
    matching `rust-std-wasm32-unknown-unknown` apt package for this Ubuntu
    release. Everything above was compiled as an ordinary `rlib`/`cdylib`
    for the host target (`x86_64-unknown-linux-gnu`), which exercises the
    same type-checking, trait resolution, macro expansion (`#[ic_cdk::update]`,
    `Encode!`/`Decode!`), and borrow-checking that a wasm build would --
    but codegen for the actual target is a separate step this still
    doesn't cover.
  - **No local replica (`dfx`) is available** in this sandbox (network
    access to `sdk.dfinity.org`/`internetcomputer.org` is blocked), so
    nothing here has been deployed, and the canister's actual runtime
    behavior against a real IC execution environment -- inter-canister
    calls to the vetKD subnet, cycles accounting, stable-memory upgrade
    behavior -- remains unverified. Compiling and unit-testing the logic is
    necessary, not sufficient, for that.
  - **The pins above are a sandbox workaround, not a real dependency
    policy.** On a machine with a current rustup toolchain (1.85+), the
    right move is to delete the entire pin block, not to ship a production
    canister frozen to `ic-cdk 0.18.5` indefinitely -- newer releases carry
    real fixes and API surface this project doesn't use yet.

- **Nothing here has been deployed to a live replica or mainnet.**

---

## Still open (needs a design decision, not just more code)

1. **The nullifier still trusts the caller's declared fields, and round 2
   surfaced two consequences of that worth separating out:**

   a. **Front-running / squatting.** Because the nullifier is a pure
      function of publicly-observable/guessable fields with no secret mixed
      in, anyone who can guess or observe those fields can compute the
      identical nullifier and register it first, permanently blocking the
      real issuer. This is a direct, unavoidable consequence of round 1's
      fix, not a separate bug: any scheme where two *independent,
      uncoordinated* parties need to arrive at the same nullifier from
      public fields alone is, by construction, computable by a third party
      too. **Still open** -- round 3 fixed the *related* membership-oracle
      leak (a third party could previously confirm, via `register_invoice`'s
      error message, whether an *already-registered* invoice's fields
      matched a guess -- see the round-3 table above), but that fix doesn't
      touch front-running itself: an attacker who front-runs a registration
      doesn't need the oracle, they just need to win the race. Both
      findings share the same root cause (a public, secret-free commitment
      over guessable data) and the same real fix. Closing this needs one
      of:
      - **External attestation** (an authoritative registry signing off on
        a specific issuer being entitled to register a specific invoice
        number) — the real fix, and the reason the round-1 "still open"
        item 2 below is now higher-priority, not just a nice-to-have.
      - **Issuer-principal pre-registration**, as a smaller interim step:
        require `register_invoice`'s caller to be pre-registered (by the
        admin or a KYC step) as *the* issuer for the declared
        `issuer_identifier`, so an anonymous attacker at least can't squat
        on arbitrary issuer identities.
      - At minimum, document this risk explicitly wherever this system is
        described to users with predictable/sequential invoice numbering.
   b. **Which fields belong in the identity hash is a business-logic
      decision.** The current hash includes `amount_minor_units` and
      `due_date_unix` alongside issuer + invoice number. The more fields
      included, the easier it is to get a "fresh" nullifier for what a
      business would consider the same invoice just by changing one
      non-essential field (e.g. correcting a rounding error). Two
      defensible directions, deliberately not picked here because the
      choice changes what "double-financing prevention" means in your
      deployment:
      - **Narrow the identity key** to `issuer_identifier + invoice_number`
        only, and require an explicit `amend_invoice` operation (not built)
        for legitimate changes to amount/currency/due-date.
      - **Keep the current wider key**, and accept that a legitimate
        amendment and an evasive resubmission look identical on-chain --
        but make that trade-off an explicit, documented product decision.

2. **The actual encryption scheme is still unspecified.** This canister
   correctly treats client-side encryption as out of scope and defers to
   `@dfinity/vetkeys`. The vetKD `context`/`input` usage in this codebase is
   mechanically correct and matches DFINITY's documented pattern for
   non-self-authenticating identities. What's still missing is the actual
   hybrid-encryption construction (which AEAD, how the vetKD-derived key
   feeds into it, how associated data binds ciphertext to `invoice_id` so a
   ciphertext can't be replayed onto a different invoice) -- that lives
   entirely in an unwritten frontend. Pin this down as an explicit spec
   before calling this API/SDK-ready; don't leave it as "the frontend
   figures it out." Given item 1a above, external attestation and this spec
   are now the two highest-priority open items.
3. **Key revocation is authorization-only, not cryptographic** (round 3
   review, §3; now documented in code, not fixed, because a real fix is a
   genuine feature, not a patch). `revoke_settlement_access` stops a party
   from calling `derive_invoice_key` *again* -- it does not, and cannot on
   its own, invalidate a key that party already derived and decrypted
   client-side. Every authorized caller for a given invoice receives the
   same underlying vetKD-derived key (correct, intended behavior for
   identity-based derivation), and nothing rotates that key on revocation:
   no generation counter, no epoch, no re-encryption. A bank whose access
   was pulled yesterday can still decrypt any ciphertext for that invoice
   it fetched or cached before revocation, indefinitely -- even after
   `prune_ciphertext` deletes the on-chain copy. This is inherent to
   granting symmetric decryption capability at all, not specific to this
   codebase, but it was previously undocumented, which let "revoke" read
   like a stronger guarantee than it provides. If a deployment's threat
   model genuinely requires point-in-time revocation, the only correct fix
   is mixing a generation counter into the vetKD `input` and re-encrypting
   stored ciphertext under a freshly derived key on every meaningful
   revocation -- real client-side work, scoped as its own feature, not
   attempted here.
4. **Rate limiting is per-principal, not per-identity-cost.** Both
   cycle-sensitive endpoints (`derive_invoice_key` and, as of round 3,
   `register_invoice`) are now rate-limited per caller, which raises the
   cost of abuse but doesn't close it: an attacker spreading calls across
   many cheaply-created principals still bypasses the practical effect of
   either limit, even though per-caller storage growth is bounded (old
   timestamps are trimmed, not accumulated forever). Closing this fully
   needs either cycles-attached calls or gating behind a real
   identity/subscription layer (see the SaaS-billing gap below).
5. **`Decode!(...).unwrap()` (now `.expect(...)`) still panics on
   corrupted stable memory.** `ic_stable_structures::Storable::from_bytes`
   is infallible by trait signature, so a clean fix would need either a
   schema-version byte plus an explicit `post_upgrade` migration path, or
   upstream support for fallible decoding -- neither is a small change, and
   isn't done here. The `.expect()` messages are at least now descriptive
   pointers back to this note rather than a bare `unwrap()`.
6. **Upgrade governance is still a deployment decision, not a code
   fact.** `transfer_admin` means a lost or compromised admin key is no
   longer a permanent lockout, but it doesn't answer "who is allowed to
   push a wasm upgrade to this canister" -- that's IC controller-list
   configuration outside this repo, and should be decided and documented
   (black-holed canister vs. multisig vs. DAO-governed, with or without a
   time lock) before anyone is asked to trust the "no standing master key"
   claim.


A jurisdiction-agnostic, personal open-source project: a minimal Rust canister
implementing confidential invoice/settlement records on the Internet
Computer, using a public nullifier registry for double-financing prevention
and vetKeys for encryption + event-driven selective disclosure.

This PoC is deliberately generic — no named market, no named regulator, no
named KYC/e-invoicing provider. Compliance and identity integrations are left
as pluggable extension points so the core protocol isn't coupled to any one
country's rules.

**Not audited. Not tested against a live replica. Not production-ready.**
Treat this as a skeleton for your own further development and review.

## What it does

- `register_invoice(invoice_id, issuer_identifier, invoice_number,
  currency_code, amount_minor_units, due_date_unix, ciphertext)` — caller
  encrypts client-side and submits ciphertext alongside the invoice's
  declared identifying fields. **The canister derives the nullifier itself**
  from those fields (see `ciphersettle_core::nullifier`) and rejects
  registration if an invoice with the same fields is already on file --
  that's the double-financing check, done without the canister ever seeing
  plaintext or persisting the declared fields themselves (only their hash
  is stored). Also rejects an oversized ciphertext or invoice_id, and is
  rate-limited per caller (round 3). Returns the derived nullifier as a
  hex-encoded receipt on success. **Rejections past field validation are
  deliberately generic** (round 3, §1): a duplicate nullifier and a
  duplicate `invoice_id` both return the same error text, since
  distinguishing them would turn this unauthenticated, ungated endpoint
  into an oracle for testing whether a guessed invoice already exists. The
  specific reason is still recorded in the audit log for the admin to see.
- `grant_settlement_access(invoice_id, counterparty)` — only the original
  issuer can name a counterparty (e.g. a financing institution) principal.
- `revoke_settlement_access(invoice_id)` — issuer-only. Pulls a previously
  granted counterparty's access. Errors (doesn't silently no-op) if nothing
  was granted.
- `mark_settled(invoice_id)` — issuer or the currently-granted bank. Records
  the invoice as settled (fund movement happens off-canister). Rejects
  double-settling. Makes the invoice eligible for ciphertext pruning later.
- `prune_ciphertext(invoice_id)` — drops the ciphertext blob for an invoice
  that is Settled and past a retention window (~180 days by default) since
  settlement. **The invoice record and its full audit trail are never
  deleted** — only the payload bytes are cleared.
- `derive_invoice_key(invoice_id, transport_public_key)` — gates vetKD key
  derivation to the issuer, the currently-granted counterparty, or a
  registered auditor/regulator. Every auditor/regulator call is logged as a
  `disclosure_request` event. Length-checks `transport_public_key` before
  forwarding it, and is rate-limited per caller (5 calls/60s by default).
- `get_encrypted_invoice(invoice_id)` — **update call**, gated to the
  issuer, the granted bank, or a registered regulator. Deliberately **not**
  admin-accessible: no current admin function needs raw ciphertext bytes, so
  granting it anyway would be an unnecessary widening of what a compromised
  or careless admin key could read. Every successful read is logged as a
  `ciphertext_accessed` event.
- `get_audit_log(invoice_id, offset, limit)` — **update call**, metadata
  only, and now **access-gated**: per-invoice reads are limited to that
  invoice's issuer/bank/regulator/admin; unscoped (cross-invoice) reads are
  admin-only, since that view reveals the entire relationship graph at
  once. Never returns ciphertext or plaintext, and is never pruned.
  `offset`/`limit` (both optional, round 3) default to `0` and
  `AUDIT_LOG_MAX_PAGE` (500); `limit` is always clamped to that max
  server-side, so an unpaginated read of a long-lived canister's full
  history can't grow into a response that exceeds the IC's practical
  message-size limit.
- `register_regulator(principal)` / `revoke_regulator(principal)` —
  admin-only.
- `transfer_admin(new_admin)` — admin-only rotation of the admin principal
  itself, so a lost or compromised admin key isn't a permanent lockout.

## What's intentionally left as extension points

1. **Client-side encryption / decryption.** Still entirely out of scope for
   this canister -- see "Still open," item 2, above for exactly what's
   missing and why it matters for a real cryptography sign-off.
2. **Any KYC/AML or identity provider integration**, and **any external
   system-of-record outcall**, remain deliberately unbuilt, as before.
   These are also the natural place to plug in an external authority's
   signature over `InvoiceFingerprint`'s fields, per "Still open," item 1.
3. **Production vetKD key.** `vetkd_key_id()` uses `"dfx_test_key"`, which
   only exists on the local replica. Mainnet requires requesting a real key
   name for your subnet.
4. **A dispute/challenge mechanism** and **SaaS billing/paywall
   enforcement** remain unbuilt, as before.

## A note on the "don't touch the money" design constraint

If you extend this toward real settlement, keep fund custody and movement
entirely outside the canister — route it through whatever licensed banking
or payment rail the deploying party already uses, and charge for the
software itself (flat fee) rather than taking a cut of settled volume.

## Before you publish this anywhere public

- Pick a name and run a basic trademark/availability check yourself.
- If you use ICP/DFINITY branding or trademarks anywhere, check DFINITY's
  brand guidelines.
- This project is licensed under the [MIT License](LICENSE).
- **Decide and document your upgrade-governance model** (see "Still open,"
  item 6) before making any claim about "no standing master key" to anyone
  relying on it.

## Contributing

CipherSettle is open source and welcomes contributions. This is a
proof-of-concept — none of it is audited or production-ready — and the README
above records every review round and every deliberately-open design question.
Please read it before contributing so your work fits the project's actual
state.

- **[CONTRIBUTING.md](CONTRIBUTING.md)** — architecture notes (change rules in
  `ciphersettle_core` first), dev setup, testing expectations, and the
  contribution workflow.
- **[SECURITY.md](SECURITY.md)** — how to report a vulnerability privately
  (do not file public issues for security bugs).
- **[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)** — the standards all
  contributors are expected to uphold.

Bug reports and feature requests use the templates under `.github/`.

## License

[MIT](LICENSE)

## Running it locally

Requires `dfx` and the `wasm32-unknown-unknown` Rust target for an actual
deployment. `cargo check`/`test`/`clippy` no longer require a newer
toolchain than this repo's own sandbox has -- see the pin block and
comment in `src/ciphersettle_backend/Cargo.toml`, and `Cargo.lock` is
checked in for exact reproducibility.

```bash
# Runs today on an ordinary Rust toolchain, no dfx or wasm32 target needed:
cargo test -p ciphersettle_core
cargo build --workspace          # compiles ciphersettle_backend too, now
cargo clippy --workspace         # zero warnings as of round 4

# Still requires dfx + the wasm32 target for an actual canister build/deploy
# (the pin block above gets you a working *host*-target compile; it doesn't
# by itself get you wasm32 codegen or a running replica):
rustup target add wasm32-unknown-unknown
dfx start --background
dfx deploy
dfx canister call ciphersettle_backend register_invoice \
  '("inv-001", "issuer-tax-id-123", "INV-001", "USD", 10000, 1893456000, blob "\00\01\02")'
dfx canister call ciphersettle_backend grant_settlement_access '("inv-001", principal "aaaaa-aa")'
dfx canister call ciphersettle_backend mark_settled '("inv-001")'
dfx canister call ciphersettle_backend get_audit_log '(opt "inv-001", null, null)'
```

## Known gaps worth reviewing before extending

See "Still open" above for the substantive ones. Additionally, unchanged
from before:

- `register_invoice` trusts the caller-supplied `invoice_id` itself (as
  opposed to the fingerprint fields, which are now hashed and checked) — tie
  it to whatever authoritative system you connect, rather than free-form
  client input, once you add one.
- No SaaS billing/paywall enforcement exists yet.
- `prune_ciphertext` is callable by anyone, gated only by the eligibility
  check — deliberate (storage hygiene, not access control), but worth a
  second look for your deployment (e.g. requiring a specific caller or a
  scheduled heartbeat/timer instead).
