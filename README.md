# CipherSettle — Phase 1 PoC

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

- **`src/ciphersettle_core`** — dependency-free logic, actually compiled and
  tested in this environment: **78 tests, all passing**
  (`cargo test -p ciphersettle_core`; verified this round against Ubuntu-packaged
  rustc 1.75, which is sufficient for this dependency-free crate even though
  the backend crate needs a newer toolchain -- see below). New this round:

  - **Field canonicalization — the actual fix for the round-2 "no
    normalization" gap.** `InvoiceFingerprint::canonicalize` trims
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

- **`sha256` module** — a from-scratch, dependency-free SHA-256
  (FIPS 180-4) implementation, needed so the nullifier derivation below
  doesn't require pulling in an external crate (keeping this crate
  buildable on any Rust toolchain, including the one available in this
  project's dev sandbox). Verified against real NIST/reference vectors
  computed independently via Python's `hashlib`, not just asserted: the
  empty string, `"abc"`, the standard two-block message, and the
  million-`'a'` long-message vector, plus determinism and distinct-input
  checks.
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
  New/changed this round: `get_encrypted_invoice` no longer treats admin as
  an allowed reader, and now logs a `ciphertext_accessed` event on every
  successful call (previously logged nothing at all). Carried over from
  round 1: `register_invoice` takes the five fingerprint fields instead of
  a caller-supplied nullifier and returns the canister-derived nullifier
  (hex) as a receipt; `get_encrypted_invoice` and `get_audit_log` are
  `update` calls (not `query`) and `get_audit_log` is access-gated;
  `transfer_admin` added; `derive_invoice_key` length-checks the transport
  key before forwarding it; `DERIVE_CALL_TIMES` entries are removed once
  empty rather than left as permanent empty rows.

  **Confirmed not compilable in this environment, same specific wall as
  before**: `ic-cdk` 0.17.x requires rustc 1.78+, this sandbox only has
  1.75 with no route to rustup. This round's change (`get_encrypted_invoice`)
  follows the exact same `INVOICES.with(...) -> Result; log_event(...); Ok(...)`
  pattern already used by `mark_settled` and `grant_settlement_access`
  elsewhere in this file, and was reviewed by hand against the toolchain
  constraint (types, trait bounds, borrow patterns checked manually
  line-by-line since the compiler couldn't do it here), but **you must run
  `cargo check -p ciphersettle_backend` yourself** on a real 1.85+ toolchain
  before trusting any of it compiles, exactly as before.

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
      too. Closing this needs one of:
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
3. **Rate limiting is per-principal, not per-identity-cost.** An attacker
   spreading calls across many cheaply-created principals still bypasses
   the practical effect of `DERIVE_KEY_RATE_LIMIT`, even though the
   per-caller storage growth this round is now bounded. Closing this needs
   either cycles-attached calls or gating behind a real
   identity/subscription layer (see the SaaS-billing gap below).
4. **`Decode!(...).unwrap()` (now `.expect(...)`) still panics on
   corrupted stable memory.** `ic_stable_structures::Storable::from_bytes`
   is infallible by trait signature, so a clean fix would need either a
   schema-version byte plus an explicit `post_upgrade` migration path, or
   upstream support for fallible decoding -- neither is a small change, and
   isn't done here. The `.expect()` messages are at least now descriptive
   pointers back to this note rather than a bare `unwrap()`.
5. **Upgrade governance is still a deployment decision, not a code
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
  is stored). Also rejects an oversized ciphertext or invoice_id. Returns
  the derived nullifier as a hex-encoded receipt.
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
- `get_audit_log(invoice_id)` — **update call**, metadata only, and now
  **access-gated**: per-invoice reads are limited to that invoice's
  issuer/bank/regulator/admin; unscoped (cross-invoice) reads are
  admin-only, since that view reveals the entire relationship graph at
  once. Never returns ciphertext or plaintext, and is never pruned.
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
- Choose a license deliberately (this repo ships without a LICENSE file).
- **Decide and document your upgrade-governance model** (see "Still open,"
  item 5) before making any claim about "no standing master key" to anyone
  relying on it.

## Running it locally

Requires `dfx` and the `wasm32-unknown-unknown` Rust target.

```bash
# Runs today, no dfx required -- the tested pure-logic crate:
cargo test -p ciphersettle_core

# Requires a current (1.85+) rustup toolchain + dfx + wasm32 target.
rustup target add wasm32-unknown-unknown
cargo check -p ciphersettle_backend    # verify it actually compiles first
dfx start --background
dfx deploy
dfx canister call ciphersettle_backend register_invoice \
  '("inv-001", "issuer-tax-id-123", "INV-001", "USD", 10000, 1893456000, blob "\00\01\02")'
dfx canister call ciphersettle_backend grant_settlement_access '("inv-001", principal "aaaaa-aa")'
dfx canister call ciphersettle_backend mark_settled '("inv-001")'
dfx canister call ciphersettle_backend get_audit_log '(opt "inv-001")'
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
