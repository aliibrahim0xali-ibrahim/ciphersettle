# CipherSettle

Confidential invoice-settlement protocol on the Internet Computer. A minimal
Rust canister implementing encrypted invoice records with a public nullifier
registry for double-financing prevention, vetKeys for encryption, and
event-driven selective disclosure.

A jurisdiction-agnostic, personal open-source proof-of-concept -- no named
market, no named regulator, no named KYC/e-invoicing provider. Compliance and
identity integrations are left as pluggable extension points.

**Not audited. Not tested against a live replica. Not production-ready.**
Treat this as a skeleton for your own further development and review.

---

## Table of Contents

- [How It Works](#how-it-works)
- [Architecture](#architecture)
- [API Reference](#api-reference)
- [Getting Started](#getting-started)
- [B2B Lifecycle Demo](#b2b-lifecycle-demo)
- [What's Built and Tested](#whats-built-and-tested)
- [Open Design Questions](#open-design-questions)
- [Security](#security)
- [Contributing](#contributing)
- [License](#license)

---

## How It Works

CipherSettle solves one specific B2B problem: **preventing the same invoice
from being financed at more than one institution**, without any participant --
including the platform operator -- being able to read the invoice itself.

The flow:

1. **Issuer registers an invoice.** They encrypt invoice content
   client-side (out of this repo's scope -- see [Open Design
   Questions](#open-design-questions)) and submit the ciphertext alongside
   five declared identifying fields (issuer ID, invoice number, currency,
   amount, due date). The canister derives a deterministic 32-byte nullifier
   from those fields via SHA-256 and rejects the registration if an invoice
   with the same fields is already on file. The declared fields themselves
   are never stored -- only their hash.

2. **Issuer grants settlement access to a bank.** Only the original issuer
   can name a counterparty (a financing institution) that may later derive
   a decryption key.

3. **Bank derives a decryption key via vetKD.** The bank fetches encrypted
   ciphertext from the canister, derives a decryption key through the vetKD
   threshold key derivation protocol, and decrypts client-side.

4. **Settlement happens off-canister.** Actual fund movement goes through
   whatever licensed banking or payment rail the deploying party already
   uses. The canister records the terminal state when either party marks the
   invoice settled.

5. **Ciphertext is pruned after retention.** Once an invoice is settled and
   past a ~180-day retention window, its ciphertext blob can be dropped to
   free stable-memory. The audit trail is never pruned.

6. **Regulators get standing disclosure access.** A registered regulator
   may derive decryption keys for any invoice. Every such access is logged
   distinctly as a `disclosure_request` event, not conflated with ordinary
   counterparty access.

---

## Architecture

The workspace has two crates with a deliberate split:

### `ciphersettle_core` -- Executable Spec

Pure Rust with **zero IC dependencies** (only `sha2` from RustCrypto). All
protocol rules live here:

- Access-decision logic (`resolve_access`)
- Nullifier derivation with canonicalization (`compute_nullifier`)
- Double-financing check (`check_nullifier`)
- Rate-limit enforcement (`check_rate_limit`)
- Payload-size and transport-key validation
- Full `ProtocolState` -- a complete in-memory simulation of the canister's
  stable-structure logic, testable on any Rust toolchain

**84 unit tests**, all passing. This is the project's primary test surface.

Treat `ProtocolState` as the executable spec: change a rule here first, get it
green, then port it to `ciphersettle_backend`.

### `ciphersettle_backend` -- IC Canister

The wire layer using `ic-cdk`, `ic-stable-structures`, and vetKD. Thin
wiring that calls into `ciphersettle_core` for all decision logic. Stores
nullifiers, invoices, regulators, and audit events in stable memory via
`StableBTreeMap` and `StableCell`.

One unit test: a Candid interface verification that cross-checks the
compiler-generated service interface against the checked-in `.did` file.

---

## API Reference

12 canister methods, all defined in `ciphersettle_backend.did`:

### Invoice Lifecycle

| Method | Caller | Description |
|--------|--------|-------------|
| `register_invoice(invoice_id, issuer_identifier, invoice_number, currency_code, amount_minor_units, due_date_unix, ciphertext)` | Anyone | Register an invoice. The canister derives the nullifier from the declared fields. Returns the nullifier as a hex receipt. Rate-limited (20 calls/60s). Rejections past field validation are deliberately generic to prevent oracle attacks. |
| `grant_settlement_access(invoice_id, bank)` | Issuer only | Grant a bank/financier decryption access to an invoice. |
| `revoke_settlement_access(invoice_id)` | Issuer only | Revoke a previously granted bank's access. Errors if nothing was granted. |
| `mark_settled(invoice_id)` | Issuer or granted bank | Record an invoice as settled. Fund movement happens off-canister. |
| `prune_ciphertext(invoice_id)` | Anyone | Drop ciphertext for a settled invoice past the retention window (~180 days). Audit trail is never pruned. |

### Key Derivation and Retrieval

| Method | Caller | Description |
|--------|--------|-------------|
| `derive_invoice_key(invoice_id, transport_public_key)` | Issuer, granted bank, or registered regulator | Derive a vetKD decryption key. Rate-limited (5 calls/60s). Regulator access is logged as `disclosure_request`. |
| `get_encrypted_invoice(invoice_id)` | Issuer, granted bank, or registered regulator | Fetch the encrypted invoice blob. Update call (not query) for consensus safety. Logged as `ciphertext_accessed`. |
| `get_vetkd_public_key()` | Anyone | Fetch the canister's vetKD public key (cacheable). |

### Admin

| Method | Caller | Description |
|--------|--------|-------------|
| `register_regulator(principal)` | Admin only | Register a principal with standing disclosure access to all invoices. |
| `revoke_regulator(principal)` | Admin only | Revoke a regulator's disclosure access. |
| `transfer_admin(new_admin)` | Admin only | Rotate the admin identity. Logged. |

### Audit

| Method | Caller | Description |
|--------|--------|-------------|
| `get_audit_log(invoice_id?, offset?, limit?)` | Gated | Paginated audit log. Per-invoice: issuer, granted bank, regulator, or admin. Unscoped: admin only. Metadata only (no ciphertext/plaintext). Limit clamped to 500. |

---

## Getting Started

### Prerequisites

- Rust toolchain (1.75+ for build/test; 1.85+ recommended)
- `dfx` and `wasm32-unknown-unknown` target for canister deployment

### Build and Test (no dfx required)

```bash
# Run all 84 core tests
cargo test -p ciphersettle_core

# Build the full workspace (including the backend canister crate)
cargo build --workspace

# Lint
cargo clippy --workspace
```

### Deploy to Local Replica

```bash
rustup target add wasm32-unknown-unknown
dfx start --background
dfx deploy
```

### Example Canister Calls

```bash
dfx canister call ciphersettle_backend register_invoice \
  '("inv-001", "issuer-tax-id-123", "INV-001", "USD", 10000, 1893456000, blob "\00\01\02")'

dfx canister call ciphersettle_backend grant_settlement_access \
  '("inv-001", principal "aaaaa-aa")'

dfx canister call ciphersettle_backend derive_invoice_key \
  '("inv-001", blob "\00\01\02\03")'

dfx canister call ciphersettle_backend mark_settled '("inv-001")'

dfx canister call ciphersettle_backend get_audit_log '(opt "inv-001", null, null)'
```

---

## B2B Lifecycle Demo

For a narrated, end-to-end walkthrough of a realistic B2B scenario, see
[`CipherSettle_B2B_Operations_Guide.md`](CipherSettle_B2B_Operations_Guide.md).

Two scripts cover the same scenario at different levels:

### Rust Simulation (verified, runs today)

```bash
cargo run --example b2b_lifecycle_simulation -p ciphersettle_core
```

Runs against `ProtocolState` -- the same executable spec the canister is
built from. Every step's outcome is asserted, not just printed. Covers:

1. Platform setup (admin onboards a regulator)
2. Invoice registration
3. Double-financing rejection
4. Oracle-closing check (indistinguishable error messages)
5. Settlement-access grant
6. Bank key derivation (+ unauthorized rejection)
7. Regulator disclosure (distinctly logged)
8. Access revocation and re-grant to a new bank
9. Settlement (+ double-settlement rejection)
10. Audit trail (scoped and unscoped, with access control)
11. Ciphertext-pruning eligibility over time

### Shell Script (deployment-level, reference only)

```bash
dfx start --background
dfx deploy
export ACME_PRINCIPAL=... MERIDIAN_PRINCIPAL=...
./scripts/b2b_lifecycle_demo.sh
```

Same scenario as real `dfx canister call` invocations against a deployed
canister. Requires `dfx` identities set up per organization. Not executable
without a local replica.

---

## What's Built and Tested

- **`ciphersettle_core`**: 84 unit tests, all passing. Covers access
  decisions, nullifier derivation with canonicalization, double-financing
  checks, rate limiting, payload-size guards, transport-key validation,
  full protocol lifecycle, settlement, pruning eligibility, and audit-log
  access control.

- **`ciphersettle_backend`**: Compiled and tested against `ic-cdk 0.18.5`
  on rustc 1.75. Candid interface mechanically verified against the `.did`
  file. Zero clippy warnings at default lint level.

- **Review rounds**: Five rounds of applied-cryptography review have been
  conducted, covering nullifier binding, canonicalization, oracle
  resistance, vetKD integration, stable-memory handling, and Candid
  interface correctness. See [Review History](#review-history) below.

### Review History

| Round | Key Findings | Status |
|-------|-------------|--------|
| **1** | Nullifier had no cryptographic binding; audit log was public; confidential reads via uncertified queries; no admin rotation; unvalidated transport key; unbounded payloads | All fixed |
| **2** | Nullifier fields hashed without canonicalization (case/whitespace bypass); `get_encrypted_invoice` privilege creep and missing audit trail | Fixed. Front-running and field-selection questions flagged as open design decisions |
| **3** | `register_invoice` was an unauthenticated oracle; no rate limit on registration; vetKD keys not invalidated by revocation (structural); hand-rolled SHA-256 replaced with audited `sha2`; regulator set materialized on every call; unbounded audit-log response | Fixes applied; revocation semantics documented, not fixed (requires generation counter + re-encryption) |
| **4** | `u64`->`usize` truncation on wasm32 target; redundant 64 KB ciphertext clone; Candid interface never mechanically checked | All fixed. Candid interface now auto-verified via `candid::export_service!()` |
| **5** | `ProtocolState` spec had drifted from canister behavior on the round-3 oracle fix (collapsing error messages) | Fixed. Spec now matches deployed behavior; regression tests added |

---

## Open Design Questions

These require design decisions, not just more code:

1. **Front-running.** The nullifier is a deterministic hash of
   guessable fields with no secret mixed in. Someone who guesses or observes
   an invoice's fields can register the nullifier first. Closing this needs
   either external attestation (a tax registry or e-invoicing platform
   vouching for issuer/invoice pairings) or issuer-principal
   pre-registration as a smaller interim step. Neither is built yet.

2. **Client-side encryption construction.** The canister correctly handles
   key derivation and access control. The actual hybrid-encryption
   construction (which AEAD, how the vetKD-derived key feeds into it, how
   associated data binds ciphertext to `invoice_id`) is unspecified and
   unbuilt. This is the single largest piece of work between this repo and
   a real product.

3. **Key revocation is authorization-only, not cryptographic.**
   `revoke_settlement_access` stops a party from deriving a *new* key; it
   does not invalidate a key they already derived. A bank whose access was
   pulled yesterday can still decrypt any ciphertext it fetched before
   revocation, indefinitely. True revocation requires a generation counter
   in the vetKD `input` plus client-side re-encryption -- real, unbuilt
   work.

4. **Which fields belong in the nullifier hash.** The current hash includes
   amount and due date alongside issuer + invoice number. Narrowing to
   issuer + invoice number only would require an explicit `amend_invoice`
   flow for legitimate changes. This is a product decision that changes what
   "double-financing prevention" means.

5. **Upgrade governance.** `transfer_admin` prevents permanent lockout, but
   "who is allowed to push a wasm upgrade" is IC controller-list
   configuration outside this repo, and should be decided (multisig vs.
   DAO-governed, with or without time lock) before any deployment claiming
   "no standing master key."

6. **Stable-memory migration.** `Decode!(...).expect()` still panics on
   corrupted stable memory. A clean fix needs a schema-version byte plus
   an explicit `post_upgrade` migration path, or upstream support for
   fallible decoding.

---

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting guidelines.

**Known security-relevant limitations:**

- Rate limiting is per-principal, not per-identity-cost. An attacker
  spreading calls across many cheaply-created principals bypasses the
  practical effect of rate limits.
- `register_invoice` trusts the caller-supplied `invoice_id` itself (the
  fingerprint fields are hashed, but `invoice_id` is not). Tie it to an
  authoritative system once you add one.
- `MIN_TRANSPORT_KEY_BYTES` / `MAX_TRANSPORT_KEY_BYTES` are loose bounds.
  Confirm the exact expected byte length against your pinned vetkeys
  library version before mainnet.
- `vetkd_key_id()` uses `"dfx_test_key"`, which only exists on the local
  replica. Mainnet requires a real key name.
- The dependency pin block in `ciphersettle_backend/Cargo.toml` is a
  sandbox workaround for rustc 1.75, not a production dependency policy.
  On a current toolchain (1.85+), remove it and let normal resolution pick
  current versions.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for architecture guidance, development
setup, testing requirements, and PR workflow.

Key principle: **change `ciphersettle_core` first**, get tests green, then
port to `ciphersettle_backend`. Don't implement rules only in the canister.

---

## License

MIT -- see [LICENSE](LICENSE).

---

*A "don't touch the money" project: keep fund custody and movement entirely
outside the canister, route through whatever licensed banking rail the
deploying party already uses, and charge for the software itself rather than
taking a cut of settled volume.*
