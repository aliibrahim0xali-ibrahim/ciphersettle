# CipherSettle

> **Confidential invoice &amp; settlement records on the Internet Computer.**
> A public nullifier registry for double-financing prevention with
> vetKeys-based encryption and event-driven selective disclosure.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.75+-orange.svg)](#requirements)
![Status: PoC](https://img.shields.io/badge/status-proof--of--concept-lightgrey)

> ⚠️ **Not audited. Not tested against a live replica. Not production-ready.**
> This is a working proof of concept — a skeleton for your own development and
> review. See [Security](#security) and [Open design questions](#open-design-questions).

---

## Table of contents

- [Why](#why)
- [Features](#features)
- [Architecture](#architecture)
- [Endpoint reference](#endpoint-reference)
- [Getting started](#getting-started)
  - [Requirements](#requirements)
  - [Build &amp; test](#build--test)
  - [Deploy to a local replica](#deploy-to-a-local-replica)
- [Security](#security)
- [Open design questions](#open-design-questions)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

---

## Why

Invoice financing has a fundamental tension: the parties need to *prove* an
invoice hasn't already been financed to a different lender, while keeping the
invoice's business details (amount, due date, counterparty) confidential from
everyone except those explicitly entitled to them.

CipherSettle is a minimal reference implementation of that tension on the
Internet Computer:

- **Double-financing prevention without disclosure.** Registration commits a
  deterministic *nullifier* — a hash of the invoice's identifying fields — to
  a public registry. Two submissions declaring the same fields collide, so the
  same invoice can't be financed twice, yet the raw fields themselves are never
  stored: only the hash is public.
- **Encryption by vetKeys, not the canister.** The canister never sees
  plaintext. Clients encrypt client-side and upload ciphertext; decryption keys
  are derived on-chain from the ICP [vetKD](https://internetcomputer.org/docs/building-apps/encryption)
  system API, limited to authorized parties.
- **Event-driven selective disclosure.** Every access event is appended to an
  immutable, access-gated audit log — regulators can follow a `disclosure_request`
  trail without ever seeing plaintext.

The project is deliberately generic: no named market, regulator, or KYC/
e-invoicing provider. Compliance and identity integrations are left as
pluggable extension points so the core protocol isn't coupled to any one
country's rules.

---

## Features

| Area | Status |
|---|---|
| On-chain nullifier derivation from canonicalized invoice fields | ✅ |
| Double-financing rejection (duplicate nullifier / duplicate `invoice_id`) | ✅ |
| Role-based access: issuer, bank, regulator, admin | ✅ |
| vetKD key derivation, gated per role | ✅ |
| Access-gated, paginated append-only audit log | ✅ |
| Ciphertext pruning after settlement + retention window | ✅ |
| Admin rotation (`transfer_admin`) | ✅ |
| Per-caller rate limiting on cycle-sensitive endpoints | ✅ |
| Audited `sha2` (RustCrypto) for hashing | ✅ |
| Mechanically-verified Candid interface (12 methods) | ✅ |
| Client-side hybrid-encryption spec | ❌ out of scope (see [Open design questions](#open-design-questions)) |

---

## Architecture

A two-crate Rust workspace. The split is deliberate:

```
src/
├── ciphersettle_core/        # Pure Rust "executable spec" — no IC deps
│   └── src/
│       ├── lib.rs            # ProtocolState: access, rate limit, lifecycle rules
│       ├── nullifier.rs      # InvoiceFingerprint + canonicalized nullifier
│       └── sha256.rs         # SHA-256 via audited sha2 crate
└── ciphersettle_backend/     # The IC canister (ic-cdk, stable memory, vetKD)
    ├── ciphersettle_backend.did   # Candid interface
    └── src/lib.rs                 # Thin wiring over the core spec
```

**Treat `ciphersettle_core` as the executable spec.** Every protocol rule
(lifecycle state machine, access decisions, nullifier derivation, rate limits,
payload-size checks, retention logic) lives and is unit-tested in
`ciphersettle_core`. The canister crate is intentionally thin wiring that maps
Candid arguments onto those tested rules. When you change a rule, change it in
the core crate first, get it green, then port it to the backend. This keeps the
security-critical logic testable without a full IC runtime and is the primary
reason bugs are caught here rather than on mainnet.

`ciphersettle_backend` deliberately has almost no unit tests of its own — its
responsibility is interface mapping, not policy.

---

## Endpoint reference

All methods are update calls (they go through consensus — appropriate for
access-controlled or evidentiary reads on ICP, where a bare query could be
served from an untrusted replica). Signatures are declared in
[`ciphersettle_backend.did`](src/ciphersettle_backend/ciphersettle_backend.did).

### Registration &amp; lifecycle

| Method | Access | Description |
|---|---|---|
| `register_invoice(invoice_id, issuer_identifier, invoice_number, currency_code, amount_minor_units, due_date_unix, ciphertext) -> {Ok: text; Err: text}` | anyone (rate-limited) | Encrypt client-side, submit ciphertext + declared identifying fields. **The canister derives the nullifier itself** from those fields and rejects a duplicate (the double-financing check) without ever seeing plaintext or persisting the raw fields. Returns the derived nullifier as a hex receipt. Rejections past field validation are deliberately indistinguishable (see [Security](#security)). |
| `grant_settlement_access(invoice_id, counterparty)` | issuer | Name a counterparty (e.g. a financing institution). |
| `revoke_settlement_access(invoice_id)` | issuer | Pull a granted counterparty's access. Errors if nothing was granted. *Authorization only — see [Open design questions](#open-design-questions).* |
| `mark_settled(invoice_id)` | issuer or bank | Record settlement (fund movement is off-canister). Rejects double-settling; makes the invoice eligible for pruning. |
| `prune_ciphertext(invoice_id)` | anyone (eligibility-gated) | Drop the ciphertext blob once Settled and past the retention window (~180 days). Invoice record + audit trail are **never** deleted. |

### Confidential reads &amp; keys

| Method | Access | Description |
|---|---|---|
| `get_encrypted_invoice(invoice_id) -> {Ok: blob; Err: text}` | issuer, bank, regulator | Return raw ciphertext. Deliberately **not** admin-accessible. Every read is logged as `ciphertext_accessed`. |
| `derive_invoice_key(invoice_id, transport_public_key) -> {Ok: blob; Err: text}` | issuer, bank, regulator | Derive a vetKD decryption key into the caller's transport key. Regulator calls logged as `disclosure_request`. Rate-limited. |
| `get_vetkd_public_key() -> blob` | anyone | The canister's vetKD public key, for use by the client-side encryption flow. |
| `get_audit_log(invoice_id: opt text, offset: opt nat64, limit: opt nat64) -> {Ok: vec AuditEvent; Err: text}` | per-invoice: issuer/bank/regulator/admin; unscoped: admin-only | Immutable, access-gated metadata log. Never returns ciphertext/plaintext, never pruned. `limit` clamped to 500 server-side. |

### Administration

| Method | Access | Description |
|---|---|---|
| `register_regulator(principal)` / `revoke_regulator(principal)` | admin | Manage the regulator set. |
| `transfer_admin(new_admin)` | admin | Rotate the admin principal, so a lost/compromised admin key isn't a permanent lockout. |

---

## Getting started

### Requirements

- **Rust toolchain.** `cargo test`/`build`/`clippy` on the workspace runs on
  `rustc 1.75+` (see the pin block in
  [`ciphersettle_backend/Cargo.toml`](src/ciphersettle_backend/Cargo.toml);
  `Cargo.lock` is checked in for reproducibility).
- **For an actual canister deployment:** the `wasm32-unknown-unknown` target,
  [`dfx`](https://internetcomputer.org/docs/building-apps/getting-started/install),
  and a local or mainnet replica.

### Build &amp; test

Most work — type-checking, the full protocol test suite, linting — needs only a
Rust toolchain:

```bash
cargo test -p ciphersettle_core   # 85 tests: the executable protocol spec
cargo build --workspace           # also compiles the canister crate
cargo clippy --workspace          # zero warnings at the default lint level
```

### Deploy to a local replica

```bash
rustup target add wasm32-unknown-unknown
dfx start --background
dfx deploy

dfx canister call ciphersettle_backend register_invoice \
  '("inv-001", "issuer-tax-id-123", "INV-001", "USD", 10000, 1893456000, blob "\00\01\02")'
dfx canister call ciphersettle_backend grant_settlement_access \
  '("inv-001", principal "aaaaa-aa")'
dfx canister call ciphersettle_backend mark_settled '("inv-001")'
dfx canister call ciphersettle_backend get_audit_log '(opt "inv-001", null, null)'
```

> Note: the production vetKD key is **not** configured. `vetkd_key_id()` uses
> `"dfx_test_key"`, which only exists on a local replica. Mainnet requires
> requesting a real key name for your subnet.

---

## Security

This project's history is documented as a series of applied-cryptography review
rounds (kept for transparency in the previous README's changelog and the commit
history). Notable properties and current posture:

- **No raw invoice fields are persisted** — only the nullifier (a hash of
  canonicalized, length-prefixed identifying fields with a domain separator).
- **Canonicalized nullifiers** — currency is case-folded and shape-validated,
  fields are trimmed, non-ASCII is rejected — so `"USD"` vs `"usd"` or
  `" INV-001 "` vs `"INV-001"` can't be used to dodge the double-financing check.
- **`register_invoice` is no longer a membership oracle.** Rejections past field
  validation (duplicate nullifier vs. duplicate `invoice_id`) return identical
  generic text; the specific reason is recorded in the admin audit log only.
- **Confidential reads are update calls**, gated per role, and every read is
  logged.
- **Limited privilege creep** — `get_encrypted_invoice` is not admin-readable.
- **Hashing via the audited `sha2` crate**, not a hand-rolled implementation.

### Reporting a vulnerability

Do **not** open a public issue for security bugs. Report privately via the
repository's **Security** tab, following [SECURITY.md](SECURITY.md). Please read
it — especially the scope section — before you trust any of this with real data.

---

## Open design questions

These are decisions that need a design choice, not just more code. They are
documented here so contributors and deploying parties know exactly where the
rigor currently ends.

1. **The nullifier trusts the caller's declared fields.**
   - **Front-running / squatting.** Anyone who can observe or guess the fields
     can compute the identical nullifier and register it first, blocking the
     real issuer. The real fix is *external attestation* (an authoritative
     registry signing off that a specific issuer may register a specific
     invoice number); a smaller interim step is requiring the registering
     caller to be pre-registered as the issuer for the declared
     `issuer_identifier`.
   - **Field choice is a product decision.** The identity hash currently
     includes amount and due date alongside issuer + invoice number. A narrower
     key (issuer + invoice number only) plus an explicit `amend_invoice`
     operation is a defensible alternative.
2. **Client-side encryption is unspecified.** The canister defers to
   `@dfinity/vetkeys` (correctly — it never sees plaintext), but the concrete
   hybrid-encryption construction (AEAD choice, how the vetKD-derived key feeds
   in, how associated data binds ciphertext to `invoice_id`) lives in an
   unwritten frontend. Pin this down as a spec before treating the API as
   SDK-ready.
3. **Key revocation is authorization-only, not cryptographic.**
   `revoke_settlement_access` stops a party deriving a key *again*; it cannot
   invalidate a key already derived and decrypted client-side. True
   point-in-time revocation requires a generation counter mixed into the vetKD
   input plus client-side re-encryption — real work, scoped as its own feature.
4. **Rate limiting is per-principal, not per-identity-cost.** Cheaply-created
   principals can still spread calls across identities. Closing this needs
   cycles-attached calls or a real identity/subscription gate.
5. **Stable-memory decode panics on corruption.** `Decode!(...).expect(...)`
   panics on corrupted stable memory; a clean fix needs a schema-version byte
   plus a `post_upgrade` migration path.
6. **Upgrade governance is a deployment decision.** `transfer_admin` exists, but
   who may push a wasm upgrade is IC controller-list configuration outside this
   repo. Decide and document it (black-holed canister, multisig, DAO, time lock)
   before claiming "no standing master key."

---

## Roadmap

High-priority, in rough order of value:

1. **External attestation** for nullifier registration — closes the
   front-running/squatting question (open item 1a).
2. **Encryption-construction spec** for the client — pin the hybrid-encryption
   scheme so the API becomes SDK-ready (open item 2).
3. **Real vetKD mainnet key** provisioning and a live-replica test pass.
4. **Generation-counter key rotation** for cryptographic revocation (open
   item 3).

Lower priority, explicitly out-of-scope-by-design today:
- KYC/AML and identity-provider integrations
- A dispute/challenge mechanism
- SaaS billing / paywall enforcement
- Any external system-of-record outcall

> **Design constraint — "don't touch the money."** If you extend this toward
> real settlement, keep fund custody and movement *entirely outside* the
> canister: route it through a licensed banking/payment rail the deploying party
> already uses, and charge a flat software fee rather than taking a cut of
> settled volume.

---

## Contributing

Contributions are welcome — and because this is security-relevant code, please
read the docs first so your work fits the project's actual state.

- **[CONTRIBUTING.md](CONTRIBUTING.md)** — architecture ("change rules in
  `ciphersettle_core` first"), dev setup, testing expectations, workflow.
- **[SECURITY.md](SECURITY.md)** — private vulnerability reporting.
- **[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)** — community standards.

Bug reports and feature requests use the templates under `.github/`.

---

## License

[MIT](LICENSE) © 2026 [aliibrahim0xali-ibrahim](https://github.com/aliibrahim0xali-ibrahim).
