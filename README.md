# CipherSettle

A confidential invoice-financing and settlement protocol for the [Internet Computer](https://internetcomputer.org), written in Rust.

CipherSettle lets an invoice issuer register an encrypted invoice on-chain together with a **nullifier** that provably prevents double-financing — while the canister itself never sees, stores, or derives any plaintext. Financing banks get scoped, revocable access; regulators get audited, per-request disclosure instead of standing keys; and every security-relevant event lands in a permanent public audit trail.

> **Status: Phase-1 PoC.** Fully tested on a local IC replica (`dfx`): **55/55 unit tests** and a **49-check end-to-end suite** covering every endpoint, positive and negative paths. Not deployed to mainnet, not audited, not production-ready.

---

## Table of contents

- [Why](#why)
- [Architecture](#architecture)
- [Roles](#roles)
- [Protocol flow](#protocol-flow)
- [API reference](#api-reference)
- [Getting started](#getting-started)
- [Testing](#testing)
- [Configuration](#configuration)
- [Design principles](#design-principles)
- [Known limitations](#known-limitations)
- [Roadmap](#roadmap)

---

## Why

Invoice financing has a fraud problem: the same invoice can be pledged to multiple lenders who cannot see each other's books. CipherSettle addresses this with a shared, trust-minimized registry:

| Problem | CipherSettle answer |
|---|---|
| Same invoice financed twice | Public nullifier registry — second submission is rejected on-chain |
| Invoice contents exposed on-chain | Client-side encryption; canister stores ciphertext only |
| Lender needs read access | Issuer grants settlement access to exactly one bank principal |
| Regulator oversight | Per-request vetKD key derivation, each logged as `disclosure_request` |
| "Was my data accessed?" | Permanent, public, metadata-only audit log |

## Architecture

Two-crate Rust workspace:

```
src/
├── ciphersettle_core/       Pure protocol logic — no platform dependencies
│   └── src/lib.rs           Access resolution, nullifier checks, rate limiting,
│                            payload/identifier guards, cycles fee, pruning
│                            eligibility, disputes, ProtocolState
│                            (executable spec) + 55 unit tests
└── ciphersettle_backend/    The Internet Computer canister
    ├── src/lib.rs           ic-cdk endpoints, stable storage, vetKD integration
    └── ciphersettle_backend.did   Candid interface
```

**`ciphersettle_core` is the executable specification.** It contains every security decision as a pure, clock-injected, dependency-free function, so rules can be tested exhaustively without a replica. `ciphersettle_backend` wires those decisions to real endpoints and storage. Change a rule in the core first, get it green, then port it.

Stable storage layout (survives canister upgrades):

| Memory ID | Structure | Contents |
|---|---|---|
| 0 | `StableBTreeMap<String, u8>` | Nullifier set (presence = already claimed) |
| 1 | `StableBTreeMap<String, InvoiceRecord>` | Invoices incl. ciphertext |
| 2 | `StableBTreeMap<Principal, u8>` | Registered regulators |
| 3 | `StableBTreeMap<u64, AuditEvent>` | Append-only audit log |
| 4 | `StableCell<Principal>` | Admin (deployer) |
| 5 | `StableBTreeMap<Principal, Vec<u64>>` | Rate-limit call history |

## Roles

| Role | Who | Powers |
|---|---|---|
| **Issuer** | Caller of `register_invoice` | Reads own ciphertext, grants/revokes bank access, settles, raises disputes |
| **Bank** | Principal granted by issuer | Reads ciphertext, derives decryption key, settles, raises disputes |
| **Regulator** | Admin-registered principal | Derives decryption keys; **every derivation is logged as `disclosure_request`** — even if the principal is also the issuer. Can also raise disputes |
| **Admin** | Canister deployer | Registers/revokes regulators; prunes expired ciphertext |
| **Stranger** | Everyone else | Read-only access to the public audit log |

Role priority matters: if a principal holds several roles, `resolve_access` labels their access by the *most sensitive* role (regulator → disclosure logging wins over issuer/bank).

## Protocol flow

```
 issuer                canister                      bank                 regulator
   │                      │                           │                       │
   │ encrypt invoice      │                           │                       │
   │ client-side (vetKD)  │                           │                       │
   │──────────────────────►│ register_invoice          │                       │
   │                      │  ├─ nullifier fresh? ──┐   │                       │
   │                      │  │  size ≤ 64 KiB?     │   │                       │
   │                      │  ▼ stored as ciphertext   │                       │
   │                      │                           │                       │
   │ grant_settlement_access(bank)                    │                       │
   │──────────────────────►│───────────────────────────►│                      │
   │                      │                           │ derive_invoice_key    │
   │                      │◄──────────────────────────│ (rate-limited)        │
   │                      │                           │ decrypt client-side   │
   │                      │                           │                       │
   │                      │◄──────────────────────────────────────────────────│ derive_invoice_key
   │                      │ logs disclosure_request ──────────────────────────►│ (audited disclosure)
   │                      │                                                                   │
   │ mark_settled         │  (fund movement happens OFF-canister)             │
   │─────────────────────►│                                                   │
   │                      │ after settled + 180-day retention:                │
   │                      │  admin prune_ciphertext: payload dropped,         │
   │                      │  record + audit kept forever                      │
```

## API reference

Candid interface (`ciphersettle_backend.did`):

| Method | Type | Caller | Description |
|---|---|---|---|
| `register_invoice(id, nullifier_hash, ciphertext)` | update | anyone | Register encrypted invoice; rejects reused nullifiers, duplicate ids, malformed identifiers, payloads > 64 KiB |
| `grant_settlement_access(id, bank)` | update | issuer only | Grant read/derive/settle rights to one bank |
| `revoke_settlement_access(id)` | update | issuer only | Revoke current bank; errors if nothing granted |
| `mark_settled(id)` | update | issuer or granted bank | Terminal state; rejects double-settling |
| `raise_dispute(id)` | update | issuer / granted bank / regulator | Permanent on-chain dispute flag; logged as `dispute_raised`; errors if already open |
| `prune_ciphertext(id)` | update | admin only | Drop ciphertext once settled + retention expired; errors otherwise |
| `get_encrypted_invoice(id)` | query | issuer / granted bank / regulator | Returns ciphertext blob |
| `derive_invoice_key(id, transport_pk)` | update | issuer / granted bank / regulator | vetKD-derived key; requires attached cycles fee ≥ `MIN_DERIVE_KEY_FEE_CYCLES`, rate-limited 5/60 s per caller; regulator calls logged as `disclosure_request` only after success |
| `get_vetkd_public_key()` | update | anyone | Canister's vetKD public key |
| `register_regulator(p)` | update | admin only | Grant standing (but always-logged) disclosure role |
| `revoke_regulator(p)` | update | admin only | Remove regulator; errors if not registered |
| `get_audit_log(?id)` | query | public | Metadata-only events: `{ id, invoice_id, actor, action, timestamp }` |

Audit `action` values: `invoice_registered`, `settlement_access_granted`, `settlement_access_revoked`, `invoice_settled`, `dispute_raised`, `ciphertext_pruned`, `key_derived_bank`, `key_derived_issuer`, `disclosure_request`, `key_derivation_failed`, `regulator_registered`, `regulator_revoked`.

## Getting started

### Prerequisites

- Rust 1.78+ via [rustup](https://rustup.rs) (a modern toolchain; the CI-tested floor is what `ic-cdk` currently requires)
- [`dfx`](https://internetcomputer.org/docs/building-apps/getting-started/install) ≥ 0.25 (tested on 0.31.0)
- The wasm32 target: `rustup target add wasm32-unknown-unknown`

### Run the pure-logic spec

No replica needed — this is the fastest way to verify the protocol rules:

```bash
cargo test -p ciphersettle_core
```

### Deploy to the local replica

```bash
dfx start --background
dfx deploy ciphersettle_backend
```

### Example session

```bash
dfx canister call ciphersettle_backend register_invoice \
  '("INV-001", "nullifier-hash-abc", blob "\DE\AD\BE\EF")'
# (variant { Ok })

dfx canister call ciphersettle_backend grant_settlement_access \
  '("INV-001", principal "eplmr-k3n7k-mf43l-ghmpa-kennn-iudmm-nwpue-qj4me-jvouc-5jjo2-vqe")'

dfx --identity bank canister call ciphersettle_backend get_encrypted_invoice '("INV-001")'

dfx --identity bank canister call ciphersettle_backend derive_invoice_key \
  '("INV-001", vec{151; 241; ...})'   # 48-byte BLS12-381 G1 compressed transport pubkey

dfx canister call ciphersettle_backend get_audit_log '(null)'
```

> **vetKD transport keys must be exactly 48 bytes** (compressed BLS12-381 G1 point). The management canister rejects anything else at deserialization time.

> Local vetKD uses the `"dfx_test_key"` key id (`vetkd_key_id()` in the backend). Mainnet requires provisioning your own key name before deploying.

### Deploying to IC mainnet

Mainnet deployment requires cycles (~2–5 T recommended). Fund your identity's account, then:

```bash
dfx deploy ciphersettle_backend --network ic --with-cycles <N>
```

Check your balance first with `dfx ledger balance --network ic`.

## Testing

### Unit tests (pure logic)

```bash
cargo test -p ciphersettle_core   # 55 tests
```

Covers: nullifier double-financing rejection, role resolution and priority (including dual-role principals), revocation semantics (non-silent no-op prevention), settlement lifecycle, disputes (who may raise, permanence across settlement), admin-gated pruning, pruning eligibility at/before/after the retention boundary, sliding-window rate limiting at boundaries, payload-size guard, identifier format validation, cycles-fee threshold, and a full `ProtocolState` lifecycle simulation.

### End-to-end suite (live replica)

An automated 49-check suite exercises every endpoint against a running canister — positive paths plus denial cases (stranger reads, non-issuer grants, unauthorized derivation, underfunded derivation, rate-limit trip at call 6, double-settle, dispute abuse, premature/unauthorized prune, revoked-regulator cutoff) and audit-trail completeness.

```bash
bash e2e.sh                        # RESULT: 49 passed, 0 failed
```

The suite reinstalls the canister first (wiping state), so it can be re-run back-to-back.

> **Wallet-relayed calls:** dfx implements `--with-cycles` by relaying through your identity's wallet canister, so the canister sees the *wallet principal* as the caller. The suite's paid-derivation checks therefore run against a dedicated invoice granted to the bank's wallet principal — the same integration pattern any wallet-relayed client must use.

## Configuration

Constants live in `src/ciphersettle_backend/src/lib.rs`:

| Constant | Default | Purpose |
|---|---|---|
| `MAX_CIPHERTEXT_BYTES` | 64 KiB | Storage-inflation guard per invoice |
| `DERIVE_KEY_RATE_LIMIT` | 5 calls / 60 s | Sliding-window guard on cycle-expensive vetKD derivations, per caller |
| `MIN_DERIVE_KEY_FEE_CYCLES` | 1 B cycles | Anti-Sybil fee attached to each derivation attempt (accepted only after authorization passes; not refunded) |
| `MAX_INVOICE_ID_LEN` / `MAX_NULLIFIER_LEN` | 64 / 128 chars | Identifier bounds; ASCII `[A-Za-z0-9-_.:]` only |
| `CIPHERTEXT_RETENTION_NANOS` | ~180 days | Post-settlement retention before ciphertext may be pruned |
| `DOMAIN_SEPARATOR` | `ciphersettle-invoice-v1` | vetKD context binding; change breaks old keys |

These are reasonable starting heuristics, not cost-derived values — recompute from real cycle/storage data before production.

## Design principles

1. **The canister never sees plaintext.** Encryption happens client-side with vetKD (identity-based encryption); the canister stores ciphertext and gates *key derivation*, never content.
2. **Don't touch the money.** Settlement recording happens on-canister; fund movement stays off-canister through licensed payment rails. A protocol that deducts fees from money in flight looks like a payment processor to regulators; one that handles encryption, matching, and audit looks like infrastructure software.
3. **The audit trail is forever and metadata-only.** Records are append-only, publicly readable, contain no payload bytes, and survive pruning. Selective disclosure means regulators get per-request, individually logged access — there is no standing master key.
4. **Errors, not silent no-ops.** Revoking something already revoked, settling twice, pruning early — all return explicit errors so callers always know whether state changed.
5. **Jurisdiction-agnostic.** No named market, regulator, KYC provider, or e-invoicing system. Compliance hooks are pluggable extension points.

## Known limitations

Honest list — review before extending:

- **Nullifier binding is unverified.** The canister trusts that the submitted nullifier hash derives from the submitted invoice. A production system needs an on-chain ZK proof binding them without exposing plaintext.
- **Disputes are flags, not resolutions.** Participants and regulators can raise a permanent, logged dispute flag over an invoice's content, but there is no on-chain challenge/arbitration path — resolution stays off-canister.
- **The cycles fee is attempt-priced, not refundable.** An authorized caller pays for a failed vetKD round-trip (logged separately as `key_derivation_failed`). Denied callers are never charged. A billing/paywall layer would supersede this.
- **Rate limiting is per-principal**, now backed by the derivation fee — Sybil principals still pay per attempt, but heavy users can rotate principals to dodge the 5/60 s window.
- **Client-supplied `invoice_id` is format-checked but unbound** (`[A-Za-z0-9-_.:]`, ≤ 64 chars) — bind it to an authoritative system of record when you add one.
- **Wallet-relayed calls appear as the wallet principal.** Any endpoint called via a cycles-forwarding wallet sees `msg_caller = wallet`; clients must grant/authorize against whichever principal actually signs the call (see the e2e suite's paid-derivation section).
- **Not yet built:** client reference implementation (frontend vetKD/IBE), ZK nullifier proofs, dispute arbitration, SaaS billing/paywall, HTTPS outcalls to external registries.

## Roadmap

1. Reference browser/frontend client implementing vetKD encrypt/decrypt
2. ZK proof binding nullifier ↔ invoice commitment
3. Dispute/challenge resolution mechanism
4. Billing layer replacing the flat derivation fee
5. Mainnet deployment with production vetKD key + external review

---

**Not audited. Not deployed to mainnet. Do not trust real invoices to it.**
Treat this as a reviewed skeleton for your own development. Add a LICENSE file before treating this as open source.
