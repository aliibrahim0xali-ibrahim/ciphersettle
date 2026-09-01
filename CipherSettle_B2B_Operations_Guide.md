# VetKeys-Powered Invoice Settlement Canister in a B2B Context: Utilization, Operation, and the Full Lifecycle

This document has two parts. Part 1 describes how this canister (formerly the VetKeys-Powered Invoice Settlement Canister) fits into a real B2B invoice-financing operation — the actors, the integration surface, the commercial model, and the operational responsibilities each party takes on. Part 2 walks through the two lifecycle scripts included in this repository, which together cover the full protocol lifecycle (setup, registration, verification, rejection, settlement, wind-down) and were both actually run and checked as part of writing this document, not just described.

---

## Part 1 — The VetKeys-Powered Invoice Settlement Canister in a B2B Context

### 1.1 The business problem, restated for a B2B audience

Invoice financing is a B2B transaction pattern: a supplier (the **issuer**) sells goods or services to a buyer on payment terms, then wants cash before those terms are up, so they pledge or sell the receivable to a bank, factor, or invoice-financing platform (the **bank/financier**). The recurring operational risk in this market is **double-financing** — the same invoice pledged to more than one financier, discovered only during reconciliation, a payment dispute, or a fraud investigation. Today this is largely handled by manual checks, bilateral trust, or centralized registries that force every participant to expose commercially sensitive data (who's financing whom, at what terms) to a platform operator or to each other.

The canister's B2B pitch is narrow and specific: **a shared, neutral registry that can answer "has this exact invoice already been claimed?" without any participant — including the registry operator — being able to read the invoice itself.**

### 1.2 The four B2B roles, mapped to the protocol

| Protocol role | Real-world B2B counterpart |
|---|---|
| **Issuer** | The supplier / seller of goods or services — the company whose receivable is being financed. Typically integrates via their ERP or accounts-receivable system. |
| **Bank / financier** | A bank, factoring company, or invoice-financing platform. Receives settlement access from the issuer, verifies the invoice is genuine and unclaimed, and (in the full system, once the client-side encryption spec exists — see §1.6) decrypts and reviews the invoice content before advancing funds. |
| **Regulator** | A compliance function with standing disclosure rights — a tax authority, an AML/KYC auditor, or (for a private deployment) the platform operator's own compliance team. Every regulator access is logged distinctly as a `disclosure_request`, not conflated with ordinary bank access, which matters for audit and regulatory-defense purposes. |
| **Admin** | The platform operator running the canister — typically the company offering this canister as a service, or an internal platform team at a large financial institution running it for their own network of suppliers and financing partners. Manages regulator onboarding and admin-key rotation; deliberately has **no** path to read invoice ciphertext (see the round-3 review's §5 finding on this). |

A single B2B deployment can have many issuers and many banks operating against one canister — the protocol doesn't assume a 1:1 relationship. A large buyer could run a private instance of this canister for its entire supplier base and a panel of approved financing partners; a neutral platform operator could run a public instance serving many unrelated issuer/bank pairs, the way a traditional invoice-exchange platform does today, but without the operator itself being a trust bottleneck for confidentiality.

### 1.3 Integration surface for a B2B partner

This canister is delivered as an Internet Computer canister with a Candid interface (`ciphersettle_backend.did`) — this is the actual API surface a B2B integrator's engineering team builds against. Three practical integration patterns:

- **Direct canister calls.** Any language with an IC agent library (`agent-js`/TypeScript, `agent-rs`/Rust, `ic-py`, etc.) can call the canister's 12 methods directly. This is the lowest-friction path for a fintech's own backend team.
- **A thin REST/webhook wrapper.** Most B2B counterparties — an ERP system, a legacy banking core — don't speak Candid natively. A realistic integration shape is a small service (run by the platform operator, or by a sophisticated issuer/bank) that translates REST/webhook calls into IC canister calls, handles the vetKD transport-key dance client-side, and exposes a conventional API to the counterparty's existing systems.
- **A signed batch-upload pattern for high-volume issuers.** An issuer with thousands of invoices a month wants to register them programmatically, not one dfx call at a time — their AR system calls `register_invoice` directly (or through the wrapper above) as invoices are generated, ideally as part of the existing invoice-issuance workflow rather than a separate manual step.

Every method's `.did` signature is authoritative and, as of round 4 of this project's review, mechanically verified against the actual compiled canister (see `src/ciphersettle_backend/src/lib.rs`'s `candid_interface_tests` module) — an integrator can trust it hasn't silently drifted from the real behavior.

### 1.4 What a B2B operator is actually responsible for

Running this canister for real counterparties is not "deploy the canister and you're done." A platform operator (the `admin` principal) takes on real, ongoing responsibilities:

- **Regulator onboarding and offboarding** (`register_regulator`/`revoke_regulator`) — a real compliance decision with real consequences, not a technical afterthought. Every registered regulator gets standing disclosure access to every invoice on the platform.
- **Admin-key custody and rotation policy** (`transfer_admin`) — who holds the admin key, how it's rotated, and what happens if it's lost or compromised is a governance decision this project deliberately does not make for you (see the README's "Still open" item 6 on upgrade governance).
- **Issuer/bank vetting**, if your deployment chooses the "issuer-principal pre-registration" mitigation for the front-running risk described in §1.5 below — this is real KYC-adjacent operational work, not a config flag.
- **Monitoring the audit log** for anomalies — the admin's unscoped `get_audit_log` read is the only view of the entire cross-invoice relationship graph, and is exactly the tool an operator would use to notice, for example, an unusual pattern of rejected registration attempts (a possible sign of the field-guessing activity described below).

### 1.5 What to tell a B2B counterparty about the current guarantees, precisely

This matters commercially, not just technically: **overselling what's actually enforced today is a real business risk**, not just a documentation nicety. Based on five rounds of applied-cryptography review in this repository, here is the accurate, current claim set:

**What this canister actually enforces today:**
- Two honest, independent submissions of the same invoice (same issuer, invoice number, currency, amount, and due date) will always collide and the second is rejected — the core double-financing check works.
- Small cosmetic differences (case, whitespace) between two submissions of the same invoice don't create a false "different invoice" — this was a real gap closed in round 2.
- Invoice content is never visible to the canister or its operator in plaintext; only ciphertext and access-control metadata are ever stored.
- Every disclosure of decryption capability is logged, distinctly, by role (issuer/bank/regulator).
- An unauthenticated party cannot use the registration endpoint to learn whether a specific guessed invoice already exists — this was a real gap closed in round 3.

**What this canister does not yet enforce, and should not be represented as enforcing to a counterparty:**
- **Front-running.** Because the nullifier is a deterministic hash of fields with no secret mixed in, a third party who can guess or observe an invoice's fields can register that nullifier first, blocking the legitimate issuer. Closing this needs either an external attestation authority (a tax registry or e-invoicing platform vouching for a specific issuer/invoice pairing) or, as a smaller interim step, pre-registering which principal is allowed to act as which issuer. **Neither is built yet.** Any B2B pitch should describe double-financing prevention as "prevents accidental or naive duplicate submission" today, not "cryptographically prevents fraud by a sophisticated adversary," until this is closed.
- **The client-side encryption construction doesn't exist yet.** The canister correctly handles key derivation (vetKD) and access control; the actual encrypt/decrypt flow a client application would use is unspecified. This is the single largest piece of unbuilt work standing between this repository and a real product a bank could integrate against for actual invoice content review.
- **Key revocation is authorization-only, not cryptographic.** Revoking a bank's settlement access stops them from deriving a *new* key; it does not invalidate a key they already derived. A bank that already reviewed an invoice retains that capability indefinitely. This is inherent to the current design, not a bug, but it must be stated plainly in any counterparty-facing terms.
- **No external audit has occurred.** Five rounds of increasingly rigorous self-review (including, as of round 4, actual compilation and testing rather than manual code reading) is real diligence, but it is not a substitute for an independent security firm's review before any deployment handling real financial instruments.

### 1.6 A realistic path to a first production B2B pilot

In priority order, based on the cumulative findings across this project's review rounds:

1. **Specify and build the client-side encryption construction.** Without this, there is no actual confidentiality product to sell — everything else in the canister is infrastructure in service of a step that doesn't exist yet.
2. **Decide and implement one of the front-running mitigations** (external attestation, or issuer-principal pre-registration as the smaller interim step) before onboarding any counterparty who might be exposed to a sophisticated adversary rather than just accidental duplicate submission.
3. **Decide the nullifier field-selection question** (whether amount/due-date belong in the identity hash, or only issuer+invoice-number with an explicit amendment flow) — this changes what "double-financing prevention" means and should be a deliberate product decision communicated to pilot counterparties, not an implicit default.
4. **Commission an external cryptographic and smart-contract audit** before any pilot that touches real invoices with real financial consequences.
5. **Decide and document upgrade governance** (who can push a canister upgrade, and under what process) before any counterparty is asked to trust "no standing master key" as a security property of the deployment, not just the code.

---

## Part 2 — Lifecycle Scripts: Setup Through Wind-Down

Two scripts are included in this repository, covering the same scenario at two different levels:

| Script | What it exercises | Verified how |
|---|---|---|
| `src/ciphersettle_core/examples/b2b_lifecycle_simulation.rs` | The actual access-control, nullifier, and audit-logging **logic** — runs against `ProtocolState`, the same pure-logic "executable spec" the canister is built from | **Actually compiled and run in this session** — every step's outcome is checked with `assert!`/`assert_eq!`, not just printed |
| `scripts/b2b_lifecycle_demo.sh` | The same scenario translated into real `dfx canister call` invocations against a **deployed canister** | Not executable in this sandbox (no `dfx`, no network path to fetch it) — provided as the operational reference translation of the verified Rust logic above, reviewed against `ciphersettle_backend.did` and `lib.rs` line by line |

### 2.1 Running the verified simulation

```bash
cargo run --example b2b_lifecycle_simulation -p ciphersettle_core
```

This actually ran clean in this session (zero panics, all assertions passed) and printed the following real output for the registration step, confirming the nullifier derivation and the full lifecycle work end to end:

```
[02] Registration: Acme registers a real invoice
----------------------------------------------
Registered ACME-2026-Q3-00231 for Acme -- nullifier receipt: 3019bd662d618eeda170dab9523d08545d7b4746da0a3ec92d9943b130cbfb81

...

=====================================================
 All 11 scenario steps completed and asserted correctly.
=====================================================
```

The 11 steps, and what each one demonstrates:

1. **Platform setup** — admin onboards a regulator (Northbridge Compliance Partners); confirms a non-admin cannot do the same.
2. **Registration** — Acme Manufacturing registers a real invoice; receives the derived nullifier as a receipt.
3. **Rejection (double-financing)** — an uncoordinated second submission of the *identical* invoice fields, under a different invoice_id and a different caller, is rejected.
4. **Rejection (oracle-closing check)** — confirms the "duplicate fingerprint" and "duplicate invoice_id" rejections produce the *same* caller-facing message, so an unauthenticated party can't use the distinction to learn which invoices already exist (the round-3/round-5 finding).
5. **Verification setup** — Acme grants Meridian Trade Finance settlement access.
6. **Verification (bank)** — Meridian successfully derives access; an unrelated third party is denied the same request.
7. **Verification (regulator)** — Northbridge, with standing disclosure rights, also derives access, resolved to a distinct `Regulator` role for audit purposes.
8. **Access change** — Acme revokes Meridian's access mid-lifecycle (a realistic scenario: the financing arrangement falls through) and grants a replacement bank instead; confirms Meridian can no longer derive a *new* key, while noting the already-derived key from step 6 isn't retroactively invalidated.
9. **Execution (settlement)** — the new bank marks the invoice settled; a second settlement attempt is rejected.
10. **Verification (audit trail)** — the issuer reads their own invoice's full history; an unrelated party is denied; the admin reads the unscoped, cross-invoice log and can see the rejected registration attempts from steps 3–4, filed under a reserved `"*"` invoice_id.
11. **Wind-down** — confirms ciphertext is not prune-eligible immediately after settlement, and becomes eligible once past the ~180-day retention window.

### 2.2 Running the deployment-level script

```bash
dfx start --background
dfx deploy
export ACME_PRINCIPAL=... MERIDIAN_PRINCIPAL=... BRIDGEPORT_PRINCIPAL=... NORTHBRIDGE_PRINCIPAL=...
./scripts/b2b_lifecycle_demo.sh
```

This mirrors the same 11-step scenario as real `dfx canister call` invocations, with an expected-response comment after each call so an operator running it against a real replica can immediately see whether the deployment is behaving as intended. It requires `dfx` identities set up per organization (`acme-mfg`, `meridian-tf`, `bridgeport-capital`, `northbridge-compliance`) to realistically simulate distinct B2B counterparties acting under their own authenticated principals, exactly as they would in production.
