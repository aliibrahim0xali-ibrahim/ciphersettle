# Security Policy

The VetKeys-Powered Invoice Settlement Canister (formerly CipherSettle) is a proof-of-concept for a confidential invoice/settlement
registry on the Internet Computer. It handles cryptographic keys, access
control, and a public nullifier registry — the kind of code where a bug can
have real confidentiality or integrity consequences.

**This project is NOT audited and is NOT production-ready.** See the README
for the explicit list of known gaps and intentionally-open design questions
before trusting it with real data.

## Reporting a vulnerability

Please report security vulnerabilities privately rather than in a public issue
or PR.

- Open a **private vulnerability report** via GitHub's "Report a vulnerability"
  button on the repository's **Security** tab (this goes to the maintainers
  only).
- Do not include ciphertext, invoice data, or other sensitive test material in
  the report beyond what is needed to reproduce the issue.
- Do not create a public issue describing the vulnerability.

You should receive an acknowledgment of your report within a few days, and a
plan for resolution as soon as the maintainers can triage it.

## What to report

Examples of things worth reporting:

* Any flaw in `ciphersettle_core` (access-decision logic, nullifier derivation,
  rate limiting, payload-size handling).
* Any flaw in `ciphersettle_backend` — especially the vetKD key-derivation
  path, audit-log gating, or stable-memory handling.
* Information leakage (e.g. the kinds of oracle/side-channel issues already
  discussed in the README's review rounds).
* Upgrade or stable-memory migration hazards (see the README note on
  `Decode!(...).expect(...)` on corrupted stable memory).

## Scope

Vulnerabilities in the canister code in this repository are in scope. The
client-side hybrid-encryption construction (which the README explicitly leaves
unbuilt and delegated to `@dfinity/vetkeys`) is generally out of scope here, as
is the security of the Internet Computer platform itself. Nevertheless, if you
find something relevant to how the canister uses vetKD or deals with key
revocation, please report it — those are known-open design areas this project
actively wants scrutiny on.

## Responsible disclosure

We ask that you give maintainers a reasonable window (by default ~90 days, or
as agreed) to fix and, if applicable, release a coordinated disclosure before
publicizing a vulnerability.
