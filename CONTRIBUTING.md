# Contributing to VetKeys-Powered Invoice Settlement Canister

Thanks for your interest in contributing. This is a small personal open-source
project, so clear, well-scoped contributions are especially appreciated.

Please read the [README](README.md) first — especially its review-round notes
and the "Still open" section — so your contribution fits the project's actual
state rather than duplicating or undermining work already discussed.

## Ground rules

* This is a **proof-of-concept, not production-ready, not audited** codebase.
  Treat any change as part of that ongoing review effort, and say so in your PR.
* **Security-relevant changes get extra scrutiny.** This project deals with
  keys, access control, and a public nullifier registry. If your change touches
  cryptography, authz decisions, or information leakage, expect a slower,
  more careful review. See [SECURITY.md](SECURITY.md).
* Keep scope tight. A focused PR that does one thing well is far more likely to
  be merged than a large one that touches many concerns.
* Be respectful. Our [Code of Conduct](CODE_OF_CONDUCT.md) applies to all
  contributors.

## Architecture — read this before you change logic

The project has two crates with a deliberate split:

* **`ciphersettle_core`** — a pure Rust "executable spec" with **no IC
  dependencies**. All protocol *rules* live here (access decisions, nullifier
  derivation, rate limiting, payload-size checks, retention logic) and are
  unit-tested in isolation.
* **`ciphersettle_backend`** — the IC canister (`ic-cdk`, stable memory, vetKD
  integration) that wires the core rules into real canister endpoints.

**Treat `ciphersettle_core` as the executable spec.** When you change a rule,
change it in `ciphersettle_core` first, get it green with tests, then port it
to `ciphersettle_backend`. Don't implement rules only in the canister.

## Development setup

### The easy path (needs only a Rust toolchain)

Most work can be done and tested without `dfx` or the wasm target:

```bash
cargo test -p ciphersettle_core
cargo build --workspace
cargo clippy --workspace
```

There is a pinned toolchain and checked-in `Cargo.lock` so the workspace
builds on `rustc 1.75` (see the pin block and comment in
`src/ciphersettle_backend/Cargo.toml`). If you're on a current rustup
toolchain (1.85+), the README recommends *removing* those pins rather than
freezing yourself to old versions.

### The canister path (needs `dfx` + `wasm32`)

An actual canister build/deploy requires the `wasm32-unknown-unknown` target
and a local replica:

```bash
rustup target add wasm32-unknown-unknown
dfx start --background
dfx deploy
```

See README "Running it locally" for example calls.

## Testing

* Every rule you add or change in `ciphersettle_core` **must** have unit tests
  that pass in that crate. This is the project's primary test surface.
* The backend crate intentionally has almost no unit tests of its own — its
  logic is thin wiring over the core spec. Prefer adding coverage in the core
  crate.
* There is no CI configured yet. Run `cargo build`, `cargo test`, and
  `cargo clippy` across the workspace before submitting.

## Code style

* **No comments unless they earn their place.** The existing code is heavily
  commented because security decisions need explaining; that's a high bar, not
  a license to add noise.
* Match the surrounding style: doc comments on public items, `#[derive]`s in
  the same order, same naming conventions.
* Keep public API changes deliberate and documented. A changed signature on a
  canister endpoint is a **breaking interface change** that must be reflected
  in `ciphersettle_backend.did` and the README.

## Workflow

1. **Check for an existing issue** before opening a new one. If none exists,
   open an issue describing what you want to do, especially for anything large
   or security-relevant, so work isn't wasted.
2. **Fork and branch** from `main`. Name your branch after the work, e.g.
   `fix/audit-log-offset`.
3. **Write the change** in `ciphersettle_core` first (see Architecture above).
4. **Add tests** and run the whole workspace:
   ```bash
   cargo build --workspace && cargo test --workspace && cargo clippy --workspace
   ```
5. **Open a pull request** using the [PR template](.github/PULL_REQUEST_TEMPLATE.md)
   and fill it out completely, especially the parts about what you changed and
   how you verified it.
6. **Respond to review.** Expect requests for changes on security-related PRs
   in particular.

## Reporting security issues

Do **not** file public issues for vulnerabilities. See
[SECURITY.md](SECURITY.md) for how to report privately.

## Getting help

Ask in issues/discussions. This is a small project — the maintainer may take a
while to respond, and that's normal.
