---
name: Bug report
about: Report something that's wrong in the protocol logic or the canister
title: "[Bug] "
labels: bug
assignees: ''
---

**Is this security-related?**
If this could be a vulnerability (access control, key handling, information
leakage, oracle/side-channel), do **not** file it here. Report it privately via
the Security tab instead — see [SECURITY.md](../SECURITY.md).

**Describe the bug**
A clear and concise description of what's wrong.

**Where does it live?**
- [ ] `ciphersettle_core` (executable spec / protocol rules)
- [ ] `ciphersettle_backend` (canister wiring, vetKD, stable memory)
- [ ] Candid interface (`.did`)
- [ ] Docs / CI / build

**Steps to reproduce**
1. ...

**Expected behavior**
What should happen instead.

**Environment**
- Rust toolchain version / `cargo --version`
- `dfx` version (if applicable)
- Target built: host vs `wasm32-unknown-unknown`

**Verification already done**
- [ ] `cargo build --workspace`
- [ ] `cargo test --workspace`
- [ ] `cargo clippy --workspace`

**Additional context**
Anything else relevant, including any known "Still open" item from the README
this touches.
