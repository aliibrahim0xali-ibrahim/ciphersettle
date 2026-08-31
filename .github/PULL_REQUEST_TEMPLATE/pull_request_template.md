## Summary

<!-- What does this change do, in one or two sentences? -->

## Is this security-related?

- [ ] No — routine change
- [ ] Yes — it touches access control, key handling, information leakage,
      cache/rate-limit behavior, or another security-sensitive area
      (if so, expect a more careful review; see SECURITY.md)

## Where did you change it?

- [ ] `ciphersettle_core` (executable spec / protocol rules)
- [ ] `ciphersettle_backend` (canister wiring, vetKD, stable memory)
- [ ] Candid interface (`.did`)
- [ ] Docs / CI / build / tooling

## Protocol change? (was a rule changed first in `ciphersettle_core`?)

<!-- Protocol rules must be changed in ciphersettle_core first and tested
     there, then ported to the canister. Describe that flow here, or note
     why this PR doesn't follow it. -->

## Testing

- [ ] `cargo build --workspace`
- [ ] `cargo test --workspace`
- [ ] `cargo clippy --workspace`
- [ ] Added/updated unit tests (required for changes in `ciphersettle_core`)
- [ ] Candid interface regenerated/verified if endpoints changed

## Breaking interface changes?

<!-- Any signature change to a canister endpoint is breaking and must be
     reflected in ciphersettle_backend.did and the README. -->

- [ ] No
- [ ] Yes — describe them here

## Related issues / "Still open" items

<!-- Link any issues this closes, and any README "Still open" item it
     addresses. -->

Closes #
