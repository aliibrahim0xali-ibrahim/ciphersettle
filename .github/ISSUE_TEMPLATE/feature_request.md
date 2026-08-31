---
name: Feature request
about: Propose a new feature or extension point
title: "[Feature] "
labels: enhancement
assignees: ''
---

**What problem does this solve?**
Describe the real-world problem or gap this addresses.

**Which area does it touch?**
- [ ] `ciphersettle_core` protocol rule (nullifier, access, retention, rate limit)
- [ ] `ciphersettle_backend` canister endpoint / interface
- [ ] Client-side encryption or vetKD integration (note: much of this is
      deliberately out of scope and delegated to `@dfinity/vetkeys`)
- [ ] Docs / tooling / CI

**Proposed behavior**
How you expect it to behave.

**Does this relate to a "Still open" item in the README?**
If so, name it. Several open items are design decisions, not just code gaps
(e.g. which fields belong in the nullifier hash, key revocation vs.
authorization-only, external attestation) — say explicitly which decision(s)
this proposal makes.

**Trade-offs / risks**
Anything security- or design-relevant: information leakage, breaking interface
changes, new dependencies, storage/cycles costs.

**Alternatives considered**
What else you looked at and why this is better.
