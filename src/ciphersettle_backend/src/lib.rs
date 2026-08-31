use candid::{CandidType, Decode, Encode, Principal};
use ciphersettle_core::{InvoiceFingerprint, Nullifier};
use ic_cdk::management_canister::{
    vetkd_derive_key, vetkd_public_key, VetKDCurve, VetKDDeriveKeyArgs, VetKDKeyId,
    VetKDPublicKeyArgs,
};
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::{storable::Bound, DefaultMemoryImpl, StableBTreeMap, StableCell, Storable};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::cell::RefCell;

type Memory = VirtualMemory<DefaultMemoryImpl>;

const DOMAIN_SEPARATOR: &[u8] = b"ciphersettle-invoice-v1";

// Storage-inflation guards.
const MAX_CIPHERTEXT_BYTES: usize = 64 * 1024;
const MAX_INVOICE_ID_BYTES: usize = 256;

// Cycle-drain guard on the expensive vetKD call: at most this many
// derive_invoice_key calls per caller per window.
const DERIVE_KEY_RATE_LIMIT: ciphersettle_core::RateLimitPolicy = ciphersettle_core::RateLimitPolicy {
    max_calls: 5,
    window_nanos: 60_000_000_000, // 60 seconds, in nanoseconds (ic_cdk::api::time() units)
};

// Round 3 review, §1: register_invoice previously had no rate limit at all --
// the only update call in this canister without one. On its own a rate
// limit doesn't close the nullifier-membership-oracle finding (see the
// error-message change on register_invoice below, which is the actual
// fix for that), but it raises the cost of a bulk field-guessing attack
// and is worth having regardless, the same way derive_invoice_key is
// already guarded. Deliberately more permissive than the vetKD limit:
// registration is the normal, frequent, legitimate operation for an
// issuer with real invoice volume, so this exists to slow down abuse, not
// to constrain ordinary use.
const REGISTER_RATE_LIMIT: ciphersettle_core::RateLimitPolicy = ciphersettle_core::RateLimitPolicy {
    max_calls: 20,
    window_nanos: 60_000_000_000, // 60 seconds
};

// Round 3 review, §4: get_audit_log(None) previously returned the entire
// audit log in one response with no bound. Fine for a demo canister with
// dozens of events; not fine once a canister has run long enough to
// accumulate thousands -- an unbounded Vec<AuditEvent> response will
// eventually hit the IC's practical message-size limit and simply fail.
// This caps every page regardless of what the caller requests; walking
// past `offset` entries in the underlying StableBTreeMap is still O(n) in
// the offset (this doesn't fix iteration cost for a very large offset),
// but it does bound response payload size, which is the specific failure
// mode being guarded against here.
const AUDIT_LOG_MAX_PAGE: u64 = 500;

// Loose sanity bounds on the caller-supplied vetKD transport public key.
// TODO before mainnet: confirm the exact expected byte length against the
// specific version of @dfinity/vetkeys / ic_vetkd_sdk_utils you pin, and
// replace this range with an exact-length check. A loose bound still stops
// a wildly malformed/oversized blob from reaching the system API; it is not
// a substitute for validating the real expected encoding.
const MIN_TRANSPORT_KEY_BYTES: usize = 32;
const MAX_TRANSPORT_KEY_BYTES: usize = 256;

// Ciphertext is only eligible for pruning once an invoice has been Settled
// and sat past this retention window. The audit log (metadata only) is never
// pruned -- see the doc comment on `prune_ciphertext` for why that split is
// deliberate.
const CIPHERTEXT_RETENTION_NANOS: u64 = 180 * 24 * 60 * 60 * 1_000_000_000; // ~180 days

// ---------- Data model ----------

#[derive(CandidType, Serialize, Deserialize, Clone, PartialEq, Eq)]
enum InvoiceStatus {
    Active,
    Settled,
}

#[derive(CandidType, Serialize, Deserialize, Clone)]
struct InvoiceRecord {
    issuer: Principal,
    bank: Option<Principal>,
    ciphertext: Vec<u8>, // encrypted client-side before submission; canister never sees plaintext
    created_at: u64,
    status: InvoiceStatus,
    settled_at: Option<u64>,
    ciphertext_pruned: bool,
}

impl Storable for InvoiceRecord {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }
    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self)
            .expect("corrupted InvoiceRecord in stable memory -- see README's note on stable-storage schema migration")
    }
    const BOUND: Bound = Bound::Unbounded;
}

#[derive(CandidType, Serialize, Deserialize, Clone)]
struct AuditEvent {
    id: u64,
    invoice_id: String,
    actor: Principal,
    action: String, // "invoice_registered" | "registration_rejected_duplicate_fingerprint" | "registration_rejected_duplicate_invoice_id" | "settlement_access_granted" | "settlement_access_revoked" | "invoice_settled" | "ciphertext_pruned" | "ciphertext_accessed" | "key_derived_issuer" | "key_derived_bank" | "disclosure_request" | "regulator_registered" | "regulator_revoked" | "admin_rotated"
    timestamp: u64,
}

impl Storable for AuditEvent {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }
    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self)
            .expect("corrupted AuditEvent in stable memory -- see README's note on stable-storage schema migration")
    }
    const BOUND: Bound = Bound::Unbounded;
}

// Wrapper so Principal can be stored in a StableCell (needs Storable + Default)
#[derive(CandidType, Serialize, Deserialize, Clone, Default)]
struct PrincipalWrapper(Option<Principal>);

impl Storable for PrincipalWrapper {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }
    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self)
            .expect("corrupted admin cell in stable memory -- see README's note on stable-storage schema migration")
    }
    const BOUND: Bound = Bound::Unbounded;
}

// Per-caller recent call timestamps for the derive_invoice_key rate limit.
#[derive(CandidType, Serialize, Deserialize, Clone, Default)]
struct CallTimes(Vec<u64>);

impl Storable for CallTimes {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }
    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self)
            .expect("corrupted rate-limit entry in stable memory -- see README's note on stable-storage schema migration")
    }
    const BOUND: Bound = Bound::Unbounded;
}

/// Local wrapper around `ciphersettle_core::Nullifier` so this crate can
/// implement the foreign `Storable` trait on it (Rust's orphan rule forbids
/// implementing a foreign trait on a foreign type directly). Stored as its
/// raw 32 bytes rather than through candid encoding, since it's a fixed-size
/// opaque hash with no benefit from the extra framing.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct NullifierKey([u8; 32]);

impl From<Nullifier> for NullifierKey {
    fn from(n: Nullifier) -> Self {
        NullifierKey(n.0)
    }
}

impl Storable for NullifierKey {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(self.0.to_vec())
    }
    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes.as_ref());
        NullifierKey(arr)
    }
    const BOUND: Bound = Bound::Bounded {
        max_size: 32,
        is_fixed_size: true,
    };
}

// ---------- Stable storage ----------

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

    // nullifier -> 1  (a set: presence = an invoice with these identifying
    // fields is already on file). The nullifier itself is derived by this
    // canister from caller-declared fields -- see register_invoice -- never
    // accepted directly from the caller.
    static NULLIFIERS: RefCell<StableBTreeMap<NullifierKey, u8, Memory>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(0))))
    );

    // invoice_id -> InvoiceRecord
    static INVOICES: RefCell<StableBTreeMap<String, InvoiceRecord, Memory>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(1))))
    );

    // regulator_principal -> 1 (a set of principals allowed to trigger disclosure)
    static REGULATORS: RefCell<StableBTreeMap<Principal, u8, Memory>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(2))))
    );

    // append-only audit log, keyed by incrementing event id
    static AUDIT_LOG: RefCell<StableBTreeMap<u64, AuditEvent, Memory>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(3))))
    );

    static NEXT_EVENT_ID: RefCell<u64> = RefCell::new(0);

    // canister admin; can be rotated via transfer_admin
    static ADMIN: RefCell<StableCell<PrincipalWrapper, Memory>> = RefCell::new(
        StableCell::init(MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(4))), PrincipalWrapper::default())
            .expect("failed to init admin cell")
    );

    // caller principal -> recent derive_invoice_key call timestamps, for rate limiting
    static DERIVE_CALL_TIMES: RefCell<StableBTreeMap<Principal, CallTimes, Memory>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(5))))
    );

    // caller principal -> recent register_invoice call timestamps, for rate
    // limiting (round 3 review, §1) -- a separate map from DERIVE_CALL_TIMES
    // since the two endpoints have very different legitimate call volumes
    // and are guarded by different policies.
    static REGISTER_CALL_TIMES: RefCell<StableBTreeMap<Principal, CallTimes, Memory>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(6))))
    );
}

fn log_event(invoice_id: &str, actor: Principal, action: &str) {
    let id = NEXT_EVENT_ID.with(|c| {
        let mut c = c.borrow_mut();
        let id = *c;
        *c += 1;
        id
    });
    let event = AuditEvent {
        id,
        invoice_id: invoice_id.to_string(),
        actor,
        action: action.to_string(),
        timestamp: ic_cdk::api::time(),
    };
    AUDIT_LOG.with(|log| log.borrow_mut().insert(id, event));
}

fn vetkd_key_id() -> VetKDKeyId {
    // "dfx_test_key" works on local replica; swap for the mainnet key name at deploy time.
    VetKDKeyId {
        curve: VetKDCurve::Bls12_381_G2,
        name: "dfx_test_key".to_string(),
    }
}

// ---------- Lifecycle ----------

#[ic_cdk::init]
fn init() {
    let caller = ic_cdk::api::msg_caller();
    ADMIN.with(|a| {
        a.borrow_mut()
            .set(PrincipalWrapper(Some(caller)))
            .expect("failed to set admin");
    });
}

fn is_admin(p: Principal) -> bool {
    ADMIN.with(|a| a.borrow().get().0 == Some(p))
}

fn is_regulator(p: Principal) -> bool {
    REGULATORS.with(|r| r.borrow().contains_key(&p))
}

// ---------- Admin: register / revoke regulator principals, rotate admin ----------

#[ic_cdk::update]
fn register_regulator(regulator: Principal) -> Result<(), String> {
    let caller = ic_cdk::api::msg_caller();
    if !is_admin(caller) {
        return Err("only the canister admin can register regulators".to_string());
    }
    REGULATORS.with(|r| r.borrow_mut().insert(regulator, 1));
    log_event("*", caller, "regulator_registered");
    Ok(())
}

/// Admin-only. Pulls a previously registered regulator's standing disclosure
/// access, e.g. once an audit window has closed. Errors (rather than
/// silently no-op'ing) if the principal wasn't registered, so a caller can't
/// mistake a typo'd principal for a successful revoke.
#[ic_cdk::update]
fn revoke_regulator(regulator: Principal) -> Result<(), String> {
    let caller = ic_cdk::api::msg_caller();
    if !is_admin(caller) {
        return Err("only the canister admin can revoke regulators".to_string());
    }
    let was_present = REGULATORS.with(|r| r.borrow_mut().remove(&regulator).is_some());
    if !was_present {
        return Err("that principal is not a registered regulator".to_string());
    }
    log_event("*", caller, "regulator_revoked");
    Ok(())
}

/// Admin-only rotation of the admin identity itself. Without this, a lost or
/// compromised admin key would be a permanent lockout on every admin-gated
/// operation, including this one. Logged like any other privileged action.
#[ic_cdk::update]
fn transfer_admin(new_admin: Principal) -> Result<(), String> {
    let caller = ic_cdk::api::msg_caller();
    if !is_admin(caller) {
        return Err("only the current admin can transfer adminship".to_string());
    }
    ADMIN.with(|a| {
        a.borrow_mut()
            .set(PrincipalWrapper(Some(new_admin)))
            .expect("failed to set admin");
    });
    log_event("*", caller, "admin_rotated");
    Ok(())
}

// ---------- Core flow: declare identifying fields -> canister derives nullifier -> encrypted store ----------

/// Registers an invoice. The nullifier is *derived by this canister* from
/// the declared identifying fields (see `ciphersettle_core::nullifier` for
/// the full rationale) -- it is never accepted directly from the caller,
/// because a caller-chosen nullifier can always be "fresh" and makes the
/// double-financing check meaningless. The declared fields themselves are
/// never persisted; only the resulting 32-byte nullifier is stored, so this
/// doesn't add a new metadata leak on top of the existing design.
///
/// Returns the derived nullifier as a hex string, purely as a receipt the
/// caller can keep -- it reveals nothing about the underlying fields.
///
/// **Rejection reasons are deliberately collapsed into one generic error
/// past the point of validation** (round 3 review, §1). This function has
/// no caller-identity gate -- anyone, including an anonymous principal, may
/// call it -- and the nullifier is a secret-free hash of guessable fields
/// (issuer identifier, invoice number, currency, amount, due date). Earlier
/// versions returned a distinct, specific error when the nullifier was
/// already claimed ("...is already registered -- this is the
/// double-financing check") versus other failures. That distinction turned
/// this endpoint into an unauthenticated oracle: anyone could submit a
/// guessed or partially-known set of fields and learn, from the error text
/// alone, whether that exact invoice already exists -- without ever holding
/// a decryption key, being a registered regulator, or leaving a trace the
/// real issuer would see (a failed guess was never logged at all). Field
/// *validation* errors (bad currency-code shape, empty required field,
/// oversized payload) are still specific, since those reveal only
/// information about the fields the caller themselves just supplied, not
/// about any other invoice's existence. The two checks that *do* depend on
/// existing, possibly-someone-else's state -- "this nullifier is already
/// claimed" and "this invoice_id is already taken" -- now return the same
/// generic message. The specific reason is still written to the audit log
/// (admin-only for unscoped reads; see `get_audit_log`), so a legitimate
/// operator can still diagnose a rejected submission; an anonymous prober
/// learns only that registration did not succeed, not why.
#[ic_cdk::update]
fn register_invoice(
    invoice_id: String,
    issuer_identifier: String,
    invoice_number: String,
    currency_code: String,
    amount_minor_units: u64,
    due_date_unix: u64,
    ciphertext: Vec<u8>,
) -> Result<String, String> {
    let caller = ic_cdk::api::msg_caller();

    // Round 3 review, §1: register_invoice was the only update call in this
    // canister with no rate limit. On its own this doesn't close the
    // oracle above -- it raises the cost of a bulk guessing attack, which
    // is worth doing regardless of the error-message fix.
    record_and_check_register_rate_limit(caller)?;

    ciphersettle_core::check_payload_size(ciphertext.len(), MAX_CIPHERTEXT_BYTES)?;
    ciphersettle_core::check_payload_size(invoice_id.len(), MAX_INVOICE_ID_BYTES)?;

    let fingerprint = InvoiceFingerprint {
        issuer_identifier,
        invoice_number,
        currency_code,
        amount_minor_units,
        due_date_unix,
    };
    let nullifier = ciphersettle_core::compute_nullifier(&fingerprint)
        .map_err(|e| format!("invalid invoice fingerprint: {e:?}"))?;
    let key = NullifierKey::from(nullifier);

    let already_claimed = NULLIFIERS.with(|n| n.borrow().contains_key(&key));
    let invoice_id_taken = INVOICES.with(|i| i.borrow().contains_key(&invoice_id));

    if already_claimed || invoice_id_taken {
        // Deliberately identical wording for both cases -- see the doc
        // comment above. The specific reason is logged under a reserved
        // "*" invoice_id (the same convention used for admin actions like
        // "regulator_registered" that aren't scoped to one invoice),
        // visible only via the admin-only unscoped audit-log read.
        let reason = if already_claimed {
            "registration_rejected_duplicate_fingerprint"
        } else {
            "registration_rejected_duplicate_invoice_id"
        };
        log_event("*", caller, reason);
        return Err("registration was not completed".to_string());
    }

    NULLIFIERS.with(|n| n.borrow_mut().insert(key, 1));
    INVOICES.with(|i| {
        i.borrow_mut().insert(
            invoice_id.clone(),
            InvoiceRecord {
                issuer: caller,
                bank: None,
                ciphertext,
                created_at: ic_cdk::api::time(),
                status: InvoiceStatus::Active,
                settled_at: None,
                ciphertext_pruned: false,
            },
        )
    });
    log_event(&invoice_id, caller, "invoice_registered");
    Ok(nullifier.to_hex())
}

#[ic_cdk::update]
fn grant_settlement_access(invoice_id: String, bank: Principal) -> Result<(), String> {
    let caller = ic_cdk::api::msg_caller();
    INVOICES.with(|i| {
        let mut i = i.borrow_mut();
        let mut record = i
            .get(&invoice_id)
            .ok_or_else(|| "invoice not found".to_string())?;
        if record.issuer != caller {
            return Err("only the issuer can grant settlement access".to_string());
        }
        record.bank = Some(bank);
        i.insert(invoice_id.clone(), record);
        Ok(())
    })?;
    log_event(&invoice_id, caller, "settlement_access_granted");
    Ok(())
}

/// Issuer-only. Pulls a previously granted counterparty's access -- e.g. a
/// financing arrangement fell through, or the bank's access needs to be
/// pulled before the invoice reaches a terminal state. Errors if nothing was
/// granted, so "revoked" always means something actually changed.
#[ic_cdk::update]
fn revoke_settlement_access(invoice_id: String) -> Result<(), String> {
    let caller = ic_cdk::api::msg_caller();
    INVOICES.with(|i| {
        let mut i = i.borrow_mut();
        let mut record = i
            .get(&invoice_id)
            .ok_or_else(|| "invoice not found".to_string())?;
        if record.issuer != caller {
            return Err("only the issuer can revoke settlement access".to_string());
        }
        if record.bank.take().is_none() {
            return Err("no settlement access is currently granted for this invoice".to_string());
        }
        i.insert(invoice_id.clone(), record);
        Ok(())
    })?;
    log_event(&invoice_id, caller, "settlement_access_revoked");
    Ok(())
}

/// Issuer or the currently-granted bank may mark an invoice settled. Actual
/// fund movement happens off-canister (see README: "don't touch the money");
/// this just records the terminal state so ciphertext-pruning eligibility
/// can be evaluated later.
#[ic_cdk::update]
fn mark_settled(invoice_id: String) -> Result<(), String> {
    let caller = ic_cdk::api::msg_caller();
    let now = ic_cdk::api::time();
    INVOICES.with(|i| {
        let mut i = i.borrow_mut();
        let mut record = i
            .get(&invoice_id)
            .ok_or_else(|| "invoice not found".to_string())?;
        let is_participant = record.issuer == caller || record.bank == Some(caller);
        if !is_participant {
            return Err("only the issuer or the granted bank can mark an invoice settled".to_string());
        }
        if record.status == InvoiceStatus::Settled {
            return Err("invoice is already settled".to_string());
        }
        record.status = InvoiceStatus::Settled;
        record.settled_at = Some(now);
        i.insert(invoice_id.clone(), record);
        Ok(())
    })?;
    log_event(&invoice_id, caller, "invoice_settled");
    Ok(())
}

/// Drops the ciphertext blob for an invoice that is Settled and past the
/// retention window, freeing paid stable-memory storage. The invoice record
/// and its full audit trail are kept permanently -- only the payload bytes
/// are cleared -- so `get_audit_log` remains a complete history even after
/// pruning. Callable by anyone (it's a storage-hygiene operation gated
/// entirely by the eligibility check, not by identity), but errors if the
/// invoice isn't actually eligible yet.
#[ic_cdk::update]
fn prune_ciphertext(invoice_id: String) -> Result<(), String> {
    let caller = ic_cdk::api::msg_caller();
    let now = ic_cdk::api::time();
    INVOICES.with(|i| {
        let mut i = i.borrow_mut();
        let mut record = i
            .get(&invoice_id)
            .ok_or_else(|| "invoice not found".to_string())?;
        if record.ciphertext_pruned {
            return Err("ciphertext already pruned for this invoice".to_string());
        }
        let eligible = record.status == InvoiceStatus::Settled
            && record
                .settled_at
                .map(|settled_at| now.saturating_sub(settled_at) >= CIPHERTEXT_RETENTION_NANOS)
                .unwrap_or(false);
        if !eligible {
            return Err(
                "invoice is not yet eligible for pruning (must be settled and past the retention window)"
                    .to_string(),
            );
        }
        record.ciphertext = Vec::new();
        record.ciphertext_pruned = true;
        i.insert(invoice_id.clone(), record);
        Ok(())
    })?;
    log_event(&invoice_id, caller, "ciphertext_pruned");
    Ok(())
}

// ---------- Confidential retrieval (ciphertext only; decryption happens client-side) ----------

/// Deliberately an **update** call, not a query. IC query calls are answered
/// by a single replica without going through consensus -- a faulty or
/// malicious replica could ignore the access-control check below and hand
/// ciphertext to an unauthorized caller, and neither the caller nor the rest
/// of the subnet would detect it. Routing this access-controlled read
/// through an update call means it goes through full replicated consensus
/// instead. (The alternative is certified variables / certified queries,
/// which would restore query-call latency at the cost of implementing a
/// certified Merkle-tree response -- a reasonable future optimization, not
/// done here.)
///
/// Deliberately **not** admin-accessible: the admin role has no current
/// function that needs raw ciphertext bytes (it operates on metadata --
/// registering regulators, pruning, rotation), so granting it anyway would
/// be an unnecessary widening of what a compromised or careless admin key
/// could read, even though the bytes are encrypted and useless without a
/// separately-gated `derive_invoice_key` call. Every successful read is
/// logged as `ciphertext_accessed` -- fetching ciphertext previously left no
/// audit trail at all, which was an asymmetry with `derive_invoice_key`
/// (which has always been logged): a system that claims "every access is
/// logged" should log this too, even though the fetched bytes alone reveal
/// nothing without the derived key.
#[ic_cdk::update]
fn get_encrypted_invoice(invoice_id: String) -> Result<Vec<u8>, String> {
    let caller = ic_cdk::api::msg_caller();
    let ciphertext = INVOICES.with(|i| {
        let record = i
            .borrow()
            .get(&invoice_id)
            .ok_or_else(|| "invoice not found".to_string())?;
        let allowed = record.issuer == caller || record.bank == Some(caller) || is_regulator(caller);
        if !allowed {
            return Err("not authorized to view this invoice".to_string());
        }
        if record.ciphertext_pruned {
            return Err("ciphertext has been pruned for this invoice (past settlement retention window)".to_string());
        }
        Ok(record.ciphertext)
    })?;
    log_event(&invoice_id, caller, "ciphertext_accessed");
    Ok(ciphertext)
}

// ---------- vetKD: key derivation gated by role + rate limit, with disclosure logging ----------

#[ic_cdk::update]
async fn get_vetkd_public_key() -> Vec<u8> {
    let request = VetKDPublicKeyArgs {
        canister_id: None,
        context: DOMAIN_SEPARATOR.to_vec(),
        key_id: vetkd_key_id(),
    };
    let reply = vetkd_public_key(&request)
        .await
        .expect("failed to fetch vetKD public key");
    reply.public_key
}

/// Shared rate-limit bookkeeping against an already-borrowed stable map:
/// checks `caller`'s recent call history against `policy`, then records
/// this call's timestamp and prunes anything outside the window while
/// we're at it. Factored out (round 3 review, §1) so `derive_invoice_key`
/// and `register_invoice` share one tested implementation instead of
/// duplicating the same window-trim-and-record logic against two different
/// stable maps. Takes the map already borrowed (rather than the
/// `thread_local!` key itself) because `DERIVE_CALL_TIMES` and
/// `REGISTER_CALL_TIMES` are distinct `thread_local!` statics and each
/// caller enters via its own `.with(...)`.
///
/// Note this bounds *storage growth per already-tracked caller* (old
/// timestamps get trimmed off, not accumulated forever) but doesn't stop an
/// attacker from creating many distinct principals to bypass a per-identity
/// limit -- that's a structural limit of any per-principal rate limit on a
/// system where identities are cheap to create, not something this
/// function can fix (see README's "known gaps").
fn check_and_record_rate_limit(
    times_map: &mut StableBTreeMap<Principal, CallTimes, Memory>,
    policy: &ciphersettle_core::RateLimitPolicy,
    caller: Principal,
) -> Result<(), ()> {
    let now = ic_cdk::api::time();
    let mut times = times_map.get(&caller).unwrap_or_default();

    ciphersettle_core::check_rate_limit(policy, &times.0, now).map_err(|_| ())?;

    let window_start = now.saturating_sub(policy.window_nanos);
    times.0.retain(|&t| t >= window_start);
    times.0.push(now);
    times_map.insert(caller, times);
    Ok(())
}

fn record_and_check_rate_limit(caller: Principal) -> Result<(), String> {
    DERIVE_CALL_TIMES.with(|m| check_and_record_rate_limit(&mut m.borrow_mut(), &DERIVE_KEY_RATE_LIMIT, caller))
        .map_err(|_| "rate limit exceeded for key derivation; please wait before retrying".to_string())
}

/// Round 3 review, §1: register_invoice was previously the only update call
/// in this canister with no rate limit at all. This alone doesn't close the
/// membership-oracle finding (see the error-message change in
/// `register_invoice` for that) -- it raises the cost of a bulk
/// field-guessing attack, which is worth doing regardless.
fn record_and_check_register_rate_limit(caller: Principal) -> Result<(), String> {
    REGISTER_CALL_TIMES.with(|m| check_and_record_rate_limit(&mut m.borrow_mut(), &REGISTER_RATE_LIMIT, caller))
        .map_err(|_| "rate limit exceeded for invoice registration; please wait before retrying".to_string())
}

/// Derives a decryption key for `invoice_id` via vetKD, gated to the
/// issuer, the currently-granted bank, or a registered regulator.
///
/// **Important limitation, made explicit here (round 3 review, §3):**
/// `revoke_settlement_access` (and `mark_settled`/`prune_ciphertext`, which
/// don't touch keys at all) only prevent *future* calls to this function.
/// They cannot and do not invalidate a key some party already derived and
/// decrypted client-side before revocation. The key returned here is
/// derived from a fixed `(context, invoice_id)` pair with no generation or
/// epoch counter, so every authorized caller who has ever derived it
/// receives the *same* underlying key (the correct behavior for vetKD's
/// identity-based derivation model -- not a bug), and nothing in this
/// canister rotates that key on revocation. A bank whose access was pulled
/// yesterday can still decrypt any ciphertext for this invoice it fetched
/// (or cached) before revocation, indefinitely, even after
/// `prune_ciphertext` deletes the on-chain copy. This is a structural
/// property of granting symmetric decryption capability at all, not
/// something a canister-side check can close -- true revocation would
/// require mixing a generation counter into the vetKD `input` and
/// re-encrypting the stored ciphertext under a freshly derived key on
/// every meaningful revocation, which is real client-side work this
/// repository doesn't do. Treat "revoke settlement access" as "stop this
/// party from deriving the key *again* from now on," not as "this party
/// can no longer read this invoice."
#[ic_cdk::update]
async fn derive_invoice_key(
    invoice_id: String,
    transport_public_key: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let caller = ic_cdk::api::msg_caller();

    ciphersettle_core::check_transport_key_length(
        transport_public_key.len(),
        MIN_TRANSPORT_KEY_BYTES,
        MAX_TRANSPORT_KEY_BYTES,
    )?;
    record_and_check_rate_limit(caller)?;

    let record = INVOICES.with(|i| i.borrow().get(&invoice_id)).ok_or("invoice not found".to_string())?;

    // Round 3 review, §4: a direct contains_key lookup instead of
    // collecting the entire regulator set into a Vec on every call -- this
    // was previously a full linear scan regardless of invoice, on the
    // canister's most frequently-hit access-gated endpoint.
    let role = ciphersettle_core::resolve_access(
        &caller.to_text(),
        &record.issuer.to_text(),
        &record.bank.map(|b| b.to_text()),
        is_regulator(caller),
    )
    .map_err(|_| "not authorized to derive a decryption key for this invoice".to_string())?;

    // Selective disclosure: resolve_access always labels regulator access as
    // such, even if the same principal also happens to be the issuer -- see
    // ciphersettle_core's tests for why that priority order is enforced, not just
    // asserted here.
    log_event(&invoice_id, caller, ciphersettle_core::audit_action_for(&role));

    let request = VetKDDeriveKeyArgs {
        input: invoice_id.as_bytes().to_vec(),
        context: DOMAIN_SEPARATOR.to_vec(),
        transport_public_key,
        key_id: vetkd_key_id(),
    };
    let reply = vetkd_derive_key(&request)
        .await
        .map_err(|e| format!("vetkd_derive_key failed: {e:?}"))?;
    Ok(reply.encrypted_key)
}

// ---------- Audit log: metadata only, never ciphertext or plaintext -- and access-gated ----------

/// Deliberately an **update** call, not a query, for the same reason as
/// `get_encrypted_invoice` above: an uncertified query's response can't be
/// trusted not to have been served (or tampered with) by a single faulty
/// replica, which matters even more here since this log's entire purpose is
/// to be a trustworthy compliance/evidentiary record.
///
/// Also deliberately **access-gated**, which the original version of this
/// canister was not: an unauthenticated global broadcast of "who granted
/// access to whom, and exactly when a regulator investigated which
/// invoice" is a real metadata leak, even though the invoice *content*
/// stays encrypted. Per invoice, the admin, that invoice's issuer, its
/// currently-granted bank, or any registered regulator may read it.
/// Unscoped (`invoice_id = None`) reads -- which would reveal the entire
/// cross-invoice relationship graph at once -- are admin-only.
///
/// **Paginated** (round 3 review, §4): `offset`/`limit` default to `0` and
/// `AUDIT_LOG_MAX_PAGE` respectively, and `limit` is always clamped to
/// `AUDIT_LOG_MAX_PAGE` regardless of what's requested. An unscoped,
/// unpaginated read of a long-lived canister's full history will
/// eventually exceed the IC's practical response-size limit and simply
/// fail outright; capping every page bounds response payload size (it does
/// *not* reduce the O(n) cost of walking past a large `offset` in the
/// underlying `StableBTreeMap` -- that's a separate, unaddressed cost, not
/// claimed to be fixed here).
#[ic_cdk::update]
fn get_audit_log(
    invoice_id: Option<String>,
    offset: Option<u64>,
    limit: Option<u64>,
) -> Result<Vec<AuditEvent>, String> {
    let caller = ic_cdk::api::msg_caller();
    // Round 4 review: IC canisters compile to wasm32-unknown-unknown, where
    // `usize` is 32 bits -- a plain `as usize` on the caller-supplied `u64`
    // offset would silently wrap for any offset >= 2^32 instead of erroring,
    // returning a page computed from the wrapped-around (wrong) offset
    // rather than "there's nothing this far in." `try_from` turns an
    // out-of-range offset into `usize::MAX`, which `Iterator::skip` treats
    // as "skip past everything" -- an empty result, which is what a caller
    // asking this far past the log's actual length should get. `limit` needs
    // no equivalent guard: it's clamped to `AUDIT_LOG_MAX_PAGE` (500) in u64
    // space first, and 500 fits in `usize` on every platform Rust targets.
    let offset = usize::try_from(offset.unwrap_or(0)).unwrap_or(usize::MAX);
    let limit = limit.unwrap_or(AUDIT_LOG_MAX_PAGE).min(AUDIT_LOG_MAX_PAGE) as usize;

    let collect = |scope: Option<&String>| -> Vec<AuditEvent> {
        AUDIT_LOG.with(|log| {
            log.borrow()
                .iter()
                .filter(|(_, e)| match scope {
                    Some(id) => &e.invoice_id == id,
                    None => true,
                })
                .map(|(_, e)| e)
                .skip(offset)
                .take(limit)
                .collect()
        })
    };

    if is_admin(caller) {
        return Ok(collect(invoice_id.as_ref()));
    }

    match &invoice_id {
        None => Err(
            "only the admin can read the unscoped audit log; request a specific invoice_id instead"
                .to_string(),
        ),
        Some(id) => {
            let record = INVOICES
                .with(|i| i.borrow().get(id))
                .ok_or_else(|| "invoice not found".to_string())?;
            // Round 3 review, §4: direct lookup instead of materializing
            // the full regulator set for every audit-log read.
            ciphersettle_core::resolve_access(
                &caller.to_text(),
                &record.issuer.to_text(),
                &record.bank.map(|b| b.to_text()),
                is_regulator(caller),
            )
            .map_err(|_| "not authorized to view the audit log for this invoice".to_string())?;
            Ok(collect(Some(id)))
        }
    }
}

// ---------- Candid interface verification (round 4 review) ----------
//
// Every prior round compared ciphersettle_backend.did against the Rust
// function signatures by hand, because the crate couldn't be compiled in
// this sandbox at all until round 4. Now that it compiles, this generates
// the *real* interface from the `#[ic_cdk::update]` signatures the compiler
// actually sees (each auto-registers with `candid::export_service!` via
// `#[candid_method]`) and cross-checks its method set against the
// checked-in .did file -- see the doc comment on the test module below for
// why this checks method names rather than full type equality.
candid::export_service!();

#[cfg(test)]
mod candid_interface_tests {
    /// Prints the *real* interface the compiler generates from every
    /// `#[ic_cdk::update]` signature in this file (via `candid::export_service!`,
    /// which each `#[update]` auto-registers with through `#[candid_method]`).
    /// Run with `cargo test -p ciphersettle_backend candid_interface -- --nocapture`
    /// to see it. This intentionally does its own diff against the checked-in
    /// `.did` file rather than depending on `candid_parser`'s `service_equal`:
    /// `candid_parser` pulls in a lalrpop/logos-based grammar toolchain whose
    /// own transitive deps (indexmap -> hashbrown) resolve to versions
    /// requiring edition2024 in this sandbox, the same wall documented in
    /// the `[dependencies]` pin block above -- not worth widening that pin
    /// set just for a dev-only check. Comparing method names extracted by a
    /// simple regex is a strictly weaker check than full Candid type
    /// equality (it won't catch a parameter reordered within one method's
    /// signature, for instance) but reliably catches the failure mode that
    /// actually matters most in practice: a method added, removed, or
    /// renamed in the Rust source without updating the `.did` file.
    #[test]
    fn did_file_declares_the_same_methods_the_compiler_generates() {
        let generated = super::__export_service();
        println!("--- interface generated from #[ic_cdk::update] signatures ---");
        println!("{generated}");

        let did_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("ciphersettle_backend.did");
        let checked_in = std::fs::read_to_string(&did_path)
            .unwrap_or_else(|e| panic!("couldn't read {}: {e}", did_path.display()));

        let method_name_re = regex_lite_extract_method_names(&generated);
        let checked_in_names = regex_lite_extract_method_names(&checked_in);

        let missing_from_did: Vec<_> = method_name_re
            .iter()
            .filter(|m| !checked_in_names.contains(*m))
            .collect();
        let extra_in_did: Vec<_> = checked_in_names
            .iter()
            .filter(|m| !method_name_re.contains(*m))
            .collect();

        assert!(
            missing_from_did.is_empty() && extra_in_did.is_empty(),
            "ciphersettle_backend.did's method set has drifted from the compiler-generated \
             interface.\nIn code but missing from .did: {missing_from_did:?}\n\
             In .did but not in code: {extra_in_did:?}\n\n\
             Full generated interface:\n{generated}"
        );
    }

    /// Extracts service method names from Candid service text without
    /// pulling in a real parser -- deliberately simple, see the doc comment
    /// above for why this is an acceptable trade-off here. Handles both
    /// forms Candid uses for a method name: quoted (`"name" : (...)`, what
    /// this project's hand-written .did uses throughout) and bare
    /// (`name : (...)`, what `candid::export_service!`'s pretty-printer
    /// emits for any name that's already a valid identifier -- which is
    /// every method in this service). An earlier version of this test only
    /// matched the quoted form and consequently matched *zero* names in the
    /// generated interface, reporting every real method as spuriously
    /// missing -- caught only by actually running the test and reading the
    /// mismatch list against the printed interface it also emits, exactly
    /// the kind of self-check this test exists to make possible.
    fn regex_lite_extract_method_names(candid_text: &str) -> std::collections::BTreeSet<String> {
        candid_text
            .lines()
            .filter_map(|line| {
                let line = line.trim();
                let (name_part, rest) = if let Some(after_quote) = line.strip_prefix('"') {
                    let end = after_quote.find('"')?;
                    (&after_quote[..end], &after_quote[end + 1..])
                } else {
                    let end = line.find(" : (")?;
                    (&line[..end], &line[end..])
                };
                let is_identifier = !name_part.is_empty()
                    && name_part
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '_')
                    && !name_part.chars().next().unwrap().is_ascii_digit();
                // Excludes the `service : () -> { ... }` prologue line
                // itself, which otherwise matches the same " : (" pattern
                // as a real method entry -- caught the same way as the
                // quoting bug above, by actually running this and reading
                // the (surprising) mismatch list rather than trusting the
                // regex on inspection alone.
                let looks_like_method = rest.trim_start().starts_with(':') && name_part != "service";
                (is_identifier && looks_like_method).then(|| name_part.to_string())
            })
            .collect()
    }
}
