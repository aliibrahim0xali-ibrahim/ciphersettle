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
    action: String, // "invoice_registered" | "settlement_access_granted" | "settlement_access_revoked" | "invoice_settled" | "ciphertext_pruned" | "key_derived_bank" | "disclosure_request" | "regulator_registered" | "regulator_revoked" | "admin_rotated"
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
    ciphersettle_core::check_nullifier(already_claimed).map_err(|_| {
        "an invoice with these identifying fields (issuer, invoice number, currency, amount, \
         due date) is already registered -- this is the double-financing check"
            .to_string()
    })?;
    if INVOICES.with(|i| i.borrow().contains_key(&invoice_id)) {
        return Err("invoice_id already exists".to_string());
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
        Ok(record.ciphertext.clone())
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

/// Records this call's timestamp against `caller` and prunes anything
/// outside the rate-limit window while we're at it. If trimming empties a
/// caller's entry entirely, the entry is removed rather than left as an
/// empty vec, so the map doesn't grow one permanent (if empty) row per
/// distinct caller forever -- this bounds *storage* growth; it doesn't stop
/// an attacker from creating many distinct principals to bypass the
/// per-identity cycle-spend limit itself (see README's "known gaps").
fn record_and_check_rate_limit(caller: Principal) -> Result<(), String> {
    let now = ic_cdk::api::time();
    DERIVE_CALL_TIMES.with(|m| {
        let mut m = m.borrow_mut();
        let mut times = m.get(&caller).unwrap_or_default();

        ciphersettle_core::check_rate_limit(&DERIVE_KEY_RATE_LIMIT, &times.0, now)
            .map_err(|_| "rate limit exceeded for key derivation; please wait before retrying".to_string())?;

        let window_start = now.saturating_sub(DERIVE_KEY_RATE_LIMIT.window_nanos);
        times.0.retain(|&t| t >= window_start);
        times.0.push(now);
        m.insert(caller, times);
        Ok(())
    })
}

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

    let registered_regulators: Vec<String> = REGULATORS.with(|r| {
        r.borrow().iter().map(|(p, _)| p.to_text()).collect()
    });
    let role = ciphersettle_core::resolve_access(
        &caller.to_text(),
        &record.issuer.to_text(),
        &record.bank.map(|b| b.to_text()),
        &registered_regulators,
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
#[ic_cdk::update]
fn get_audit_log(invoice_id: Option<String>) -> Result<Vec<AuditEvent>, String> {
    let caller = ic_cdk::api::msg_caller();

    let collect = |scope: Option<&String>| -> Vec<AuditEvent> {
        AUDIT_LOG.with(|log| {
            log.borrow()
                .iter()
                .filter(|(_, e)| match scope {
                    Some(id) => &e.invoice_id == id,
                    None => true,
                })
                .map(|(_, e)| e)
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
            let registered_regulators: Vec<String> =
                REGULATORS.with(|r| r.borrow().iter().map(|(p, _)| p.to_text()).collect());
            ciphersettle_core::resolve_access(
                &caller.to_text(),
                &record.issuer.to_text(),
                &record.bank.map(|b| b.to_text()),
                &registered_regulators,
            )
            .map_err(|_| "not authorized to view the audit log for this invoice".to_string())?;
            Ok(collect(Some(id)))
        }
    }
}
