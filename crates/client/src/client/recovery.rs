//! Account recovery (recovery code, organization recovery), emergency
//! access and adding a device by code.
//!
//! All cryptography is in `passbox_core::{recovery, emergency,
//! device_link}`; these methods add the HTTP calls and the multi-step flows.
//! See `docs/architecture/recovery.md`.

use std::collections::{BTreeMap, BTreeSet};

use passbox_core::device_link::{
    CliLoginApproval, CliLoginRequest, DeviceLinkOffer, DeviceLinkRequest,
};
use passbox_core::emergency::EmergencyGrantInfo;
use passbox_core::kdf::{self, KdfParams, MasterKeys};
use passbox_core::keyring::{AccountKeysUpload, Keyring};
use passbox_core::opaque::{ClientLoginFlow, ClientRegistrationFlow};
use passbox_core::recovery::code::{RecoveryCode, RecoveryKeys};
use passbox_core::recovery::org::{
    ApprovedRecovery, OrgRecoveryInfo, OrgRecoveryRecord, RecoveryRequestKey,
    RecoveryRequestRecord, request_code,
};
use passbox_core::secret_key::SecretKey;
use passbox_core::{encoding, id};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use super::{Cache, Client, Session, derive, now_ms};
use crate::model::{DeviceAccount, Item, ItemData};
use crate::store::{ACCOUNT_KEY, CACHE_KEY, DEVICE_TOKEN_KEY};
use crate::{Error, Result};

/// Where a pending organization recovery request is kept on the device.
pub const ORG_RECOVERY_KEY: &str = "org_recovery";

/// A proven recovery as the server returns it.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RecoveryGrant {
    recovery_token: String,
    account_id: String,
    email: String,
    #[serde(default)]
    two_factor_methods: Option<Vec<String>>,
    #[serde(default)]
    wrapped_account_key: Option<String>,
    #[serde(default)]
    account_keys: Option<AccountKeysUpload>,
}

/// Recovery state kept in memory between the steps.
#[derive(Default)]
pub(crate) struct RecoveryState {
    /// A recovery by code waiting for its second factor.
    code: Option<(RecoveryGrant, RecoveryKeys)>,
    /// A proven recovery: the account key and the token for new credentials.
    ready: Option<(RecoveryGrant, Keyring)>,
    /// Device links opened on this device.
    offers: BTreeMap<String, DeviceLinkOffer>,
    /// The device code this (new) device entered, with the claim token.
    claim: Option<(DeviceLinkRequest, String)>,
    /// A sign-in this device (without a session) asked a browser for, with
    /// the poll token.
    cli_login: Option<(CliLoginRequest, String)>,
}

/// The first step of a recovery by code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeRecoveryStart {
    pub account_id: String,
    pub email: String,
    /// Set when the account uses two-factor sign-in (`totp`, `recovery`):
    /// call [`Client::complete_recovery_two_factor`].
    pub two_factor_methods: Option<Vec<String>>,
}

/// New credentials after a recovery, for the new Emergency Kit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryResult {
    pub account_id: String,
    pub email: String,
    /// The new Secret Key; the old one no longer works.
    pub secret_key: String,
    /// The new recovery code; an old one no longer works.
    pub recovery_code: String,
}

/// An organization recovery request this device sent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingOrgRecovery {
    pub request_id: String,
    pub request_token: String,
    /// The ephemeral private key's seed (Base64url).
    pub seed: String,
    pub email: String,
    #[serde(default)]
    pub org_id: Option<String>,
    /// Read it to the approving admin.
    pub request_code: String,
    pub created_at: i64,
    pub expires_at: i64,
}

/// Recovery options set up for the account.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryStatus {
    /// When the recovery code was created; `None` without one.
    pub recovery_code_created_at: Option<i64>,
    /// Organizations the account escrowed its key with.
    pub org_escrows: Vec<String>,
}

/// An organization's recovery setup as this account sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrgRecovery {
    pub org_id: String,
    /// Set up and verified against the organization's roster.
    pub available: bool,
    /// Why it could not be verified.
    pub problem: Option<String>,
    /// Fingerprint of the recovery key (8 groups of five digits).
    pub fingerprint: Option<String>,
    /// Verified admins who can approve requests.
    pub admins: Vec<String>,
    pub can_approve: bool,
    /// This account opted in.
    pub enrolled: bool,
    /// For admins who hold the key: open requests.
    pub pending_requests: Option<i64>,
}

/// A pending request as an admin sees it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryRequest {
    pub id: String,
    pub org_id: String,
    pub account_id: String,
    pub email: String,
    pub device_name: String,
    pub ip: String,
    pub created_at: i64,
    pub expires_at: i64,
    /// Compare it with the code on the member's screen.
    #[serde(skip)]
    pub request_code: String,
    #[serde(flatten)]
    record: RequestRecordFields,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RequestRecordFields {
    ephemeral_key: String,
    key_version: u32,
    escrow: String,
    escrow_signature: String,
    sealed_key: String,
}

/// An emergency access grant (as grantor or grantee).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EmergencyContact {
    pub id: String,
    pub grantor_id: String,
    pub grantor_email: String,
    pub grantee_id: Option<String>,
    pub grantee_email: String,
    pub wait_days: u32,
    /// `invited`, `accepted` or `confirmed`.
    pub status: String,
    pub vault_ids: Vec<String>,
    pub version: u64,
    #[serde(default)]
    pub grant: Option<String>,
    #[serde(default)]
    pub grant_signature: Option<String>,
    pub requested_at: i64,
    pub approved_at: i64,
    pub denied_at: i64,
    pub accessed_at: i64,
    pub release_at: i64,
    pub released: bool,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct EmergencyContacts {
    /// People this account trusts.
    pub granted: Vec<EmergencyContact>,
    /// People who trust this account.
    pub received: Vec<EmergencyContact>,
}

/// The grantor's vaults, opened through released emergency access.
#[derive(Debug, Clone, PartialEq)]
pub struct EmergencyVaults {
    pub grantor_id: String,
    /// (vault ID, name)
    pub vaults: Vec<(String, String)>,
    pub items: Vec<Item>,
    pub errors: Vec<String>,
}

/// A device link opened on this device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceLinkStart {
    pub id: String,
    /// `XXXX-XXXX-XXXX-XXXX`; show it and put it into a QR code.
    pub code: String,
    pub expires_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceLinkState {
    /// `open`, `claimed` or `approved`.
    pub status: String,
    pub expires_at: i64,
    #[serde(default)]
    pub device_name: Option<String>,
    #[serde(default)]
    pub ip: Option<String>,
    #[serde(default)]
    ephemeral_key: Option<String>,
    #[serde(default)]
    mac: Option<String>,
}

/// What a new device receives from the signed-in one. Never the master password.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkedAccount {
    pub email: String,
    pub account_id: String,
    pub secret_key: String,
}

/// A sign-in request this device registered (see [`Client::start_cli_login`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliLoginStart {
    pub id: String,
    /// Open it in a signed-in browser: the web vault's approval page. The
    /// secret is in the fragment, which is never sent to a server. Show it
    /// only to the user.
    pub url: String,
    pub expires_at: i64,
}

/// The state of a sign-in request, as the requesting device sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliLoginPoll {
    /// Not answered yet.
    Pending,
    /// Approved: the account details (sign in with them and the master
    /// password) and the name of the device that approved.
    Approved {
        account: LinkedAccount,
        approved_by: String,
    },
    /// Denied in the browser.
    Denied,
    /// Expired (10 minutes) or cancelled.
    Expired,
}

/// A sign-in request as the approving (signed-in) device sees it. The
/// device name is covered by the MAC; IP and time come from the server.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CliLoginInfo {
    pub id: String,
    pub device_name: String,
    pub ip: String,
    pub created_at: i64,
    pub expires_at: i64,
    #[serde(default)]
    ephemeral_key: String,
    #[serde(default)]
    mac: String,
}

fn cli_login_expired() -> Error {
    Error::Server {
        status: 403,
        code: "cli_login_expired".into(),
        message: "the sign-in request expired or was already answered; start it again".into(),
    }
}

fn expired() -> Error {
    Error::Server {
        status: 403,
        code: "recovery_expired".into(),
        message: "the recovery expired or was already used; start again".into(),
    }
}

fn invalid_device_code() -> Error {
    Error::Server {
        status: 403,
        code: "device_link_expired".into(),
        message: "the code expired or was already used; show a new code on your other device"
            .into(),
    }
}

fn verify_recovered(keyring: &mut Keyring, grant: &RecoveryGrant) -> Result<()> {
    if let Some(keys) = &grant.account_keys {
        keyring
            .load_account_keys(
                &keys.bundle,
                &keys.bundle_signature,
                &keys.encrypted_private,
            )
            .map_err(|_| {
                Error::InvalidData(
                    "the recovered key could not be verified; nothing was changed".into(),
                )
            })?;
    }
    Ok(())
}

impl Client {
    fn lock_recovery(&self) -> std::sync::MutexGuard<'_, RecoveryState> {
        self.recovery
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn anonymous(&self, method: &str, path: &str, body: Value) -> Result<Value> {
        self.api.request_anonymous(method, path, Some(body))
    }

    fn device_fields(&self) -> (String, String) {
        self.device
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    // --- Recovery code ---------------------------------------------------------------

    /// Recovery options set up on the server.
    pub fn recovery_status(&self) -> Result<RecoveryStatus> {
        let value = self.with_token(|token| {
            self.api
                .request("GET", "/api/v1/account/recovery", token, None)
        })?;
        Ok(RecoveryStatus {
            recovery_code_created_at: value["recoveryCode"]["createdAt"].as_i64(),
            org_escrows: value["orgEscrows"]
                .as_array()
                .map(|list| {
                    list.iter()
                        .filter_map(|e| e["orgId"].as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default(),
        })
    }

    /// Creates a recovery code (replacing an earlier one) and returns it for
    /// the Emergency Kit; it is not stored. `password` is checked on the
    /// device; without a recent login a fresh login follows (which can fail
    /// with [`Error::TwoFactorRequired`]: complete it and call this again).
    pub fn create_recovery_code(&self, password: &str) -> Result<String> {
        let account = self.device_account()?.ok_or(Error::NoAccount)?;
        let current = self.checked_keys(&account, password)?;
        let token = match self.recent_token() {
            Some(token) => token,
            None => self.fresh_token(&account, &current)?,
        };
        let code = RecoveryCode::generate()?;
        let keys = code.keys()?;
        let (flow, request) = ClientRegistrationFlow::start(&*keys.auth_secret)?;
        let response = self.api.request(
            "POST",
            "/api/v1/account/recovery-code/start",
            &token,
            Some(json!({ "registrationRequest": encoding::encode(&request) })),
        )?;
        let upload = flow.finish(&encoding::decode(
            response["registrationResponse"]
                .as_str()
                .unwrap_or_default(),
        )?)?;
        let wrapped = {
            let guard = self.lock_session();
            guard
                .as_ref()
                .ok_or(Error::Locked)?
                .keyring
                .wrap_account_key_for_recovery(&keys.wrap_key)?
        };
        self.api.request(
            "POST",
            "/api/v1/account/recovery-code",
            &token,
            Some(json!({ "registrationUpload": encoding::encode(&upload), "wrappedAccountKey": wrapped })),
        )?;
        Ok(code.to_display_string())
    }

    /// Deletes the recovery code (needs a recent login).
    pub fn remove_recovery_code(&self, password: &str) -> Result<()> {
        let account = self.device_account()?.ok_or(Error::NoAccount)?;
        let current = self.checked_keys(&account, password)?;
        let token = match self.recent_token() {
            Some(token) => token,
            None => self.fresh_token(&account, &current)?,
        };
        self.api
            .request("DELETE", "/api/v1/account/recovery-code", &token, None)?;
        Ok(())
    }

    /// Starts recovering an account with its recovery code (signed out or
    /// locked). Wrong codes fail with [`Error::InvalidCredentials`], malformed
    /// ones with a core `InvalidRecoveryCode` error.
    pub fn start_code_recovery(&self, email: &str, code: &str) -> Result<CodeRecoveryStart> {
        self.cancel_recovery();
        let code = RecoveryCode::parse(code)?;
        let keys = code.keys()?;
        let (flow, request) = ClientLoginFlow::start(&*keys.auth_secret)?;
        let email = email.trim().to_lowercase();
        let start = self.anonymous(
            "POST",
            "/api/v1/recovery/code/start",
            json!({ "email": email, "credentialRequest": encoding::encode(&request) }),
        )?;
        let finish = flow
            .finish(&encoding::decode(
                start["credentialResponse"].as_str().unwrap_or_default(),
            )?)
            .map_err(|_| Error::InvalidCredentials)?;
        let (device_name, client_kind) = self.device_fields();
        let grant: RecoveryGrant = serde_json::from_value(self.anonymous(
            "POST",
            "/api/v1/recovery/code/finish",
            json!({
                "loginId": start["loginId"],
                "credentialFinalization": encoding::encode(&finish.finalization),
                "deviceName": device_name,
                "clientKind": client_kind,
            }),
        )?)?;
        let result = CodeRecoveryStart {
            account_id: grant.account_id.clone(),
            email: grant.email.clone(),
            two_factor_methods: grant.two_factor_methods.clone(),
        };
        if grant.two_factor_methods.is_some() {
            self.lock_recovery().code = Some((grant, keys));
        } else {
            self.open_code_recovery(grant, &keys)?;
        }
        Ok(result)
    }

    /// The second factor of a recovery by code: `totp` (6-digit code) or
    /// `recovery` (two-factor recovery code).
    pub fn complete_recovery_two_factor(&self, method: &str, code: &str) -> Result<()> {
        let (pending, keys) = self.lock_recovery().code.take().ok_or_else(expired)?;
        let response = self.anonymous(
            "POST",
            "/api/v1/recovery/two-factor",
            json!({
                "recoveryToken": pending.recovery_token,
                "method": method,
                "code": code.split_whitespace().collect::<String>(),
            }),
        );
        let grant: RecoveryGrant = match response {
            Ok(value) => serde_json::from_value(value)?,
            Err(e) => {
                // A wrong code can be tried again.
                if matches!(e, Error::InvalidTwoFactorCode) {
                    self.lock_recovery().code = Some((pending, keys));
                }
                return Err(e);
            }
        };
        self.open_code_recovery(grant, &keys)
    }

    fn open_code_recovery(&self, grant: RecoveryGrant, keys: &RecoveryKeys) -> Result<()> {
        let wrapped = grant.wrapped_account_key.clone().ok_or_else(expired)?;
        let mut keyring =
            Keyring::unlock_with_recovery(&keys.wrap_key, &grant.account_id, &wrapped)?;
        verify_recovered(&mut keyring, &grant)?;
        self.lock_recovery().ready = Some((grant, keyring));
        Ok(())
    }

    /// Whether a recovery is ready for [`Client::finish_recovery`].
    pub fn recovery_ready(&self) -> bool {
        self.lock_recovery().ready.is_some()
    }

    /// Drops a recovery in progress.
    pub fn cancel_recovery(&self) {
        let mut state = self.lock_recovery();
        state.code = None;
        state.ready = None;
    }

    /// Sets a new master password for the recovered account: new Secret
    /// Key, new recovery code, every other device signed out; unlocks this
    /// device. Show the result in a new Emergency Kit.
    pub fn finish_recovery(&self, new_password: &str) -> Result<RecoveryResult> {
        let (grant, keyring) = self.lock_recovery().ready.take().ok_or_else(expired)?;
        let secret_key = SecretKey::generate()?;
        let account = DeviceAccount {
            server_url: self.api.base_url().to_owned(),
            email: grant.email.clone(),
            account_id: grant.account_id.clone(),
            secret_key: secret_key.to_display_string(),
            kdf_salt: encoding::encode(&kdf::generate_salt()?),
            kdf_params: KdfParams::DEFAULT,
        };
        let keys: MasterKeys = derive(&account, new_password)?;
        let code = RecoveryCode::generate()?;
        let code_keys = code.keys()?;
        let (flow, request) = ClientRegistrationFlow::start(&*keys.auth_secret)?;
        let (code_flow, code_request) = ClientRegistrationFlow::start(&*code_keys.auth_secret)?;
        let start = self.anonymous(
            "POST",
            "/api/v1/recovery/complete/start",
            json!({
                "recoveryToken": grant.recovery_token,
                "registrationRequest": encoding::encode(&request),
                "recoveryRegistrationRequest": encoding::encode(&code_request),
            }),
        )?;
        let upload = flow.finish(&encoding::decode(
            start["registrationResponse"].as_str().unwrap_or_default(),
        )?)?;
        let code_upload = code_flow.finish(&encoding::decode(
            start["recoveryRegistrationResponse"]
                .as_str()
                .unwrap_or_default(),
        )?)?;
        let encrypted_account_key = keyring.wrap_account_key(&keys.auk)?;
        let session = self.anonymous(
            "POST",
            "/api/v1/recovery/complete/finish",
            json!({
                "recoveryToken": grant.recovery_token,
                "registrationUpload": encoding::encode(&upload),
                "kdfSalt": account.kdf_salt,
                "kdfParams": account.kdf_params,
                "encryptedAccountKey": encrypted_account_key,
                "recoveryCode": {
                    "registrationUpload": encoding::encode(&code_upload),
                    "wrappedAccountKey": keyring.wrap_account_key_for_recovery(&code_keys.wrap_key)?,
                },
            }),
        )?;
        let token = session["token"]
            .as_str()
            .ok_or_else(|| Error::InvalidData("no session after recovery".into()))?
            .to_owned();
        if let Some(device_token) = session["deviceToken"].as_str() {
            self.store.put(DEVICE_TOKEN_KEY, device_token.as_bytes())?;
        }
        self.store.delete(CACHE_KEY)?;
        self.store.delete(ORG_RECOVERY_KEY)?;
        if self.device_account()?.map(|a| a.account_id) != Some(account.account_id.clone()) {
            self.store.delete(crate::store::TRUST_KEY)?;
        }
        self.store
            .put(ACCOUNT_KEY, &serde_json::to_vec(&account)?)?;
        let mut keyring = keyring;
        keyring.set_trust_store(self.trust_store()?);
        *self.lock_session() = Some(Session {
            keyring,
            auk: keys.auk.clone(),
            auth_secret: Zeroizing::new(*keys.auth_secret),
            token: Some(token),
            token_at: now_ms(),
            cache: Cache {
                account_id: account.account_id.clone(),
                encrypted_account_key,
                account_keys: grant.account_keys.clone(),
                ..Cache::default()
            },
            vaults: BTreeMap::new(),
            items: BTreeMap::new(),
            errors: Vec::new(),
        });
        self.sync()?;
        Ok(RecoveryResult {
            account_id: account.account_id,
            email: account.email,
            secret_key: account.secret_key,
            recovery_code: code.to_display_string(),
        })
    }

    // --- Organization recovery ---------------------------------------------------------

    fn org_recovery_state(&self, org_id: &str) -> Result<Value> {
        self.with_token(|token| {
            self.api.request(
                "GET",
                &format!("/api/v1/orgs/{org_id}/recovery"),
                token,
                None,
            )
        })
    }

    fn org_recovery_record(&self, org_id: &str) -> Result<OrgRecoveryRecord> {
        let state = self.org_recovery_state(org_id)?;
        if state["key"].is_null() {
            return Err(Error::NotFound(
                "the organization has not set up recovery".into(),
            ));
        }
        Ok(serde_json::from_value(state["key"].clone())?)
    }

    /// The organization's recovery setup, verified against its roster.
    pub fn org_recovery(&self, org_id: &str) -> Result<OrgRecovery> {
        let state = self.org_recovery_state(org_id)?;
        let key_version = state["key"]["keyVersion"].as_u64();
        let escrow_version = state["escrow"]["keyVersion"].as_u64();
        let mut info = OrgRecovery {
            org_id: org_id.to_owned(),
            available: false,
            problem: None,
            fingerprint: None,
            admins: Vec::new(),
            can_approve: false,
            enrolled: key_version.is_some() && escrow_version == key_version,
            pending_requests: state["pendingRequests"].as_i64(),
        };
        if state["key"].is_null() {
            return Ok(info);
        }
        let record: OrgRecoveryRecord = serde_json::from_value(state["key"].clone())?;
        let guard = self.lock_session();
        let session = guard.as_ref().ok_or(Error::Locked)?;
        match session.keyring.verify_org_recovery(org_id, &record) {
            Ok(OrgRecoveryInfo {
                fingerprint,
                admins,
                can_approve,
                ..
            }) => {
                info.available = true;
                info.fingerprint = Some(fingerprint);
                info.admins = admins;
                info.can_approve = can_approve;
            }
            Err(e) => info.problem = Some(e.to_string()),
        }
        Ok(info)
    }

    /// Sets up recovery for an organization (owners and admins).
    pub fn set_up_org_recovery(&self, org_id: &str) -> Result<()> {
        let state = self.org_recovery_state(org_id)?;
        let version = u32::try_from(state["key"]["keyVersion"].as_u64().unwrap_or(0) + 1)
            .map_err(|_| Error::InvalidData("key version out of range".into()))?;
        let body = self.with_keyring(|k| k.create_org_recovery_key(org_id, version, now_ms()))?;
        self.call(
            "POST",
            &format!("/api/v1/orgs/{org_id}/recovery/keys"),
            Some(serde_json::to_value(&body)?),
        )?;
        Ok(())
    }

    /// Lets another verified admin approve requests (this account must
    /// hold the recovery key).
    pub fn add_recovery_admin(&self, org_id: &str, admin_id: &str) -> Result<()> {
        let record = self.org_recovery_record(org_id)?;
        let body =
            self.with_keyring(|k| k.grant_org_recovery(org_id, &record, admin_id, now_ms()))?;
        self.call(
            "POST",
            &format!("/api/v1/orgs/{org_id}/recovery/grants"),
            Some(serde_json::to_value(&body)?),
        )?;
        Ok(())
    }

    /// Opts in: escrows the account key with the organization.
    pub fn enroll_org_recovery(&self, org_id: &str) -> Result<()> {
        let record = self.org_recovery_record(org_id)?;
        let body = self.with_keyring(|k| k.enroll_org_recovery(org_id, &record, now_ms()))?;
        self.call(
            "PUT",
            &format!("/api/v1/orgs/{org_id}/recovery/escrow"),
            Some(serde_json::to_value(&body)?),
        )?;
        Ok(())
    }

    /// Enrolls in the recovery of every organization whose policy requires
    /// it and that has recovery set up (on by default for new
    /// organizations; members were told when they joined). Guests are never
    /// enrolled. Returns the organizations enrolled now; organizations that
    /// fail (for example while the membership is not confirmed yet) are
    /// skipped and tried again next time.
    pub fn enroll_required_org_recovery(&self) -> Result<Vec<String>> {
        let required = self.effective_policy()?.recovery_enrollment_orgs;
        if required.is_empty() {
            return Ok(Vec::new());
        }
        let enrolled = self.recovery_status()?.org_escrows;
        let mut done = Vec::new();
        for org_id in required.into_iter().filter(|o| !enrolled.contains(o)) {
            match self.enroll_org_recovery(&org_id) {
                Ok(()) => done.push(org_id),
                Err(Error::Locked) => return Err(Error::Locked),
                Err(_) => {}
            }
        }
        Ok(done)
    }

    /// Turns recovery off for the whole organization (owners and admins):
    /// the recovery key, admins' copies and members' escrows are deleted.
    /// Refused while the policy requires recovery (`recovery_required`).
    pub fn turn_off_org_recovery(&self, org_id: &str) -> Result<()> {
        self.call("DELETE", &format!("/api/v1/orgs/{org_id}/recovery"), None)?;
        Ok(())
    }

    /// Opts out.
    pub fn withdraw_org_recovery(&self, org_id: &str) -> Result<()> {
        self.call(
            "DELETE",
            &format!("/api/v1/orgs/{org_id}/recovery/escrow"),
            None,
        )?;
        Ok(())
    }

    /// Open requests (admins who hold the key), with the code to compare.
    pub fn recovery_requests(&self, org_id: &str) -> Result<Vec<RecoveryRequest>> {
        let mut requests: Vec<RecoveryRequest> = serde_json::from_value(self.call(
            "GET",
            &format!("/api/v1/orgs/{org_id}/recovery/requests"),
            None,
        )?)?;
        for request in &mut requests {
            request.request_code = request_code(&encoding::decode(&request.record.ephemeral_key)?);
        }
        Ok(requests)
    }

    /// Approves a request after verifying the member out of band and
    /// comparing the request code. This device briefly holds the member's
    /// account key.
    pub fn approve_recovery_request(&self, org_id: &str, request_id: &str) -> Result<()> {
        let request = self
            .recovery_requests(org_id)?
            .into_iter()
            .find(|r| r.id == request_id)
            .ok_or_else(|| Error::NotFound(request_id.to_owned()))?;
        let record = self.org_recovery_record(org_id)?;
        let core_request = RecoveryRequestRecord {
            id: request.id.clone(),
            org_id: request.org_id.clone(),
            account_id: request.account_id.clone(),
            ephemeral_key: request.record.ephemeral_key.clone(),
            key_version: request.record.key_version,
            escrow: request.record.escrow.clone(),
            escrow_signature: request.record.escrow_signature.clone(),
            sealed_key: request.record.sealed_key.clone(),
        };
        let body =
            self.with_keyring(|k| k.approve_org_recovery(&record, &core_request, now_ms()))?;
        self.call(
            "POST",
            &format!("/api/v1/orgs/{org_id}/recovery/requests/{request_id}/approve"),
            Some(serde_json::to_value(&body)?),
        )?;
        Ok(())
    }

    pub fn deny_recovery_request(&self, org_id: &str, request_id: &str) -> Result<()> {
        self.call(
            "POST",
            &format!("/api/v1/orgs/{org_id}/recovery/requests/{request_id}/deny"),
            Some(json!({})),
        )?;
        Ok(())
    }

    /// Asks the organization to recover the account (signed out or
    /// locked). The request is kept on this device; show its code.
    pub fn request_org_recovery(
        &self,
        email: &str,
        org_id: Option<&str>,
    ) -> Result<PendingOrgRecovery> {
        let key = RecoveryRequestKey::generate()?;
        let email = email.trim().to_lowercase();
        let (device_name, _) = self.device_fields();
        let mut body = json!({
            "email": email,
            "ephemeralKey": encoding::encode(&key.public_key()),
            "deviceName": device_name,
        });
        if let Some(org_id) = org_id {
            body["orgId"] = json!(org_id);
        }
        let created = self.anonymous("POST", "/api/v1/recovery/org/request", body)?;
        let pending = PendingOrgRecovery {
            request_id: created["requestId"].as_str().unwrap_or_default().to_owned(),
            request_token: created["requestToken"]
                .as_str()
                .unwrap_or_default()
                .to_owned(),
            seed: encoding::encode(key.seed()),
            email,
            org_id: org_id.map(str::to_owned),
            request_code: key.request_code(),
            created_at: now_ms(),
            expires_at: created["expiresAt"].as_i64().unwrap_or_default(),
        };
        self.store
            .put(ORG_RECOVERY_KEY, &serde_json::to_vec(&pending)?)?;
        Ok(pending)
    }

    /// The request this device is waiting for, if it has not expired.
    pub fn pending_org_recovery(&self) -> Result<Option<PendingOrgRecovery>> {
        Ok(match self.store.get(ORG_RECOVERY_KEY)? {
            Some(bytes) => serde_json::from_slice::<PendingOrgRecovery>(&bytes)
                .ok()
                .filter(|p| p.expires_at > now_ms()),
            None => None,
        })
    }

    /// Checks the pending request: `pending`, `approved` (then call
    /// [`Client::finish_recovery`]), `denied`, `expired`, `cancelled` or
    /// `completed`.
    pub fn check_org_recovery(&self) -> Result<String> {
        let Some(pending) = self.pending_org_recovery()? else {
            return Ok("expired".into());
        };
        let (_, client_kind) = self.device_fields();
        let status = self.anonymous(
            "POST",
            "/api/v1/recovery/org/status",
            json!({
                "requestId": pending.request_id,
                "requestToken": pending.request_token,
                "clientKind": client_kind,
            }),
        )?;
        let state = status["status"].as_str().unwrap_or("pending").to_owned();
        if state != "approved" {
            if state != "pending" {
                self.store.delete(ORG_RECOVERY_KEY)?;
            }
            return Ok(state);
        }
        let approved: ApprovedRecovery = serde_json::from_value(status["approved"].clone())?;
        let grant: RecoveryGrant = serde_json::from_value(status["recovery"].clone())?;
        let seed: Zeroizing<[u8; 32]> = Zeroizing::new(
            encoding::decode(&pending.seed)?
                .try_into()
                .map_err(|_| Error::InvalidData("corrupt recovery request".into()))?,
        );
        let mut keyring = RecoveryRequestKey::from_seed(&seed).open(&approved)?;
        verify_recovered(&mut keyring, &grant)?;
        self.lock_recovery().ready = Some((grant, keyring));
        Ok(state)
    }

    /// Withdraws the pending request.
    pub fn cancel_org_recovery(&self) -> Result<()> {
        if let Some(pending) = self.pending_org_recovery()? {
            let _ = self.anonymous(
                "POST",
                "/api/v1/recovery/org/cancel",
                json!({ "requestId": pending.request_id, "requestToken": pending.request_token }),
            );
        }
        self.store.delete(ORG_RECOVERY_KEY)
    }

    // --- Emergency access --------------------------------------------------------------

    pub fn emergency_contacts(&self) -> Result<EmergencyContacts> {
        Ok(serde_json::from_value(self.call(
            "GET",
            "/api/v1/emergency",
            None,
        )?)?)
    }

    /// Adds a trusted person by email; they get a mail and must accept.
    pub fn add_emergency_contact(&self, email: &str, wait_days: u32) -> Result<String> {
        let created = self.call(
            "POST",
            "/api/v1/emergency/grants",
            Some(json!({ "granteeEmail": email.trim().to_lowercase(), "waitDays": wait_days })),
        )?;
        Ok(created["id"].as_str().unwrap_or_default().to_owned())
    }

    /// Seals the chosen personal vaults for a contact who accepted, after
    /// looking their key up in the key directory. Returns their fingerprint.
    pub fn confirm_emergency_contact(
        &self,
        grant_id: &str,
        vault_ids: &[String],
    ) -> Result<String> {
        let contact = self
            .emergency_contacts()?
            .granted
            .into_iter()
            .find(|g| g.id == grant_id)
            .ok_or_else(|| Error::NotFound(grant_id.to_owned()))?;
        self.seal_emergency(&contact, vault_ids)
    }

    fn seal_emergency(&self, contact: &EmergencyContact, vault_ids: &[String]) -> Result<String> {
        let grantee = contact.grantee_id.clone().ok_or_else(|| {
            Error::InvalidData("the emergency contact has not accepted yet".into())
        })?;
        self.lookup_key(&grantee)?;
        let body = self.with_keyring(|k| {
            k.seal_emergency_access(
                &contact.id,
                &grantee,
                u64::from(contact.wait_days),
                vault_ids,
                contact.version + 1,
                now_ms(),
            )
        })?;
        self.call(
            "POST",
            &format!("/api/v1/emergency/grants/{}/confirm", contact.id),
            Some(serde_json::to_value(&body)?),
        )?;
        Ok(body.fingerprint)
    }

    /// Seals emergency access again where vault keys changed or chosen
    /// vaults were deleted (call after unlocking). Returns how many grants
    /// were updated.
    pub fn reseal_emergency_access(&self) -> Result<u32> {
        let personal: BTreeSet<String> = self
            .vaults()?
            .into_iter()
            .filter(|v| v.org_id.is_none())
            .map(|v| v.id)
            .collect();
        let mut updated = 0;
        for contact in self.emergency_contacts()?.granted {
            let (Some(grant), Some(signature)) = (&contact.grant, &contact.grant_signature) else {
                continue;
            };
            if contact.status != "confirmed" {
                continue;
            }
            let vault_ids: Vec<String> = contact
                .vault_ids
                .iter()
                .filter(|id| personal.contains(*id))
                .cloned()
                .collect();
            let needed =
                self.with_keyring(|k| k.emergency_reseal_needed(grant, signature, &vault_ids))?;
            if needed && self.seal_emergency(&contact, &vault_ids).is_ok() {
                updated += 1;
            }
        }
        Ok(updated)
    }

    pub fn remove_emergency_contact(&self, grant_id: &str) -> Result<()> {
        self.call(
            "DELETE",
            &format!("/api/v1/emergency/grants/{grant_id}"),
            None,
        )?;
        Ok(())
    }

    fn emergency_action(&self, grant_id: &str, action: &str) -> Result<()> {
        self.call(
            "POST",
            &format!("/api/v1/emergency/grants/{grant_id}/{action}"),
            Some(json!({})),
        )?;
        Ok(())
    }

    pub fn accept_emergency_invitation(&self, grant_id: &str) -> Result<()> {
        self.emergency_action(grant_id, "accept")
    }

    /// As the trusted person: starts the waiting period.
    pub fn request_emergency_access(&self, grant_id: &str) -> Result<()> {
        self.emergency_action(grant_id, "request")
    }

    /// As the grantor: releases access before the waiting period ends.
    pub fn approve_emergency_access(&self, grant_id: &str) -> Result<()> {
        self.emergency_action(grant_id, "approve")
    }

    /// As the grantor: declines the request (or ends released access).
    pub fn deny_emergency_access(&self, grant_id: &str) -> Result<()> {
        self.emergency_action(grant_id, "deny")
    }

    /// As the trusted person after the release: fetches, verifies (the
    /// grantor's key from the key directory) and decrypts the shared vaults.
    pub fn open_emergency_access(&self, grant_id: &str) -> Result<EmergencyVaults> {
        let data = self.call(
            "GET",
            &format!("/api/v1/emergency/grants/{grant_id}/access"),
            None,
        )?;
        let grantor_id = data["grantorId"].as_str().unwrap_or_default().to_owned();
        self.lookup_key(&grantor_id)?;
        let keys = self.with_keyring(|k| {
            k.open_emergency_access(
                data["grant"].as_str().unwrap_or_default(),
                data["grantSignature"].as_str().unwrap_or_default(),
                data["sealedKeys"].as_str().unwrap_or_default(),
            )
        })?;
        let mut errors = Vec::new();
        let mut vaults = Vec::new();
        for vault in data["vaults"].as_array().cloned().unwrap_or_default() {
            let id = vault["id"].as_str().unwrap_or_default().to_owned();
            let epoch = u32::try_from(vault["keyEpoch"].as_u64().unwrap_or(0)).unwrap_or(0);
            match keys
                .decrypt_vault_meta(
                    &id,
                    epoch,
                    vault["encryptedMeta"].as_str().unwrap_or_default(),
                )
                .map_err(Error::from)
                .and_then(|json| Ok(serde_json::from_str::<Value>(&json)?))
            {
                Ok(meta) => vaults.push((id, meta["name"].as_str().unwrap_or("Vault").to_owned())),
                Err(e) => errors.push(format!("Vault {id}: {e}")),
            }
        }
        let mut items = Vec::new();
        for item in data["items"].as_array().cloned().unwrap_or_default() {
            let item_id = item["id"].as_str().unwrap_or_default().to_owned();
            let vault_id = item["vaultId"].as_str().unwrap_or_default().to_owned();
            let revision = item["revision"].as_u64().unwrap_or(0);
            let epoch = u32::try_from(item["keyEpoch"].as_u64().unwrap_or(0)).unwrap_or(0);
            if !id::is_valid_id(&item_id) {
                continue;
            }
            match keys
                .decrypt_item(
                    &vault_id,
                    epoch,
                    &item_id,
                    revision,
                    item["encryptedData"].as_str().unwrap_or_default(),
                )
                .map_err(Error::from)
                .and_then(|json| ItemData::from_json(&json))
            {
                Ok(data) if data.trashed_at().is_none() => items.push(Item {
                    id: item_id,
                    vault_id,
                    revision,
                    updated_at: item["updatedAt"].as_i64().unwrap_or(0),
                    created_at: item["createdAt"].as_i64().unwrap_or(0),
                    key_epoch: epoch,
                    data,
                }),
                Ok(_) => {}
                Err(e) => errors.push(format!("Item {item_id}: {e}")),
            }
        }
        items.sort_by(|a, b| a.data.title.cmp(&b.data.title));
        Ok(EmergencyVaults {
            grantor_id,
            vaults,
            items,
            errors,
        })
    }

    /// The grant details of an own grant (verified signature).
    pub fn emergency_grant_info(&self, grant: &str, signature: &str) -> Result<EmergencyGrantInfo> {
        self.with_keyring(|k| k.emergency_grant_info(grant, signature))
    }

    // --- Adding a device by code -------------------------------------------------------

    /// On a signed-in device: opens a link and returns the code to show.
    pub fn start_device_link(&self) -> Result<DeviceLinkStart> {
        let link = self.call("POST", "/api/v1/device-links", Some(json!({})))?;
        let id = link["id"].as_str().unwrap_or_default().to_owned();
        let offer = DeviceLinkOffer::new(link["shortId"].as_str().unwrap_or_default())?;
        let code = offer.code();
        self.lock_recovery().offers.insert(id.clone(), offer);
        Ok(DeviceLinkStart {
            id,
            code,
            expires_at: link["expiresAt"].as_i64().unwrap_or_default(),
        })
    }

    /// Whether the new device entered the code, and its name.
    pub fn device_link_status(&self, link_id: &str) -> Result<DeviceLinkState> {
        let value = self
            .call("GET", &format!("/api/v1/device-links/{link_id}"), None)
            .map_err(|e| match e {
                Error::Server { code, .. } if code == "device_link_expired" => {
                    invalid_device_code()
                }
                other => other,
            })?;
        Ok(serde_json::from_value(value)?)
    }

    /// Sends the email, account ID and Secret Key to the new device, sealed
    /// to its key. Fails (and sends nothing) if the claim did not come from a
    /// device that knows the code.
    pub fn approve_device_link(&self, link_id: &str) -> Result<()> {
        let account = self.device_account()?.ok_or(Error::NoAccount)?;
        let offer = self
            .lock_recovery()
            .offers
            .remove(link_id)
            .ok_or_else(invalid_device_code)?;
        let state = self.device_link_status(link_id)?;
        let (Some(ephemeral), Some(mac)) = (state.ephemeral_key, state.mac) else {
            return Err(invalid_device_code());
        };
        let payload = serde_json::to_string(&LinkedAccount {
            email: account.email,
            account_id: account.account_id,
            secret_key: account.secret_key,
        })?;
        let sealed = offer
            .seal(
                &encoding::decode(&ephemeral)?,
                &encoding::decode(&mac)?,
                &payload,
            )
            .map_err(|_| invalid_device_code())?;
        self.call(
            "POST",
            &format!("/api/v1/device-links/{link_id}/approve"),
            Some(json!({ "sealedPayload": sealed })),
        )?;
        Ok(())
    }

    pub fn cancel_device_link(&self, link_id: &str) -> Result<()> {
        self.lock_recovery().offers.remove(link_id);
        self.call("DELETE", &format!("/api/v1/device-links/{link_id}"), None)?;
        Ok(())
    }

    /// On the new device: answers the code shown on the signed-in device.
    pub fn claim_device_link(&self, code: &str) -> Result<()> {
        let request = DeviceLinkRequest::new(code)?;
        let (device_name, _) = self.device_fields();
        let claim = self
            .anonymous(
                "POST",
                "/api/v1/device-links/claim",
                json!({
                    "shortId": request.short_id(),
                    "ephemeralKey": encoding::encode(&request.public_key()),
                    "mac": encoding::encode(request.mac()),
                    "deviceName": device_name,
                }),
            )
            .map_err(|e| match e {
                Error::Server { code, .. } if code == "device_link_expired" => {
                    invalid_device_code()
                }
                other => other,
            })?;
        let token = claim["claimToken"].as_str().unwrap_or_default().to_owned();
        self.lock_recovery().claim = Some((request, token));
        Ok(())
    }

    /// Polls for the approval: the account details once approved (then
    /// sign in with them and the master password), `None` while waiting.
    pub fn poll_device_link(&self) -> Result<Option<LinkedAccount>> {
        let token = self
            .lock_recovery()
            .claim
            .as_ref()
            .map(|(_, token)| token.clone())
            .ok_or_else(invalid_device_code)?;
        let result = self.anonymous(
            "POST",
            "/api/v1/device-links/poll",
            json!({ "claimToken": token }),
        )?;
        if result["status"] != "approved" {
            return Ok(None);
        }
        let (request, _) = self
            .lock_recovery()
            .claim
            .take()
            .ok_or_else(invalid_device_code)?;
        let payload = request.open(result["sealedPayload"].as_str().unwrap_or_default())?;
        Ok(Some(serde_json::from_str(&payload)?))
    }

    // --- Signing in a new device from a signed-in browser ------------------------------

    /// On a device without a session (`pbx login`): registers a sign-in
    /// request and returns the link to open in a signed-in browser (valid
    /// 10 minutes). Poll with [`Client::poll_cli_login`].
    pub fn start_cli_login(&self) -> Result<CliLoginStart> {
        let (device_name, _) = self.device_fields();
        let request = CliLoginRequest::new(&device_name)?;
        let created = self.anonymous(
            "POST",
            "/api/v1/cli-logins",
            json!({
                "id": request.id(),
                "ephemeralKey": encoding::encode(&request.public_key()),
                "mac": encoding::encode(request.mac()),
                "deviceName": request.device_name(),
            }),
        )?;
        let token = created["pollToken"].as_str().unwrap_or_default().to_owned();
        let start = CliLoginStart {
            id: request.id().to_owned(),
            url: format!("{}/{}", self.api.base_url(), request.link_fragment()),
            expires_at: created["expiresAt"].as_i64().unwrap_or_default(),
        };
        self.lock_recovery().cli_login = Some((request, token));
        Ok(start)
    }

    /// Whether the browser answered. The account details arrive once.
    pub fn poll_cli_login(&self) -> Result<CliLoginPoll> {
        let token = self
            .lock_recovery()
            .cli_login
            .as_ref()
            .map(|(_, token)| token.clone())
            .ok_or_else(cli_login_expired)?;
        let result = match self.anonymous(
            "POST",
            "/api/v1/cli-logins/poll",
            json!({ "pollToken": token }),
        ) {
            Ok(result) => result,
            Err(Error::Server { code, .. }) if code == "cli_login_expired" => {
                self.lock_recovery().cli_login = None;
                return Ok(CliLoginPoll::Expired);
            }
            Err(other) => return Err(other),
        };
        let status = result["status"].as_str().unwrap_or_default();
        if status == "pending" {
            return Ok(CliLoginPoll::Pending);
        }
        let (request, _) = self
            .lock_recovery()
            .cli_login
            .take()
            .ok_or_else(cli_login_expired)?;
        match status {
            "approved" => {
                let payload = request.open(result["sealedPayload"].as_str().unwrap_or_default())?;
                Ok(CliLoginPoll::Approved {
                    account: serde_json::from_str(&payload)?,
                    approved_by: result["approvedBy"].as_str().unwrap_or_default().to_owned(),
                })
            }
            "denied" => Ok(CliLoginPoll::Denied),
            _ => Ok(CliLoginPoll::Expired),
        }
    }

    /// Withdraws the request (for example on Ctrl+C).
    pub fn cancel_cli_login(&self) -> Result<()> {
        let Some((_, token)) = self.lock_recovery().cli_login.take() else {
            return Ok(());
        };
        self.anonymous(
            "POST",
            "/api/v1/cli-logins/cancel",
            json!({ "pollToken": token }),
        )?;
        Ok(())
    }

    /// On the signed-in device: the request a link points to (`id` and
    /// `secret` from its fragment), after checking that the key and the
    /// device name are the ones the requesting device registered.
    pub fn cli_login_request(&self, id: &str, secret: &str) -> Result<CliLoginInfo> {
        let approval = CliLoginApproval::new(id, secret).map_err(|_| cli_login_expired())?;
        let info = self.fetch_cli_login(&approval)?;
        approval
            .verify(
                &encoding::decode(&info.ephemeral_key)?,
                &info.device_name,
                &encoding::decode(&info.mac)?,
            )
            .map_err(|_| cli_login_expired())?;
        Ok(info)
    }

    fn fetch_cli_login(&self, approval: &CliLoginApproval) -> Result<CliLoginInfo> {
        let value = self.call(
            "GET",
            &format!("/api/v1/cli-logins/{}", approval.id()),
            None,
        )?;
        Ok(serde_json::from_value(value)?)
    }

    /// Sends the email, account ID and Secret Key to the requesting device,
    /// sealed to its key. Fails (and sends nothing) if the request does not
    /// match the link.
    pub fn approve_cli_login(&self, id: &str, secret: &str) -> Result<()> {
        let account = self.device_account()?.ok_or(Error::NoAccount)?;
        let approval = CliLoginApproval::new(id, secret).map_err(|_| cli_login_expired())?;
        let info = self.fetch_cli_login(&approval)?;
        let payload = Zeroizing::new(serde_json::to_string(&LinkedAccount {
            email: account.email,
            account_id: account.account_id,
            secret_key: account.secret_key,
        })?);
        let sealed = approval
            .seal(
                &encoding::decode(&info.ephemeral_key)?,
                &info.device_name,
                &encoding::decode(&info.mac)?,
                &payload,
            )
            .map_err(|_| cli_login_expired())?;
        self.call(
            "POST",
            &format!("/api/v1/cli-logins/{id}/approve"),
            Some(json!({ "sealedPayload": sealed })),
        )?;
        Ok(())
    }

    /// Denies the request; the requesting device is told.
    pub fn deny_cli_login(&self, id: &str) -> Result<()> {
        if !id::is_valid_id(id) {
            return Err(cli_login_expired());
        }
        self.call(
            "POST",
            &format!("/api/v1/cli-logins/{id}/deny"),
            Some(json!({})),
        )?;
        Ok(())
    }
}
