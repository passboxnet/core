//! WebAssembly bindings for the Passbox core, used by the web client and the
//! browser extension.
//!
//! Secret material (master keys, account and vault keys, OPAQUE state) stays
//! inside WebAssembly objects. JavaScript only sees ciphertexts, protocol
//! messages and the decrypted JSON it needs to display. Call `free()` on
//! objects holding secrets when they are no longer needed; their memory is
//! wiped on drop.
//!
//! Build with `pnpm --filter @passbox/core-wasm build`.

use passbox_core::aead::{KEY_LEN, SymmetricKey};
use passbox_core::device_link::{
    CliLoginApproval as CoreCliLoginApproval, CliLoginRequest as CoreCliLoginRequest,
    DeviceLinkOffer as CoreDeviceLinkOffer, DeviceLinkRequest as CoreDeviceLinkRequest,
};
use passbox_core::emergency::EmergencyKeys as CoreEmergencyKeys;
use passbox_core::generator::{self, PassphraseOptions, PasswordOptions};
use passbox_core::kdf::{self, KdfParams, MasterKeys as CoreMasterKeys};
use passbox_core::keyring::Keyring as CoreKeyring;
use passbox_core::opaque::{ClientLoginFlow, ClientRegistrationFlow};
use passbox_core::passkey::{self, Flags};
use passbox_core::recovery::code::{RecoveryCode, RecoveryKeys as CoreRecoveryKeys};
use passbox_core::recovery::org::{
    self as org_recovery, RecoveryRequestKey as CoreRecoveryRequestKey,
};
use passbox_core::secret_key::SecretKey;
use passbox_core::sharing::objects::{OrgKind, OrgRole, PrincipalType, VaultRole};
use passbox_core::strength;
use passbox_core::totp::Totp;
use passbox_core::{Error, encoding, export, id};
use wasm_bindgen::prelude::*;

/// Converts a core error into a JavaScript `Error`. Wrong credentials get the
/// name `InvalidCredentialsError` so callers can tell them apart.
fn js_error(err: Error) -> JsValue {
    let error = js_sys::Error::new(&err.to_string());
    if err == Error::InvalidCredentials {
        error.set_name("InvalidCredentialsError");
    }
    error.into()
}

fn json_error(err: serde_json::Error) -> JsValue {
    js_sys::Error::new(&format!("invalid JSON: {err}")).into()
}

fn revision(value: f64) -> Result<u64, JsValue> {
    if value.fract() == 0.0 && (1.0..=9_007_199_254_740_991.0).contains(&value) {
        Ok(value as u64)
    } else {
        Err(js_sys::Error::new("revision must be a positive integer").into())
    }
}

// --- Utilities ----------------------------------------------------------------

/// Generates a password. `options_json` is a JSON object matching `PasswordOptions`;
/// missing fields use the defaults.
#[wasm_bindgen(js_name = generatePassword)]
pub fn generate_password(options_json: &str) -> Result<String, JsValue> {
    let options: PasswordOptions = serde_json::from_str(options_json).map_err(json_error)?;
    generator::generate_password(&options).map_err(js_error)
}

/// Generates a word passphrase. `options_json` is a `PassphraseOptions`
/// object (`words`, `separator`, `capitalize`, `includeDigit`).
#[wasm_bindgen(js_name = generatePassphrase)]
pub fn generate_passphrase(options_json: &str) -> Result<String, JsValue> {
    let options: PassphraseOptions = serde_json::from_str(options_json).map_err(json_error)?;
    generator::generate_passphrase(&options).map_err(js_error)
}

/// Estimates password strength. `user_inputs_json` is a JSON array of
/// strings an attacker would try first (email, name). Returns JSON:
/// `{"score":0-4,"bits":n,"warning":code|null,"suggestions":[codes],
/// "acceptableMasterPassword":bool}`.
#[wasm_bindgen(js_name = estimateStrength)]
pub fn estimate_strength(password: &str, user_inputs_json: &str) -> Result<String, JsValue> {
    let inputs: Vec<String> = serde_json::from_str(user_inputs_json).map_err(json_error)?;
    let inputs: Vec<&str> = inputs.iter().map(String::as_str).collect();
    let estimate = strength::estimate(password, &inputs);
    Ok(serde_json::json!({
        "score": estimate.score,
        "bits": estimate.bits,
        "warning": estimate.warning,
        "suggestions": estimate.suggestions,
        "acceptableMasterPassword": strength::is_acceptable_master_password(password, &estimate),
    })
    .to_string())
}

/// The vault security analysis (`passbox_core::analysis::analyze`).
/// `items_json` is an array of `{ id, createdAt, data }` with `data` in the
/// item format; `options_json` an `AnalysisOptions` object. Returns the
/// `SecurityReport` as JSON. Everything runs locally.
#[wasm_bindgen(js_name = analyzeSecurity)]
pub fn analyze_security(items_json: &str, options_json: &str) -> Result<String, JsValue> {
    use passbox_core::analysis;
    let items: Vec<analysis::AnalysisItem> =
        serde_json::from_str(items_json).map_err(json_error)?;
    let options: analysis::AnalysisOptions =
        serde_json::from_str(options_json).map_err(json_error)?;
    serde_json::to_string(&analysis::analyze(&items, &options)).map_err(json_error)
}

/// The breach catalogue snapshot bundled with this build, without its
/// entries: `{ version, updatedAt, entries, source, sourceUrl, license }`
/// as JSON. `analyzeSecurity` uses the snapshot when the options carry no
/// `siteBreaches`.
#[wasm_bindgen(js_name = bundledBreachCatalog)]
pub fn bundled_breach_catalog() -> Result<String, JsValue> {
    let catalog = passbox_core::analysis::breaches::bundled();
    serde_json::to_string(&serde_json::json!({
        "version": catalog.version,
        "updatedAt": catalog.updated_at,
        "entries": catalog.breaches.len(),
        "source": catalog.source,
        "sourceUrl": catalog.source_url,
        "license": catalog.license,
    }))
    .map_err(json_error)
}

/// Checks a page host against the user's saved login hosts (JSON array)
/// and well-known sites before filling or saving. Returns a `Lookalike`
/// as JSON (`{ domain, looksLike, reason, saved }`) or `undefined`.
#[wasm_bindgen(js_name = checkLookalike)]
pub fn check_lookalike(host: &str, saved_json: &str) -> Result<Option<String>, JsValue> {
    let saved: Vec<String> = serde_json::from_str(saved_json).map_err(json_error)?;
    passbox_core::analysis::lookalike::check_host(host, saved.iter().map(String::as_str), true)
        .map(|found| serde_json::to_string(&found).map_err(json_error))
        .transpose()
}

/// What the bundled 2FA and passkey directories know about a host, as
/// JSON (`SiteSupport`), or `undefined`.
#[wasm_bindgen(js_name = siteSupport)]
pub fn site_support(host: &str) -> Result<Option<String>, JsValue> {
    passbox_core::analysis::sites::lookup(host)
        .map(|site| serde_json::to_string(&site).map_err(json_error))
        .transpose()
}

/// Checks a one-time password field: `undefined` when fine or empty,
/// `"one_time_code"` for a single code instead of the setup key, or
/// `"invalid"`.
#[wasm_bindgen(js_name = totpInputProblem)]
pub fn totp_input_problem(input: &str) -> Option<String> {
    Totp::input_problem(input).map(str::to_owned)
}

/// Generates a new Secret Key in display format.
#[wasm_bindgen(js_name = generateSecretKey)]
pub fn generate_secret_key() -> Result<String, JsValue> {
    Ok(SecretKey::generate().map_err(js_error)?.to_display_string())
}

/// Returns the normalized display format of a Secret Key, or throws if it is invalid.
#[wasm_bindgen(js_name = normalizeSecretKey)]
pub fn normalize_secret_key(input: &str) -> Result<String, JsValue> {
    Ok(SecretKey::parse(input)
        .map_err(js_error)?
        .to_display_string())
}

/// Creates a new random ID for accounts, vaults and items.
#[wasm_bindgen(js_name = newId)]
pub fn new_id() -> Result<String, JsValue> {
    id::new_id().map_err(js_error)
}

/// Generates a new KDF salt (Base64url).
#[wasm_bindgen(js_name = generateKdfSalt)]
pub fn generate_kdf_salt() -> Result<String, JsValue> {
    Ok(encoding::encode(&kdf::generate_salt().map_err(js_error)?))
}

/// The KDF parameters for new accounts, as JSON.
#[wasm_bindgen(js_name = defaultKdfParams)]
pub fn default_kdf_params() -> String {
    serde_json::to_string(&KdfParams::DEFAULT).expect("KdfParams serialize")
}

/// Generates the TOTP code for an `otpauth://` URI or a Base32 secret at `unix_time` seconds.
#[wasm_bindgen(js_name = totpCode)]
pub fn totp_code(uri_or_secret: &str, unix_time: f64) -> Result<String, JsValue> {
    let totp = Totp::parse(uri_or_secret).map_err(js_error)?;
    // Time values from JavaScript are non-negative and well within u64 range.
    Ok(totp.generate(unix_time.max(0.0) as u64))
}

// --- Export files ---------------------------------------------------------------

/// Encrypts an export payload (UTF-8 text, usually JSON) with a password the
/// user chose for this file. Uses the default KDF parameters and returns the
/// `.pbx-export` JSON envelope.
#[wasm_bindgen(js_name = encryptExport)]
pub fn encrypt_export(password: &str, plaintext: &str) -> Result<String, JsValue> {
    export::encrypt(password, plaintext.as_bytes(), KdfParams::DEFAULT).map_err(js_error)
}

/// Decrypts a `.pbx-export` envelope. A wrong password or a modified file
/// throws an error named `ExportDecryptionError`.
#[wasm_bindgen(js_name = decryptExport)]
pub fn decrypt_export(password: &str, envelope_json: &str) -> Result<String, JsValue> {
    let plaintext = export::decrypt(password, envelope_json).map_err(|err| {
        let wrong_password = err == Error::Decryption;
        let value = js_error(err);
        if wrong_password {
            js_sys::Reflect::set(&value, &"name".into(), &"ExportDecryptionError".into()).ok();
        }
        value
    })?;
    String::from_utf8(plaintext.to_vec())
        .map_err(|_| js_sys::Error::new("the export payload is not UTF-8 text").into())
}

/// Whether `input` is a `.pbx-export` envelope (checked without decrypting).
#[wasm_bindgen(js_name = isExport)]
pub fn is_export(input: &str) -> bool {
    export::is_export(input)
}

// --- Passkeys ----------------------------------------------------------------

/// Creates an ES256 passkey for `rp_id`. The caller must have checked the
/// relying party ID against the requesting origin. Returns JSON with Base64url
/// values: `{ credentialId, privateKey (PKCS#8), publicKeyCose, publicKeySpki,
/// authenticatorData, attestationObject, algorithm }`.
///
/// `user_verified` sets the UV flag. Pass `true` only when the user entered
/// the master password (or used biometrics) for this very operation.
#[wasm_bindgen(js_name = passkeyCreate)]
pub fn passkey_create(rp_id: &str, user_verified: bool) -> Result<String, JsValue> {
    let created = passkey::create(rp_id, Flags::synced(user_verified)).map_err(js_error)?;
    Ok(serde_json::json!({
        "credentialId": encoding::encode(&created.credential_id),
        "privateKey": encoding::encode(&created.private_key_pkcs8),
        "publicKeyCose": encoding::encode(&created.public_key_cose),
        "publicKeySpki": encoding::encode(&created.public_key_spki),
        "authenticatorData": encoding::encode(&created.authenticator_data),
        "attestationObject": encoding::encode(&created.attestation_object),
        "algorithm": passkey::ALG_ES256,
    })
    .to_string())
}

/// Signs a WebAuthn assertion with a stored passkey (`private_key`: PKCS#8,
/// Base64url) over `authenticatorData || SHA-256(client_data_json)`. Returns
/// JSON `{ authenticatorData, signature }` (Base64url, DER signature).
/// `user_verified` sets the UV flag, as for `passkeyCreate`.
#[wasm_bindgen(js_name = passkeyAssert)]
pub fn passkey_assert(
    private_key: &str,
    rp_id: &str,
    client_data_json: &str,
    sign_count: u32,
    user_verified: bool,
) -> Result<String, JsValue> {
    let der = zeroize::Zeroizing::new(encoding::decode(private_key).map_err(js_error)?);
    let assertion = passkey::assert(
        &der,
        rp_id,
        client_data_json.as_bytes(),
        sign_count,
        Flags::synced(user_verified),
    )
    .map_err(js_error)?;
    Ok(serde_json::json!({
        "authenticatorData": encoding::encode(&assertion.authenticator_data),
        "signature": encoding::encode(&assertion.signature),
    })
    .to_string())
}

// --- Keys ---------------------------------------------------------------------

/// Keys derived from the master password and the Secret Key.
#[wasm_bindgen]
pub struct MasterKeys(CoreMasterKeys);

#[wasm_bindgen]
impl MasterKeys {
    /// Runs Argon2id and derives the master keys. This takes a moment; run it
    /// in a worker or show progress. Throws if the parameters are below the
    /// minimum or the Secret Key is malformed.
    pub fn derive(
        password: &str,
        secret_key: &str,
        account_id: &str,
        kdf_salt: &str,
        kdf_params_json: &str,
    ) -> Result<MasterKeys, JsValue> {
        let secret_key = SecretKey::parse(secret_key).map_err(js_error)?;
        let salt: [u8; kdf::SALT_LEN] = encoding::decode(kdf_salt)
            .map_err(js_error)?
            .try_into()
            .map_err(|_| JsValue::from(js_sys::Error::new("KDF salt must be 16 bytes")))?;
        let params: KdfParams = serde_json::from_str(kdf_params_json).map_err(json_error)?;
        kdf::derive_master_keys(password, &secret_key, account_id, &salt, params)
            .map(MasterKeys)
            .map_err(js_error)
    }
}

// --- OPAQUE -------------------------------------------------------------------

/// Client side of an account registration.
#[wasm_bindgen]
pub struct RegistrationFlow {
    flow: Option<ClientRegistrationFlow>,
    request: String,
}

#[wasm_bindgen]
impl RegistrationFlow {
    pub fn start(keys: &MasterKeys) -> Result<RegistrationFlow, JsValue> {
        let (flow, request) =
            ClientRegistrationFlow::start(&*keys.0.auth_secret).map_err(js_error)?;
        Ok(Self {
            flow: Some(flow),
            request: encoding::encode(&request),
        })
    }

    /// The registration request for the server (Base64url).
    #[wasm_bindgen(getter)]
    pub fn request(&self) -> String {
        self.request.clone()
    }

    /// Processes the server's response and returns the upload message (Base64url).
    pub fn finish(&mut self, response: &str) -> Result<String, JsValue> {
        let flow = self
            .flow
            .take()
            .ok_or_else(|| JsValue::from(js_sys::Error::new("registration already finished")))?;
        let upload = flow
            .finish(&encoding::decode(response).map_err(js_error)?)
            .map_err(js_error)?;
        Ok(encoding::encode(&upload))
    }
}

/// Client side of a login.
#[wasm_bindgen]
pub struct LoginFlow {
    flow: Option<ClientLoginFlow>,
    request: String,
}

#[wasm_bindgen]
impl LoginFlow {
    pub fn start(keys: &MasterKeys) -> Result<LoginFlow, JsValue> {
        let (flow, request) = ClientLoginFlow::start(&*keys.0.auth_secret).map_err(js_error)?;
        Ok(Self {
            flow: Some(flow),
            request: encoding::encode(&request),
        })
    }

    /// The credential request for the server (Base64url).
    #[wasm_bindgen(getter)]
    pub fn request(&self) -> String {
        self.request.clone()
    }

    /// Processes the server's response and returns the finalization message
    /// (Base64url). Throws `InvalidCredentialsError` if the password or Secret
    /// Key is wrong.
    pub fn finish(&mut self, response: &str) -> Result<String, JsValue> {
        let flow = self
            .flow
            .take()
            .ok_or_else(|| JsValue::from(js_sys::Error::new("login already finished")))?;
        let result = flow
            .finish(&encoding::decode(response).map_err(js_error)?)
            .map_err(js_error)?;
        Ok(encoding::encode(&result.finalization))
    }
}

// --- Keyring ------------------------------------------------------------------

/// The unlocked key hierarchy of an account.
#[wasm_bindgen]
pub struct Keyring {
    inner: CoreKeyring,
    encrypted_account_key: Option<String>,
}

#[wasm_bindgen]
impl Keyring {
    /// Creates the keys of a new account. Read `encryptedAccountKey` afterwards
    /// to upload it.
    pub fn create(keys: &MasterKeys, account_id: &str) -> Result<Keyring, JsValue> {
        let (inner, encrypted) = CoreKeyring::create(&keys.0.auk, account_id).map_err(js_error)?;
        Ok(Self {
            inner,
            encrypted_account_key: Some(encrypted),
        })
    }

    /// Unlocks an existing account. Throws `InvalidCredentialsError` if the
    /// master keys do not match.
    pub fn unlock(
        keys: &MasterKeys,
        account_id: &str,
        encrypted_account_key: &str,
    ) -> Result<Keyring, JsValue> {
        let inner = CoreKeyring::unlock(&keys.0.auk, account_id, encrypted_account_key)
            .map_err(js_error)?;
        Ok(Self {
            inner,
            encrypted_account_key: Some(encrypted_account_key.to_owned()),
        })
    }

    /// Restores a keyring exported with `exportSession`. Throws if the session
    /// key, account ID or blob do not match.
    #[wasm_bindgen(js_name = importSession)]
    pub fn import_session(
        session_key: &str,
        account_id: &str,
        blob: &str,
    ) -> Result<Keyring, JsValue> {
        let bytes = zeroize::Zeroizing::new(encoding::decode(session_key).map_err(js_error)?);
        let key: [u8; KEY_LEN] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| JsValue::from(js_sys::Error::new("session key must be 32 bytes")))?;
        let inner = CoreKeyring::import_session(&SymmetricKey::from_bytes(key), account_id, blob)
            .map_err(js_error)?;
        Ok(Self {
            inner,
            encrypted_account_key: None,
        })
    }

    /// Exports the unlocked keys encrypted under a fresh session key. Returns
    /// JSON `{ sessionKey, blob }` (Base64url). Keep both in memory-only
    /// storage (for example `chrome.storage.session`) and delete them on lock.
    #[wasm_bindgen(js_name = exportSession)]
    pub fn export_session(&self) -> Result<String, JsValue> {
        let (key, blob) = self.inner.export_session().map_err(js_error)?;
        Ok(serde_json::json!({
            "sessionKey": encoding::encode(key.as_bytes()),
            "blob": blob,
        })
        .to_string())
    }

    /// Encrypts the account key with new master keys, for changing the master
    /// password. Returns Base64url.
    #[wasm_bindgen(js_name = wrapAccountKey)]
    pub fn wrap_account_key(&self, keys: &MasterKeys) -> Result<String, JsValue> {
        self.inner.wrap_account_key(&keys.0.auk).map_err(js_error)
    }

    /// Encrypts device-local data (JSON, for example item usage) with the
    /// account key; `purpose` is bound as associated data. Returns Base64url.
    #[wasm_bindgen(js_name = encryptLocal)]
    pub fn encrypt_local(&self, purpose: &str, json: &str) -> Result<String, JsValue> {
        self.inner.encrypt_local(purpose, json).map_err(js_error)
    }

    /// Decrypts data from `encryptLocal` with the same `purpose`.
    #[wasm_bindgen(js_name = decryptLocal)]
    pub fn decrypt_local(&self, purpose: &str, encrypted: &str) -> Result<String, JsValue> {
        self.inner
            .decrypt_local(purpose, encrypted)
            .map_err(js_error)
    }

    /// The account key encrypted with the Account Unlock Key (Base64url).
    #[wasm_bindgen(getter, js_name = encryptedAccountKey)]
    pub fn encrypted_account_key(&self) -> Option<String> {
        self.encrypted_account_key.clone()
    }

    /// Creates a vault. Returns JSON `{ id, encryptedKey, encryptedMeta }`.
    #[wasm_bindgen(js_name = createVault)]
    pub fn create_vault(&mut self, meta_json: &str) -> Result<String, JsValue> {
        let vault = self.inner.create_vault(meta_json).map_err(js_error)?;
        Ok(serde_json::json!({
            "id": vault.id,
            "encryptedKey": vault.encrypted_key,
            "encryptedMeta": vault.encrypted_meta,
        })
        .to_string())
    }

    #[wasm_bindgen(js_name = addVault)]
    pub fn add_vault(&mut self, vault_id: &str, encrypted_key: &str) -> Result<(), JsValue> {
        self.inner
            .add_vault(vault_id, encrypted_key)
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = hasVault)]
    pub fn has_vault(&self, vault_id: &str) -> bool {
        self.inner.has_vault(vault_id)
    }

    #[wasm_bindgen(js_name = encryptVaultMeta)]
    pub fn encrypt_vault_meta(&self, vault_id: &str, meta_json: &str) -> Result<String, JsValue> {
        self.inner
            .encrypt_vault_meta(vault_id, meta_json)
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = decryptVaultMeta)]
    pub fn decrypt_vault_meta(
        &self,
        vault_id: &str,
        encrypted_meta: &str,
    ) -> Result<String, JsValue> {
        self.inner
            .decrypt_vault_meta(vault_id, encrypted_meta)
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = encryptItem)]
    pub fn encrypt_item(
        &self,
        vault_id: &str,
        item_id: &str,
        revision_: f64,
        data_json: &str,
    ) -> Result<String, JsValue> {
        self.inner
            .encrypt_item(vault_id, item_id, revision(revision_)?, data_json)
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = decryptItem)]
    pub fn decrypt_item(
        &self,
        vault_id: &str,
        item_id: &str,
        revision_: f64,
        encrypted: &str,
    ) -> Result<String, JsValue> {
        self.inner
            .decrypt_item(vault_id, item_id, revision(revision_)?, encrypted)
            .map_err(js_error)
    }
}

// --- Key pairs, key directory and sharing ------------------------------------------
//
// Private keys (account key pairs, group keys) stay inside the keyring.
// Objects cross the boundary as JSON; request builders return the JSON body
// for the server endpoint named in their documentation
// (`passbox_core::sharing::build`).

fn to_json<T: serde::Serialize>(value: &T) -> Result<String, JsValue> {
    serde_json::to_string(value).map_err(json_error)
}

fn from_json<T: serde::de::DeserializeOwned>(json: &str) -> Result<T, JsValue> {
    serde_json::from_str(json).map_err(json_error)
}

fn epoch(value: f64) -> Result<u32, JsValue> {
    if value.fract() == 0.0 && (0.0..=f64::from(u32::MAX)).contains(&value) {
        Ok(value as u32)
    } else {
        Err(js_sys::Error::new("epoch must be a non-negative integer").into())
    }
}

fn now(value: f64) -> i64 {
    value as i64
}

fn principals(json: &str) -> Result<Vec<(PrincipalType, String)>, JsValue> {
    let list: Vec<(String, String)> = from_json(json)?;
    list.into_iter()
        .map(|(t, id)| Ok((PrincipalType::parse(&t).map_err(js_error)?, id)))
        .collect()
}

#[wasm_bindgen]
impl Keyring {
    /// Creates the account's key pairs (on sign-up, or on the first unlock of
    /// an existing account). Returns JSON `{ keyVersion, bundle,
    /// bundleSignature, encryptedPrivate }` for `PUT /api/v1/account/keys`.
    #[wasm_bindgen(js_name = createAccountKeys)]
    pub fn create_account_keys(&mut self, now_ms: f64) -> Result<String, JsValue> {
        to_json(
            &self
                .inner
                .create_account_keys(now(now_ms))
                .map_err(js_error)?,
        )
    }

    /// Loads the key pairs from `GET /api/v1/account/keys`. Throws if they do
    /// not belong to this account or the halves do not match.
    #[wasm_bindgen(js_name = loadAccountKeys)]
    pub fn load_account_keys(
        &mut self,
        bundle: &str,
        bundle_signature: &str,
        encrypted_private: &str,
    ) -> Result<(), JsValue> {
        self.inner
            .load_account_keys(bundle, bundle_signature, encrypted_private)
            .map_err(js_error)
    }

    /// The account ID the keyring belongs to.
    #[wasm_bindgen(getter, js_name = accountId)]
    pub fn account_id(&self) -> String {
        self.inner.account_id().to_owned()
    }

    #[wasm_bindgen(js_name = hasAccountKeys)]
    pub fn has_account_keys(&self) -> bool {
        self.inner.has_account_keys()
    }

    /// Fingerprint of the account's own keys (12 groups of five digits).
    #[wasm_bindgen(js_name = ownFingerprint)]
    pub fn own_fingerprint(&self) -> Option<String> {
        self.inner.own_bundle().map(|b| b.fingerprint())
    }

    /// The trust store (pinned keys, organization fingerprints, verified
    /// directory head, manifest versions) as JSON, for persisting.
    #[wasm_bindgen(js_name = trustStore)]
    pub fn trust_store(&self) -> Result<String, JsValue> {
        to_json(self.inner.trust_store())
    }

    #[wasm_bindgen(js_name = setTrustStore)]
    pub fn set_trust_store(&mut self, json: &str) -> Result<(), JsValue> {
        self.inner.set_trust_store(from_json(json)?);
        Ok(())
    }

    /// Merges the `sharing` object of a sync response, verifies everything
    /// and opens keys. Returns JSON `{ view, wrappedKeys }`.
    #[wasm_bindgen(js_name = applySharing)]
    pub fn apply_sharing(&mut self, delta_json: &str) -> Result<String, JsValue> {
        let delta = from_json(delta_json)?;
        to_json(&self.inner.apply_sharing(delta))
    }

    /// The last verified view: `{ orgs, vaults, warnings }`.
    #[wasm_bindgen(js_name = sharingView)]
    pub fn sharing_view(&self) -> Result<String, JsValue> {
        to_json(self.inner.sharing_view())
    }

    /// Pins the organization fingerprint from an invitation link.
    #[wasm_bindgen(js_name = pinOrgRoot)]
    pub fn pin_org_root(&mut self, org_id: &str, root_hash: &str) -> Result<(), JsValue> {
        self.inner.pin_org_root(org_id, root_hash).map_err(js_error)
    }

    /// `[rootHash, fingerprint]` of an organization, as JSON.
    #[wasm_bindgen(js_name = orgFingerprint)]
    pub fn org_fingerprint(&self, org_id: &str) -> Result<String, JsValue> {
        to_json(&self.inner.org_fingerprint(org_id).map_err(js_error)?)
    }

    /// Verifies a `GET /api/v1/keys/{id}` response. Returns JSON
    /// `{ accountId, fingerprint, bundleHash, status, previousFingerprint }`.
    #[wasm_bindgen(js_name = verifyDirectoryLookup)]
    pub fn verify_directory_lookup(
        &mut self,
        account_id: &str,
        response_json: &str,
    ) -> Result<String, JsValue> {
        let response = from_json(response_json)?;
        to_json(
            &self
                .inner
                .verify_directory_lookup(account_id, &response)
                .map_err(js_error)?,
        )
    }

    /// Trusts the current key of an account after a change. Returns its
    /// fingerprint.
    #[wasm_bindgen(js_name = acceptKeyChange)]
    pub fn accept_key_change(&mut self, account_id: &str) -> Result<String, JsValue> {
        self.inner.accept_key_change(account_id).map_err(js_error)
    }

    /// `POST /api/v1/orgs` body. `kind` is `family` or `team`.
    #[wasm_bindgen(js_name = createOrg)]
    pub fn create_org(
        &mut self,
        kind: &str,
        meta_json: &str,
        vault_meta_json: Option<String>,
        now_ms: f64,
    ) -> Result<String, JsValue> {
        let kind = OrgKind::parse(kind).map_err(js_error)?;
        to_json(
            &self
                .inner
                .create_org(kind, meta_json, vault_meta_json.as_deref(), now(now_ms))
                .map_err(js_error)?,
        )
    }

    /// `POST /api/v1/orgs/{orgId}/vaults` body.
    #[wasm_bindgen(js_name = createSharedVault)]
    pub fn create_shared_vault(
        &mut self,
        org_id: &str,
        meta_json: &str,
        now_ms: f64,
    ) -> Result<String, JsValue> {
        to_json(
            &self
                .inner
                .create_shared_vault(org_id, meta_json, now(now_ms))
                .map_err(js_error)?,
        )
    }

    /// `POST /api/v1/orgs/{orgId}/members/{accountId}/confirm` body (with
    /// the attested `fingerprint`). Look the member up first.
    #[wasm_bindgen(js_name = confirmMember)]
    pub fn confirm_member(
        &mut self,
        org_id: &str,
        account_id: &str,
        now_ms: f64,
    ) -> Result<String, JsValue> {
        to_json(
            &self
                .inner
                .confirm_member(org_id, account_id, now(now_ms))
                .map_err(js_error)?,
        )
    }

    /// `PUT /api/v1/orgs/{orgId}/members/{accountId}` body.
    #[wasm_bindgen(js_name = setMemberRole)]
    pub fn set_member_role(
        &self,
        org_id: &str,
        account_id: &str,
        role: &str,
        now_ms: f64,
    ) -> Result<String, JsValue> {
        let role = OrgRole::parse(role).map_err(js_error)?;
        to_json(
            &self
                .inner
                .set_member_role(org_id, account_id, role, now(now_ms))
                .map_err(js_error)?,
        )
    }

    /// Re-attestations (JSON array of `PUT .../members/{id}` bodies) for the
    /// members attested by `attester_id`.
    #[wasm_bindgen(js_name = reattestMembers)]
    pub fn reattest_members(
        &self,
        org_id: &str,
        attester_id: &str,
        now_ms: f64,
    ) -> Result<String, JsValue> {
        to_json(
            &self
                .inner
                .reattest_members(org_id, attester_id, now(now_ms))
                .map_err(js_error)?,
        )
    }

    /// `POST /api/v1/orgs/{orgId}/rotate-key` body.
    #[wasm_bindgen(js_name = rotateOrgKey)]
    pub fn rotate_org_key(&mut self, org_id: &str, now_ms: f64) -> Result<String, JsValue> {
        to_json(
            &self
                .inner
                .rotate_org_key(org_id, now(now_ms))
                .map_err(js_error)?,
        )
    }

    /// `POST /api/v1/vaults/{vaultId}/members` body (share or change role).
    #[wasm_bindgen(js_name = shareVault)]
    pub fn share_vault(
        &self,
        vault_id: &str,
        principal_type: &str,
        principal_id: &str,
        role: &str,
        now_ms: f64,
    ) -> Result<String, JsValue> {
        let principal_type = PrincipalType::parse(principal_type).map_err(js_error)?;
        let role = VaultRole::parse(role).map_err(js_error)?;
        to_json(
            &self
                .inner
                .share_vault(vault_id, principal_type, principal_id, role, now(now_ms))
                .map_err(js_error)?,
        )
    }

    /// `POST /api/v1/vaults/{vaultId}/rotate` body. `removed_json` is a JSON
    /// array of `[principalType, principalId]` pairs.
    #[wasm_bindgen(js_name = rotateVault)]
    pub fn rotate_vault(
        &mut self,
        vault_id: &str,
        removed_json: &str,
        meta_json: &str,
        now_ms: f64,
    ) -> Result<String, JsValue> {
        let removed = principals(removed_json)?;
        to_json(
            &self
                .inner
                .rotate_vault(vault_id, &removed, meta_json, now(now_ms))
                .map_err(js_error)?,
        )
    }

    /// `POST /api/v1/orgs/{orgId}/groups` body. `members_json` is a JSON
    /// array of account IDs.
    #[wasm_bindgen(js_name = createGroup)]
    pub fn create_group(
        &mut self,
        org_id: &str,
        meta_json: &str,
        members_json: &str,
        now_ms: f64,
    ) -> Result<String, JsValue> {
        let members: Vec<String> = from_json(members_json)?;
        to_json(
            &self
                .inner
                .create_group(org_id, meta_json, &members, now(now_ms))
                .map_err(js_error)?,
        )
    }

    /// `POST /api/v1/orgs/{orgId}/groups/{groupId}/members` body.
    #[wasm_bindgen(js_name = addGroupMember)]
    pub fn add_group_member(
        &self,
        group_id: &str,
        account_id: &str,
        now_ms: f64,
    ) -> Result<String, JsValue> {
        to_json(
            &self
                .inner
                .add_group_member(group_id, account_id, now(now_ms))
                .map_err(js_error)?,
        )
    }

    /// `POST /api/v1/orgs/{orgId}/groups/{groupId}/rotate` body.
    #[wasm_bindgen(js_name = rotateGroup)]
    pub fn rotate_group(
        &mut self,
        group_id: &str,
        removed_json: &str,
        now_ms: f64,
    ) -> Result<String, JsValue> {
        let removed: Vec<String> = from_json(removed_json)?;
        to_json(
            &self
                .inner
                .rotate_group(group_id, &removed, now(now_ms))
                .map_err(js_error)?,
        )
    }

    #[wasm_bindgen(js_name = hasVaultKey)]
    pub fn has_vault_key(&self, vault_id: &str, key_epoch: f64) -> Result<bool, JsValue> {
        Ok(self.inner.has_vault_key(vault_id, epoch(key_epoch)?))
    }

    /// Encrypts item data with the vault key of `key_epoch` (0 for personal vaults).
    #[wasm_bindgen(js_name = encryptItemAt)]
    pub fn encrypt_item_at(
        &self,
        vault_id: &str,
        key_epoch: f64,
        item_id: &str,
        revision_: f64,
        data_json: &str,
    ) -> Result<String, JsValue> {
        self.inner
            .encrypt_item_at(
                vault_id,
                epoch(key_epoch)?,
                item_id,
                revision(revision_)?,
                data_json,
            )
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = decryptItemAt)]
    pub fn decrypt_item_at(
        &self,
        vault_id: &str,
        key_epoch: f64,
        item_id: &str,
        revision_: f64,
        encrypted: &str,
    ) -> Result<String, JsValue> {
        self.inner
            .decrypt_item_at(
                vault_id,
                epoch(key_epoch)?,
                item_id,
                revision(revision_)?,
                encrypted,
            )
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = encryptVaultMetaAt)]
    pub fn encrypt_vault_meta_at(
        &self,
        vault_id: &str,
        key_epoch: f64,
        meta_json: &str,
    ) -> Result<String, JsValue> {
        self.inner
            .encrypt_vault_meta_at(vault_id, epoch(key_epoch)?, meta_json)
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = decryptVaultMetaAt)]
    pub fn decrypt_vault_meta_at(
        &self,
        vault_id: &str,
        key_epoch: f64,
        encrypted_meta: &str,
    ) -> Result<String, JsValue> {
        self.inner
            .decrypt_vault_meta_at(vault_id, epoch(key_epoch)?, encrypted_meta)
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = encryptOrgMeta)]
    pub fn encrypt_org_meta(
        &self,
        org_id: &str,
        key_epoch: f64,
        meta_json: &str,
    ) -> Result<String, JsValue> {
        self.inner
            .encrypt_org_meta(org_id, epoch(key_epoch)?, meta_json)
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = encryptGroupMeta)]
    pub fn encrypt_group_meta(
        &self,
        org_id: &str,
        group_id: &str,
        key_epoch: f64,
        meta_json: &str,
    ) -> Result<String, JsValue> {
        self.inner
            .encrypt_group_meta(org_id, group_id, epoch(key_epoch)?, meta_json)
            .map_err(js_error)
    }
}

// --- Account recovery, emergency access, device links --------------------------------
//
// See `docs/architecture/recovery.md`. Secret material (recovery keys,
// ephemeral keys, released vault keys) stays inside these objects.

fn recovery_code_error(err: Error) -> JsValue {
    let invalid = err == Error::InvalidRecoveryCode;
    let value = js_error(err);
    if invalid {
        js_sys::Reflect::set(&value, &"name".into(), &"InvalidRecoveryCodeError".into()).ok();
    }
    value
}

fn device_code_error(err: Error) -> JsValue {
    let invalid = err == Error::InvalidDeviceCode;
    let value = js_error(err);
    if invalid {
        js_sys::Reflect::set(&value, &"name".into(), &"InvalidDeviceCodeError".into()).ok();
    }
    value
}

fn seed_from(value: &str) -> Result<zeroize::Zeroizing<[u8; 32]>, JsValue> {
    let bytes = zeroize::Zeroizing::new(encoding::decode(value).map_err(js_error)?);
    let seed: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| JsValue::from(js_sys::Error::new("seed must be 32 bytes")))?;
    Ok(zeroize::Zeroizing::new(seed))
}

/// Generates a new recovery code in display format (`R1-XXXXX-…`).
#[wasm_bindgen(js_name = generateRecoveryCode)]
pub fn generate_recovery_code() -> Result<String, JsValue> {
    Ok(RecoveryCode::generate()
        .map_err(js_error)?
        .to_display_string())
}

/// The normalized display format of a recovery code. Throws an error named
/// `InvalidRecoveryCodeError` if it is incomplete or has a typo.
#[wasm_bindgen(js_name = normalizeRecoveryCode)]
pub fn normalize_recovery_code(input: &str) -> Result<String, JsValue> {
    Ok(RecoveryCode::parse(input)
        .map_err(recovery_code_error)?
        .to_display_string())
}

/// Whether `input` is a complete recovery code (format and checksum).
#[wasm_bindgen(js_name = isRecoveryCode)]
pub fn is_recovery_code(input: &str) -> bool {
    RecoveryCode::is_valid(input)
}

/// The comparison code of a recovery request (4 groups of five digits)
/// for an ephemeral public key (Base64url).
#[wasm_bindgen(js_name = recoveryRequestCode)]
pub fn recovery_request_code(ephemeral_key: &str) -> Result<String, JsValue> {
    Ok(org_recovery::request_code(
        &encoding::decode(ephemeral_key).map_err(js_error)?,
    ))
}

/// Whether `input` has the shape of a device code (`XXXX-XXXX-XXXX-XXXX`).
#[wasm_bindgen(js_name = isDeviceCode)]
pub fn is_device_code(input: &str) -> bool {
    CoreDeviceLinkRequest::is_valid_code(input)
}

/// Keys derived from a recovery code.
#[wasm_bindgen]
pub struct RecoveryKeys(CoreRecoveryKeys);

#[wasm_bindgen]
impl RecoveryKeys {
    /// Throws `InvalidRecoveryCodeError` for a malformed code.
    #[wasm_bindgen(js_name = fromCode)]
    pub fn from_code(code: &str) -> Result<RecoveryKeys, JsValue> {
        let code = RecoveryCode::parse(code).map_err(recovery_code_error)?;
        Ok(Self(code.keys().map_err(js_error)?))
    }
}

#[wasm_bindgen]
impl RegistrationFlow {
    /// Starts registering the OPAQUE record of a recovery code.
    #[wasm_bindgen(js_name = startRecovery)]
    pub fn start_recovery(keys: &RecoveryKeys) -> Result<RegistrationFlow, JsValue> {
        let (flow, request) =
            ClientRegistrationFlow::start(&*keys.0.auth_secret).map_err(js_error)?;
        Ok(Self {
            flow: Some(flow),
            request: encoding::encode(&request),
        })
    }
}

#[wasm_bindgen]
impl LoginFlow {
    /// Starts the recovery-code login.
    #[wasm_bindgen(js_name = startRecovery)]
    pub fn start_recovery(keys: &RecoveryKeys) -> Result<LoginFlow, JsValue> {
        let (flow, request) = ClientLoginFlow::start(&*keys.0.auth_secret).map_err(js_error)?;
        Ok(Self {
            flow: Some(flow),
            request: encoding::encode(&request),
        })
    }
}

#[wasm_bindgen]
impl Keyring {
    /// The account key wrapped for a recovery code (Base64url).
    #[wasm_bindgen(js_name = wrapAccountKeyForRecovery)]
    pub fn wrap_account_key_for_recovery(&self, keys: &RecoveryKeys) -> Result<String, JsValue> {
        self.inner
            .wrap_account_key_for_recovery(&keys.0.wrap_key)
            .map_err(js_error)
    }

    /// Opens the recovery copy of the account key. Throws
    /// `InvalidCredentialsError` for a wrong code.
    #[wasm_bindgen(js_name = unlockWithRecovery)]
    pub fn unlock_with_recovery(
        keys: &RecoveryKeys,
        account_id: &str,
        wrapped_account_key: &str,
    ) -> Result<Keyring, JsValue> {
        let inner =
            CoreKeyring::unlock_with_recovery(&keys.0.wrap_key, account_id, wrapped_account_key)
                .map_err(js_error)?;
        Ok(Self {
            inner,
            encrypted_account_key: None,
        })
    }

    /// `POST /api/v1/orgs/{orgId}/recovery/keys` body.
    #[wasm_bindgen(js_name = createOrgRecoveryKey)]
    pub fn create_org_recovery_key(
        &self,
        org_id: &str,
        key_version: f64,
        now_ms: f64,
    ) -> Result<String, JsValue> {
        to_json(
            &self
                .inner
                .create_org_recovery_key(org_id, epoch(key_version)?, now(now_ms))
                .map_err(js_error)?,
        )
    }

    /// Verifies `GET /api/v1/orgs/{orgId}/recovery` (`key`). Returns JSON
    /// `{ orgId, keyVersion, fingerprint, creatorId, admins, canApprove }`.
    #[wasm_bindgen(js_name = verifyOrgRecovery)]
    pub fn verify_org_recovery(&self, org_id: &str, record_json: &str) -> Result<String, JsValue> {
        let record = from_json(record_json)?;
        to_json(
            &self
                .inner
                .verify_org_recovery(org_id, &record)
                .map_err(js_error)?,
        )
    }

    /// `POST /api/v1/orgs/{orgId}/recovery/grants` body.
    #[wasm_bindgen(js_name = grantOrgRecovery)]
    pub fn grant_org_recovery(
        &self,
        org_id: &str,
        record_json: &str,
        admin_id: &str,
        now_ms: f64,
    ) -> Result<String, JsValue> {
        let record = from_json(record_json)?;
        to_json(
            &self
                .inner
                .grant_org_recovery(org_id, &record, admin_id, now(now_ms))
                .map_err(js_error)?,
        )
    }

    /// `PUT /api/v1/orgs/{orgId}/recovery/escrow` body (opt in).
    #[wasm_bindgen(js_name = enrollOrgRecovery)]
    pub fn enroll_org_recovery(
        &self,
        org_id: &str,
        record_json: &str,
        now_ms: f64,
    ) -> Result<String, JsValue> {
        let record = from_json(record_json)?;
        to_json(
            &self
                .inner
                .enroll_org_recovery(org_id, &record, now(now_ms))
                .map_err(js_error)?,
        )
    }

    /// `POST .../recovery/requests/{id}/approve` body. Compare the request
    /// code with the member first.
    #[wasm_bindgen(js_name = approveOrgRecovery)]
    pub fn approve_org_recovery(
        &self,
        record_json: &str,
        request_json: &str,
        now_ms: f64,
    ) -> Result<String, JsValue> {
        let record = from_json(record_json)?;
        let request = from_json(request_json)?;
        to_json(
            &self
                .inner
                .approve_org_recovery(&record, &request, now(now_ms))
                .map_err(js_error)?,
        )
    }

    /// `POST /api/v1/emergency/grants/{id}/confirm` body. Look the grantee
    /// up in the key directory first. `vault_ids_json` is a JSON array.
    #[wasm_bindgen(js_name = sealEmergencyAccess)]
    pub fn seal_emergency_access(
        &self,
        grant_id: &str,
        grantee_id: &str,
        wait_days: f64,
        vault_ids_json: &str,
        version: f64,
        now_ms: f64,
    ) -> Result<String, JsValue> {
        let vault_ids: Vec<String> = from_json(vault_ids_json)?;
        to_json(
            &self
                .inner
                .seal_emergency_access(
                    grant_id,
                    grantee_id,
                    u64::from(epoch(wait_days)?),
                    &vault_ids,
                    u64::from(epoch(version)?),
                    now(now_ms),
                )
                .map_err(js_error)?,
        )
    }

    /// `{ grantId, grantorId, granteeId, waitDays, vaultIds, version }` of an
    /// own grant.
    #[wasm_bindgen(js_name = emergencyGrantInfo)]
    pub fn emergency_grant_info(&self, grant: &str, signature: &str) -> Result<String, JsValue> {
        to_json(
            &self
                .inner
                .emergency_grant_info(grant, signature)
                .map_err(js_error)?,
        )
    }

    /// Whether an own grant must be sealed again (new key epochs, vaults
    /// gone, own key changed).
    #[wasm_bindgen(js_name = emergencyResealNeeded)]
    pub fn emergency_reseal_needed(
        &self,
        grant: &str,
        signature: &str,
        vault_ids_json: &str,
    ) -> Result<bool, JsValue> {
        let vault_ids: Vec<String> = from_json(vault_ids_json)?;
        self.inner
            .emergency_reseal_needed(grant, signature, &vault_ids)
            .map_err(js_error)
    }

    /// Opens released emergency access. Look the grantor up in the key
    /// directory first.
    #[wasm_bindgen(js_name = openEmergencyAccess)]
    pub fn open_emergency_access(
        &self,
        grant: &str,
        signature: &str,
        sealed_keys: &str,
    ) -> Result<EmergencyKeys, JsValue> {
        Ok(EmergencyKeys(
            self.inner
                .open_emergency_access(grant, signature, sealed_keys)
                .map_err(js_error)?,
        ))
    }
}

/// Vault keys released through emergency access.
#[wasm_bindgen]
pub struct EmergencyKeys(CoreEmergencyKeys);

#[wasm_bindgen]
impl EmergencyKeys {
    #[wasm_bindgen(getter, js_name = grantorId)]
    pub fn grantor_id(&self) -> String {
        self.0.grantor_id.clone()
    }

    /// The vault IDs as a JSON array.
    #[wasm_bindgen(js_name = vaultIds)]
    pub fn vault_ids(&self) -> Result<String, JsValue> {
        to_json(&self.0.vault_ids())
    }

    #[wasm_bindgen(js_name = decryptVaultMeta)]
    pub fn decrypt_vault_meta(
        &self,
        vault_id: &str,
        key_epoch: f64,
        encrypted: &str,
    ) -> Result<String, JsValue> {
        self.0
            .decrypt_vault_meta(vault_id, epoch(key_epoch)?, encrypted)
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = decryptItem)]
    pub fn decrypt_item(
        &self,
        vault_id: &str,
        key_epoch: f64,
        item_id: &str,
        revision_: f64,
        encrypted: &str,
    ) -> Result<String, JsValue> {
        self.0
            .decrypt_item(
                vault_id,
                epoch(key_epoch)?,
                item_id,
                revision(revision_)?,
                encrypted,
            )
            .map_err(js_error)
    }
}

/// The ephemeral key of a device that asks its organization for recovery.
#[wasm_bindgen]
pub struct RecoveryRequestKey(CoreRecoveryRequestKey);

#[wasm_bindgen]
impl RecoveryRequestKey {
    pub fn generate() -> Result<RecoveryRequestKey, JsValue> {
        Ok(Self(CoreRecoveryRequestKey::generate().map_err(js_error)?))
    }

    /// Restores a key saved with `seed` (Base64url).
    #[wasm_bindgen(js_name = fromSeed)]
    pub fn from_seed(seed: &str) -> Result<RecoveryRequestKey, JsValue> {
        Ok(Self(CoreRecoveryRequestKey::from_seed(&*seed_from(seed)?)))
    }

    /// The private seed (Base64url), to keep the request across reloads on
    /// this device. It is useless once the request expired.
    #[wasm_bindgen(getter)]
    pub fn seed(&self) -> String {
        encoding::encode(self.0.seed())
    }

    #[wasm_bindgen(getter, js_name = publicKey)]
    pub fn public_key(&self) -> String {
        encoding::encode(&self.0.public_key())
    }

    /// The code to read to the approving admin.
    #[wasm_bindgen(getter, js_name = requestCode)]
    pub fn request_code(&self) -> String {
        self.0.request_code()
    }

    /// Opens the account key from the `approved` object of
    /// `POST /api/v1/recovery/org/status`.
    pub fn open(&self, approved_json: &str) -> Result<Keyring, JsValue> {
        let approved = from_json(approved_json)?;
        Ok(Keyring {
            inner: self.0.open(&approved).map_err(js_error)?,
            encrypted_account_key: None,
        })
    }
}

/// The signed-in device's side of adding a device by code.
#[wasm_bindgen]
pub struct DeviceLinkOffer(CoreDeviceLinkOffer);

#[wasm_bindgen]
impl DeviceLinkOffer {
    /// Adds a secret to the server's short ID.
    #[wasm_bindgen(constructor)]
    pub fn new(short_id: &str) -> Result<DeviceLinkOffer, JsValue> {
        Ok(Self(
            CoreDeviceLinkOffer::new(short_id).map_err(device_code_error)?,
        ))
    }

    /// `XXXX-XXXX-XXXX-XXXX`, to show and put into the QR code.
    #[wasm_bindgen(getter)]
    pub fn code(&self) -> String {
        self.0.code()
    }

    /// Checks the claim (Base64url key and MAC) and seals `payload_json`.
    /// Throws `InvalidDeviceCodeError` if the claim did not come from a
    /// device that knows the code.
    pub fn seal(
        &self,
        ephemeral_key: &str,
        mac: &str,
        payload_json: &str,
    ) -> Result<String, JsValue> {
        self.0
            .seal(
                &encoding::decode(ephemeral_key).map_err(js_error)?,
                &encoding::decode(mac).map_err(js_error)?,
                payload_json,
            )
            .map_err(device_code_error)
    }
}

/// The new device's side of adding a device by code.
#[wasm_bindgen]
pub struct DeviceLinkRequest(CoreDeviceLinkRequest);

#[wasm_bindgen]
impl DeviceLinkRequest {
    /// Throws `InvalidDeviceCodeError` for a malformed code.
    #[wasm_bindgen(constructor)]
    pub fn new(code: &str) -> Result<DeviceLinkRequest, JsValue> {
        Ok(Self(
            CoreDeviceLinkRequest::new(code).map_err(device_code_error)?,
        ))
    }

    #[wasm_bindgen(getter, js_name = shortId)]
    pub fn short_id(&self) -> String {
        self.0.short_id().to_owned()
    }

    #[wasm_bindgen(getter, js_name = publicKey)]
    pub fn public_key(&self) -> String {
        encoding::encode(&self.0.public_key())
    }

    #[wasm_bindgen(getter)]
    pub fn mac(&self) -> String {
        encoding::encode(self.0.mac())
    }

    /// Opens the sealed payload (JSON).
    pub fn open(&self, sealed: &str) -> Result<String, JsValue> {
        self.0.open(sealed).map_err(js_error)
    }
}

/// A device without a session asking a signed-in browser for the account
/// details (the side `pbx login` takes; see `CliLoginApproval`).
#[wasm_bindgen]
pub struct CliLoginRequest(CoreCliLoginRequest);

#[wasm_bindgen]
impl CliLoginRequest {
    /// A fresh ID, secret and ephemeral key. The device name is cleaned like
    /// the server stores it.
    #[wasm_bindgen(constructor)]
    pub fn new(device_name: &str) -> Result<CliLoginRequest, JsValue> {
        Ok(Self(
            CoreCliLoginRequest::new(device_name).map_err(js_error)?,
        ))
    }

    #[wasm_bindgen(getter)]
    pub fn id(&self) -> String {
        self.0.id().to_owned()
    }

    #[wasm_bindgen(getter, js_name = deviceName)]
    pub fn device_name(&self) -> String {
        self.0.device_name().to_owned()
    }

    #[wasm_bindgen(getter, js_name = publicKey)]
    pub fn public_key(&self) -> String {
        encoding::encode(&self.0.public_key())
    }

    #[wasm_bindgen(getter)]
    pub fn mac(&self) -> String {
        encoding::encode(self.0.mac())
    }

    /// `#/cli-login/{id}#{secret}`, to append to the web vault's URL.
    #[wasm_bindgen(getter, js_name = linkFragment)]
    pub fn link_fragment(&self) -> String {
        self.0.link_fragment()
    }

    /// Opens the sealed payload (JSON).
    pub fn open(&self, sealed: &str) -> Result<String, JsValue> {
        self.0.open(sealed).map_err(js_error)
    }
}

/// The signed-in browser's side of a sign-in requested by another device
/// (`pbx login`): built from the ID and secret in the link's fragment
/// (`#/cli-login/{id}#{secret}`).
#[wasm_bindgen]
pub struct CliLoginApproval(CoreCliLoginApproval);

#[wasm_bindgen]
impl CliLoginApproval {
    /// Throws `InvalidDeviceCodeError` for a malformed ID or secret.
    #[wasm_bindgen(constructor)]
    pub fn new(id: &str, secret: &str) -> Result<CliLoginApproval, JsValue> {
        Ok(Self(
            CoreCliLoginApproval::new(id, secret).map_err(device_code_error)?,
        ))
    }

    #[wasm_bindgen(getter)]
    pub fn id(&self) -> String {
        self.0.id().to_owned()
    }

    /// Checks the key and device name the server returned (Base64url key
    /// and MAC). Throws `InvalidDeviceCodeError` if they are not the ones
    /// the requesting device registered.
    pub fn verify(&self, ephemeral_key: &str, device_name: &str, mac: &str) -> Result<(), JsValue> {
        self.0
            .verify(
                &encoding::decode(ephemeral_key).map_err(device_code_error)?,
                device_name,
                &encoding::decode(mac).map_err(device_code_error)?,
            )
            .map_err(device_code_error)
    }

    /// Verifies the request and seals `payload_json` to its key.
    pub fn seal(
        &self,
        ephemeral_key: &str,
        device_name: &str,
        mac: &str,
        payload_json: &str,
    ) -> Result<String, JsValue> {
        self.0
            .seal(
                &encoding::decode(ephemeral_key).map_err(device_code_error)?,
                device_name,
                &encoding::decode(mac).map_err(device_code_error)?,
                payload_json,
            )
            .map_err(device_code_error)
    }
}

// --- Trusted devices (SSO unlock) ------------------------------------------------

/// The approval code (4 groups of five digits) of a device public key
/// (Base64url), to compare with the new device before approving it.
#[wasm_bindgen(js_name = trustedDeviceApprovalCode)]
pub fn trusted_device_approval_code(public_key: &str) -> Result<String, JsValue> {
    Ok(passbox_core::trusted_device::approval_code(
        &encoding::decode(public_key).map_err(js_error)?,
    ))
}

#[wasm_bindgen]
impl Keyring {
    /// Seals the account key to a device's public key (Base64url) and signs
    /// the grant. `approvedBy` is this device's trusted device ID, or empty
    /// when a device trusts itself. Returns JSON `{ deviceId, publicKey,
    /// sealedKey, grant, grantSignature }`.
    #[wasm_bindgen(js_name = trustDevice)]
    pub fn trust_device(
        &self,
        device_id: &str,
        public_key: &str,
        approved_by: &str,
        now_ms: f64,
    ) -> Result<String, JsValue> {
        to_json(
            &self
                .inner
                .trust_device(
                    device_id,
                    &encoding::decode(public_key).map_err(js_error)?,
                    approved_by,
                    now_ms as i64,
                )
                .map_err(js_error)?,
        )
    }
}

/// A trusted device's key pair. Keep its `seed` only in protected storage.
#[wasm_bindgen]
pub struct TrustedDeviceKey(passbox_core::trusted_device::TrustedDeviceKey);

#[wasm_bindgen]
impl TrustedDeviceKey {
    pub fn generate() -> Result<TrustedDeviceKey, JsValue> {
        Ok(Self(
            passbox_core::trusted_device::TrustedDeviceKey::generate().map_err(js_error)?,
        ))
    }

    /// Restores a key from its seed (Base64url).
    #[wasm_bindgen(js_name = fromSeed)]
    pub fn from_seed(seed: &str) -> Result<TrustedDeviceKey, JsValue> {
        Ok(Self(
            passbox_core::trusted_device::TrustedDeviceKey::from_seed(&*seed_from(seed)?),
        ))
    }

    /// The private seed (Base64url), to store wrapped on this device.
    #[wasm_bindgen(getter)]
    pub fn seed(&self) -> String {
        encoding::encode(self.0.seed())
    }

    #[wasm_bindgen(getter, js_name = publicKey)]
    pub fn public_key(&self) -> String {
        encoding::encode(&self.0.public_key())
    }

    /// The code to compare with the approving device.
    #[wasm_bindgen(getter, js_name = approvalCode)]
    pub fn approval_code(&self) -> String {
        self.0.approval_code()
    }

    /// Opens and verifies the account key from the `unlock` object of
    /// `POST /api/v1/sso/unlock`. The keyring has the account's key pairs.
    pub fn unlock(&self, unlock_json: &str) -> Result<Keyring, JsValue> {
        let unlock = from_json(unlock_json)?;
        Ok(Keyring {
            inner: self.0.unlock(&unlock).map_err(js_error)?,
            encrypted_account_key: None,
        })
    }
}

// --- Organization policies and audit log ------------------------------------------

/// Policies and signed client events. The verified policies come
/// with every `applySharing` result (`view.policies`,
/// `view.effectivePolicy`); these functions sign new versions and verify
/// single records.
#[wasm_bindgen]
impl Keyring {
    /// `PUT /api/v1/orgs/{orgId}/policy` body: the next version of the
    /// organization's policy with `rules_json` (`PolicyRules`), signed by
    /// this account (owners and admins). Sync first.
    #[wasm_bindgen(js_name = signOrgPolicy)]
    pub fn sign_org_policy(
        &self,
        org_id: &str,
        rules_json: &str,
        now_ms: f64,
    ) -> Result<String, JsValue> {
        let rules = from_json(rules_json)?;
        to_json(
            &self
                .inner
                .sign_org_policy(org_id, &rules, now(now_ms))
                .map_err(js_error)?,
        )
    }

    /// Verifies one policy record (for example from the history) against the
    /// verified roster without changing pins. Returns `OrgPolicyView` JSON.
    #[wasm_bindgen(js_name = verifyOrgPolicy)]
    pub fn verify_org_policy(&self, org_id: &str, record_json: &str) -> Result<String, JsValue> {
        let record = from_json(record_json)?;
        to_json(
            &self
                .inner
                .verify_org_policy(org_id, &record)
                .map_err(js_error)?,
        )
    }

    /// The policy in force for an organization (`OrgPolicyView` JSON or
    /// `null`).
    #[wasm_bindgen(js_name = orgPolicy)]
    pub fn org_policy(&self, org_id: &str) -> Result<String, JsValue> {
        to_json(&self.inner.org_policy(org_id))
    }

    /// The combination of every policy this account is bound by.
    #[wasm_bindgen(js_name = effectivePolicy)]
    pub fn effective_policy(&self) -> Result<String, JsValue> {
        to_json(self.inner.effective_policy())
    }

    /// Signs client events (JSON array of `{ action, vaultId, itemId, field,
    /// occurredAt }`) for `POST /api/v1/orgs/{orgId}/audit/client-events`.
    #[wasm_bindgen(js_name = signClientEvents)]
    pub fn sign_client_events(&self, org_id: &str, events_json: &str) -> Result<String, JsValue> {
        let events: Vec<passbox_core::audit::ClientEventInput> = from_json(events_json)?;
        to_json(
            &self
                .inner
                .sign_client_events(org_id, &events)
                .map_err(js_error)?,
        )
    }
}

/// Checks an exported audit log (JSON array of entries, oldest first).
/// `anchor` is the hash the first entry must link to ("" for entry 1, the
/// `head.prunedHash` of the export, or the head of an earlier export);
/// `undefined` accepts any. Returns `ChainCheck` JSON.
#[wasm_bindgen(js_name = verifyAuditChain)]
pub fn verify_audit_chain(records_json: &str, anchor: Option<String>) -> Result<String, JsValue> {
    let records: Vec<passbox_core::audit::AuditRecord> = from_json(records_json)?;
    to_json(&passbox_core::audit::verify_chain(
        &records,
        anchor.as_deref(),
    ))
}

/// Checks the signature of a client-reported audit event against the
/// account's public bundle. Returns the event as JSON.
#[wasm_bindgen(js_name = verifyClientEvent)]
pub fn verify_client_event(
    bundle: &str,
    bundle_signature: &str,
    event: &str,
    signature: &str,
) -> Result<String, JsValue> {
    let bundle =
        passbox_core::identity::SignedBundle::parse(bundle, bundle_signature).map_err(js_error)?;
    let event = passbox_core::audit::verify_client_event(
        &bundle,
        &passbox_core::audit::SignedClientEvent {
            event: event.to_owned(),
            signature: signature.to_owned(),
        },
    )
    .map_err(js_error)?;
    to_json(&serde_json::json!({
        "orgId": event.org_id,
        "accountId": event.account_id,
        "action": event.action,
        "vaultId": event.vault_id,
        "itemId": event.item_id,
        "field": event.field,
        "occurredAt": event.occurred_at,
    }))
}

/// Whether a share link with this lifetime (days) and view limit (0 = no
/// limit) is allowed by `rules_json` (`PolicyRules`). Returns `undefined`
/// if allowed, otherwise the reason.
#[wasm_bindgen(js_name = shareLinkProblem)]
pub fn share_link_problem(
    rules_json: &str,
    days: u32,
    max_views: u32,
) -> Result<Option<String>, JsValue> {
    let rules: passbox_core::policy::PolicyRules = from_json(rules_json)?;
    Ok(rules
        .check_share_link(days, max_views)
        .err()
        .map(|e| e.to_string()))
}

// --- Service accounts and agent grants -----------------------------------------------
//
// See `docs/architecture/service-accounts.md` and `docs/architecture/ai-agents.md`.

fn permission(value: &str) -> Result<passbox_core::service_account::Permission, JsValue> {
    passbox_core::service_account::Permission::parse(value).map_err(js_error)
}

#[wasm_bindgen]
impl Keyring {
    /// Creates a service account owned by this account. Returns JSON `{ id,
    /// token, publicKey, publicKeySignature, encryptedPrivate, authHash }`.
    /// Show `token` once and do not store it; everything else is for
    /// `POST /api/v1/service-accounts`.
    #[wasm_bindgen(js_name = createServiceAccount)]
    pub fn create_service_account(&self, now_ms: f64) -> Result<String, JsValue> {
        let created = self
            .inner
            .create_service_account(now(now_ms))
            .map_err(js_error)?;
        Ok(serde_json::json!({
            "id": created.id,
            "token": created.token.as_str(),
            "publicKey": created.public_key,
            "publicKeySignature": created.public_key_signature,
            "encryptedPrivate": created.encrypted_private,
            "authHash": created.auth_hash,
        })
        .to_string())
    }

    /// Seals a vault key for a service account this account owns, after
    /// checking the owner's signature on its public key. `permission` is
    /// `read` or `write`. Returns the grant JSON for the server.
    #[wasm_bindgen(js_name = grantServiceAccount)]
    pub fn grant_service_account(
        &self,
        public_key: &str,
        public_key_signature: &str,
        vault_id: &str,
        key_epoch: f64,
        permission_name: &str,
        now_ms: f64,
    ) -> Result<String, JsValue> {
        let upload = self
            .inner
            .grant_service_account(
                public_key,
                public_key_signature,
                vault_id,
                epoch(key_epoch)?,
                permission(permission_name)?,
                now(now_ms),
            )
            .map_err(js_error)?;
        Ok(serde_json::json!({
            "vaultId": upload.vault_id,
            "keyEpoch": upload.key_epoch,
            "permission": upload.permission.as_str(),
            "sealedKey": upload.sealed_key,
            "grant": upload.grant,
            "grantSignature": upload.grant_signature,
        })
        .to_string())
    }

    /// Signs the decision on an agent grant request (Base64url bytes as
    /// relayed by the server). Show the person `parseAgentRequest(request)`
    /// first. `allowReveal` is the person's explicit tick "Allow revealing
    /// the value to the agent" (refused when the request does not ask for
    /// `reveal` or an organization's policy forbids it). Returns JSON
    /// `{ decision, decisionSignature }`.
    #[wasm_bindgen(js_name = decideAgentGrant)]
    pub fn decide_agent_grant(
        &self,
        request: &str,
        approved: bool,
        max_uses: f64,
        now_ms: f64,
        allow_reveal: Option<bool>,
    ) -> Result<String, JsValue> {
        if max_uses.fract() != 0.0 || !(0.0..=1e9).contains(&max_uses) {
            return Err(js_sys::Error::new("maxUses must be a non-negative integer").into());
        }
        let (decision, signature) = self
            .inner
            .decide_agent_grant_with_reveal(
                request,
                approved,
                allow_reveal.unwrap_or(false),
                max_uses as u64,
                now(now_ms),
            )
            .map_err(js_error)?;
        Ok(serde_json::json!({ "decision": decision, "decisionSignature": signature }).to_string())
    }
}

/// Parses an agent grant request for display. Returns JSON `{ id, code,
/// principalKind, principalId, clientName, onBehalfOf, items: [{itemId,
/// vaultId}], actions, commands, paths, reason, ttlMs, maxUses, createdAt }`.
/// `reason` and `clientName` come from the agent and are untrusted.
#[wasm_bindgen(js_name = parseAgentRequest)]
pub fn parse_agent_request(request: &str) -> Result<String, JsValue> {
    let r = passbox_core::agent_grant::GrantRequest::decode(request).map_err(js_error)?;
    let items: Vec<serde_json::Value> = r
        .items
        .iter()
        .map(|i| serde_json::json!({ "itemId": i.item_id, "vaultId": i.vault_id }))
        .collect();
    Ok(serde_json::json!({
        "id": r.id,
        "code": r.code(),
        "principalKind": r.principal_kind.as_str(),
        "principalId": r.principal_id,
        "clientName": r.client_name,
        "onBehalfOf": r.on_behalf_of,
        "items": items,
        "actions": r.actions,
        "commands": r.commands,
        "paths": r.paths,
        "reason": r.reason,
        "ttlMs": r.ttl_ms,
        "maxUses": r.max_uses,
        "createdAt": r.created_at,
    })
    .to_string())
}

// --- Attachments, share links, SSH keys -------------------------------------------

/// A new random file key (Base64url), stored in the item with the
/// attachment's metadata.
#[wasm_bindgen(js_name = generateFileKey)]
pub fn generate_file_key() -> Result<String, JsValue> {
    passbox_core::file_crypto::generate_key().map_err(js_error)
}

/// Encrypts a file chunk by chunk (see `passbox_core::file_crypto`). Write
/// `header()` first, then every chunk of `chunkSize` bytes; the last chunk
/// may be shorter and must be marked `last`.
#[wasm_bindgen]
pub struct FileEncryptor(passbox_core::file_crypto::FileEncryptor);

#[wasm_bindgen]
impl FileEncryptor {
    #[wasm_bindgen(constructor)]
    pub fn new(key: &str, file_id: &str) -> Result<FileEncryptor, JsValue> {
        let key = passbox_core::file_crypto::parse_key(key).map_err(js_error)?;
        passbox_core::file_crypto::FileEncryptor::new(&key, file_id)
            .map(FileEncryptor)
            .map_err(js_error)
    }

    pub fn header(&self) -> Vec<u8> {
        self.0.header().to_vec()
    }

    #[wasm_bindgen(getter, js_name = chunkSize)]
    pub fn chunk_size(&self) -> usize {
        self.0.chunk_size()
    }

    #[wasm_bindgen(js_name = encryptChunk)]
    pub fn encrypt_chunk(&mut self, plaintext: &[u8], last: bool) -> Result<Vec<u8>, JsValue> {
        self.0.encrypt_chunk(plaintext, last).map_err(js_error)
    }
}

/// Decrypts a blob chunk by chunk. Pass the first `fileHeaderLength()` bytes to
/// the constructor, then chunks of `encryptedChunkSize` bytes (the last
/// one may be shorter and must be marked `last`), then call `finish()`.
#[wasm_bindgen]
pub struct FileDecryptor(passbox_core::file_crypto::FileDecryptor);

#[wasm_bindgen]
impl FileDecryptor {
    #[wasm_bindgen(constructor)]
    pub fn new(key: &str, file_id: &str, header: &[u8]) -> Result<FileDecryptor, JsValue> {
        let key = passbox_core::file_crypto::parse_key(key).map_err(js_error)?;
        passbox_core::file_crypto::FileDecryptor::new(&key, file_id, header)
            .map(FileDecryptor)
            .map_err(js_error)
    }

    #[wasm_bindgen(getter, js_name = encryptedChunkSize)]
    pub fn encrypted_chunk_size(&self) -> usize {
        self.0.encrypted_chunk_size()
    }

    #[wasm_bindgen(js_name = decryptChunk)]
    pub fn decrypt_chunk(&mut self, ciphertext: &[u8], last: bool) -> Result<Vec<u8>, JsValue> {
        self.0.decrypt_chunk(ciphertext, last).map_err(js_error)
    }

    pub fn finish(&self) -> Result<(), JsValue> {
        self.0.finish().map_err(js_error)
    }
}

/// Length of the header of an encrypted file.
#[wasm_bindgen(js_name = fileHeaderLength)]
pub fn file_header_length() -> usize {
    passbox_core::file_crypto::HEADER_LEN
}

/// Size of the encrypted blob for a file of `plain_len` bytes.
#[wasm_bindgen(js_name = encryptedFileLength)]
pub fn encrypted_file_length(plain_len: f64) -> f64 {
    passbox_core::file_crypto::encrypted_len(plain_len.max(0.0) as u64) as f64
}

/// Encrypts a snapshot for a new share link. Returns JSON `{ key, blob,
/// authHash, salt }`; `key` goes only into the link's fragment.
#[wasm_bindgen(js_name = shareLinkCreate)]
pub fn share_link_create(
    link_id: &str,
    snapshot: &str,
    passphrase: Option<String>,
) -> Result<String, JsValue> {
    let link = passbox_core::share_link::create(link_id, snapshot, passphrase.as_deref())
        .map_err(js_error)?;
    Ok(serde_json::json!({
        "key": link.key,
        "blob": link.blob,
        "authHash": link.auth_hash,
        "salt": link.salt,
    })
    .to_string())
}

/// The access token that opens a link on the server.
#[wasm_bindgen(js_name = shareLinkAuthToken)]
pub fn share_link_auth_token(
    link_id: &str,
    key: &str,
    passphrase: Option<String>,
    salt: Option<String>,
) -> Result<String, JsValue> {
    passbox_core::share_link::auth_token(link_id, key, passphrase.as_deref(), salt.as_deref())
        .map_err(js_error)
}

/// Decrypts a link's snapshot.
#[wasm_bindgen(js_name = shareLinkOpen)]
pub fn share_link_open(
    link_id: &str,
    key: &str,
    passphrase: Option<String>,
    salt: Option<String>,
    blob: &str,
) -> Result<String, JsValue> {
    passbox_core::share_link::open(link_id, key, passphrase.as_deref(), salt.as_deref(), blob)
        .map_err(js_error)
}

/// A new Ed25519 SSH key. Returns JSON `{ privateKey, publicKey, fingerprint }`.
#[wasm_bindgen(js_name = sshGenerateEd25519)]
pub fn ssh_generate_ed25519(comment: &str) -> Result<String, JsValue> {
    let pair = passbox_core::ssh::generate_ed25519(comment).map_err(js_error)?;
    Ok(serde_json::json!({
        "privateKey": pair.private_key,
        "publicKey": pair.public_key,
        "fingerprint": pair.fingerprint,
    })
    .to_string())
}

/// The public key and fingerprint of an OpenSSH Ed25519 private key.
/// Returns JSON `{ publicKey, fingerprint }`.
#[wasm_bindgen(js_name = sshPublicKey)]
pub fn ssh_public_key(private_key: &str) -> Result<String, JsValue> {
    let (public_key, fingerprint) =
        passbox_core::ssh::public_key_of(private_key).map_err(js_error)?;
    Ok(serde_json::json!({ "publicKey": public_key, "fingerprint": fingerprint }).to_string())
}

/// The `SHA256:` fingerprint of an SSH public key line.
#[wasm_bindgen(js_name = sshFingerprint)]
pub fn ssh_fingerprint(public_key: &str) -> Result<String, JsValue> {
    passbox_core::ssh::fingerprint(public_key).map_err(js_error)
}
