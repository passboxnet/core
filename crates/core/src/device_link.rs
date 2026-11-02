//! Adding a device with a code from a signed-in device.
//!
//! The signed-in device asks the server for a link (the server picks a
//! 4-character `short_id`), adds a 12-character secret and shows
//! `XXXX-XXXX-XXXX-XXXX` (also as a QR code). The secret never reaches the
//! server. The new device types or scans the code, creates an ephemeral
//! X-Wing key pair and claims the link with
//!
//! ```text
//! mac = HMAC-SHA256(HKDF-SHA256(ikm = secret, salt = short_id, info = "passbox/v1/device-link"),
//!                   canonical("passbox/v1/device-link-claim", short_id, ephemeral_pk))
//! ```
//!
//! The signed-in device checks the MAC, so a server that swaps in its own
//! ephemeral key is detected (it would have to guess 60 secret bits within
//! the link's lifetime), shows the new device's name and, after the user
//! approves, seals the account's email, ID and Secret Key to the ephemeral
//! key (purpose `device-link`). The master password is never transferred:
//! the new device still asks for it.

use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::canon::Writer;
use crate::identity::{self, EncryptionKey};
use crate::keyring::ensure_json;
use crate::recovery::ephemeral_key_hash;
use crate::{Error, Result, encoding, random};

pub const PURPOSE: &str = "device-link";
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
pub const SHORT_ID_LEN: usize = 4;
const SECRET_LEN: usize = 12;

fn normalize(input: &str) -> Zeroizing<String> {
    Zeroizing::new(
        input
            .chars()
            .filter(|c| *c != '-' && !c.is_whitespace())
            .map(|c| match c.to_ascii_uppercase() {
                'I' | 'L' => '1',
                'O' => '0',
                other => other,
            })
            .collect(),
    )
}

/// Whether `value` is a valid short ID (4 Crockford Base32 characters).
pub fn is_short_id(value: &str) -> bool {
    value.len() == SHORT_ID_LEN && value.bytes().all(|b| ALPHABET.contains(&b))
}

/// A random short ID, for the server.
pub fn new_short_id() -> Result<String> {
    random_chars(SHORT_ID_LEN).map(|s| s.to_string())
}

fn random_chars(len: usize) -> Result<Zeroizing<String>> {
    let mut out = Zeroizing::new(String::with_capacity(len));
    for _ in 0..len {
        out.push(char::from(ALPHABET[random::below(32)? as usize]));
    }
    Ok(out)
}

fn mac_key(short_id: &str, secret: &str) -> Result<Zeroizing<[u8; 32]>> {
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(short_id.as_bytes()), secret.as_bytes())
        .expand(b"passbox/v1/device-link", key.as_mut())
        .map_err(|e| Error::Kdf(e.to_string()))?;
    Ok(key)
}

fn claim_mac(short_id: &str, secret: &str, ephemeral_pk: &[u8]) -> Result<Vec<u8>> {
    let key = mac_key(short_id, secret)?;
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key.as_ref())
        .expect("HMAC accepts any key length");
    mac.update(
        &Writer::new("passbox/v1/device-link-claim")
            .str(short_id)
            .bytes(ephemeral_pk)
            .finish(),
    );
    Ok(mac.finalize().into_bytes().to_vec())
}

fn context(short_id: &str) -> Vec<u8> {
    Writer::new("passbox/v1/seal-context/device-link")
        .str(short_id)
        .finish()
}

fn display(short_id: &str, secret: &str) -> String {
    let all = format!("{short_id}{secret}");
    all.as_bytes()
        .chunks(4)
        .map(|c| core::str::from_utf8(c).expect("ASCII"))
        .collect::<Vec<_>>()
        .join("-")
}

/// The signed-in device's side.
pub struct DeviceLinkOffer {
    short_id: String,
    secret: Zeroizing<String>,
}

impl core::fmt::Debug for DeviceLinkOffer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DeviceLinkOffer")
            .field("short_id", &self.short_id)
            .finish_non_exhaustive()
    }
}

impl DeviceLinkOffer {
    /// Adds a fresh secret to the server's short ID.
    pub fn new(short_id: &str) -> Result<Self> {
        if !is_short_id(short_id) {
            return Err(Error::InvalidDeviceCode);
        }
        Ok(Self {
            short_id: short_id.to_owned(),
            secret: random_chars(SECRET_LEN)?,
        })
    }

    /// `XXXX-XXXX-XXXX-XXXX`, to show and to put into the QR code.
    pub fn code(&self) -> String {
        display(&self.short_id, &self.secret)
    }

    /// Checks that the claim comes from a device that knows the code.
    pub fn verify_claim(&self, ephemeral_pk: &[u8], mac: &[u8]) -> Result<()> {
        let key = mac_key(&self.short_id, &self.secret)?;
        let mut check = <Hmac<Sha256> as KeyInit>::new_from_slice(key.as_ref())
            .expect("HMAC accepts any key length");
        check.update(
            &Writer::new("passbox/v1/device-link-claim")
                .str(&self.short_id)
                .bytes(ephemeral_pk)
                .finish(),
        );
        check
            .verify_slice(mac)
            .map_err(|_| Error::InvalidDeviceCode)
    }

    /// Verifies the claim and seals `payload_json` (email, account ID and
    /// Secret Key) to the new device's ephemeral key.
    pub fn seal(&self, ephemeral_pk: &[u8], mac: &[u8], payload_json: &str) -> Result<String> {
        self.verify_claim(ephemeral_pk, mac)?;
        ensure_json(payload_json.as_bytes())?;
        let sealed = identity::seal(
            ephemeral_pk,
            &ephemeral_key_hash(ephemeral_pk),
            PURPOSE,
            &context(&self.short_id),
            payload_json.as_bytes(),
        )?;
        Ok(encoding::encode(&sealed))
    }
}

/// The new device's side.
pub struct DeviceLinkRequest {
    short_id: String,
    key: EncryptionKey,
    mac: Vec<u8>,
}

impl core::fmt::Debug for DeviceLinkRequest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DeviceLinkRequest")
            .field("short_id", &self.short_id)
            .finish_non_exhaustive()
    }
}

impl DeviceLinkRequest {
    /// Parses the code shown on the signed-in device (typing mistakes
    /// such as `O`/`0` are forgiven) and creates an ephemeral key.
    pub fn new(code: &str) -> Result<Self> {
        let compact = normalize(code);
        if compact.len() != SHORT_ID_LEN + SECRET_LEN
            || !compact.bytes().all(|b| ALPHABET.contains(&b))
        {
            return Err(Error::InvalidDeviceCode);
        }
        let (short_id, secret) = compact.split_at(SHORT_ID_LEN);
        let key = EncryptionKey::generate()?;
        let mac = claim_mac(short_id, secret, &key.public_key())?;
        Ok(Self {
            short_id: short_id.to_owned(),
            key,
            mac,
        })
    }

    /// Whether `code` has the shape of a device code.
    pub fn is_valid_code(code: &str) -> bool {
        let compact = normalize(code);
        compact.len() == SHORT_ID_LEN + SECRET_LEN && compact.bytes().all(|b| ALPHABET.contains(&b))
    }

    pub fn short_id(&self) -> &str {
        &self.short_id
    }

    pub fn public_key(&self) -> Vec<u8> {
        self.key.public_key()
    }

    pub fn mac(&self) -> &[u8] {
        &self.mac
    }

    /// Opens the sealed payload (JSON).
    pub fn open(&self, sealed: &str) -> Result<String> {
        let public_key = self.key.public_key();
        let plaintext = self.key.open(
            &ephemeral_key_hash(&public_key),
            PURPOSE,
            &context(&self.short_id),
            &encoding::decode(sealed)?,
        )?;
        ensure_json(&plaintext)?;
        String::from_utf8(plaintext.to_vec())
            .map_err(|_| Error::InvalidData("payload is not UTF-8".into()))
    }
}

// --- Signing in a new device from a signed-in browser ---------------------------------

/// Domain separation of the CLI-initiated direction: the MAC key, the MAC
/// input and the seal context have labels of their own, so a MAC or a sealed
/// payload of one direction never verifies in the other.
const CLI_LOGIN_MAC_INFO: &[u8] = b"passbox/v1/cli-login";
const CLI_LOGIN_MAC_TAG: &str = "passbox/v1/cli-login-request";
const CLI_LOGIN_CONTEXT_TAG: &str = "passbox/v1/seal-context/cli-login";
/// Bytes of the secret in the URL fragment.
const CLI_LOGIN_SECRET_LEN: usize = 32;
/// Longest device name the MAC covers (the server keeps 80 characters).
pub const CLI_LOGIN_MAX_DEVICE_NAME: usize = 80;

fn cli_login_mac(
    id: &str,
    secret: &[u8],
    ephemeral_pk: &[u8],
    device_name: &str,
) -> Result<Hmac<Sha256>> {
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(id.as_bytes()), secret)
        .expand(CLI_LOGIN_MAC_INFO, key.as_mut())
        .map_err(|e| Error::Kdf(e.to_string()))?;
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key.as_ref())
        .expect("HMAC accepts any key length");
    mac.update(
        &Writer::new(CLI_LOGIN_MAC_TAG)
            .str(id)
            .bytes(ephemeral_pk)
            .str(device_name)
            .finish(),
    );
    Ok(mac)
}

fn cli_login_context(id: &str) -> Vec<u8> {
    Writer::new(CLI_LOGIN_CONTEXT_TAG).str(id).finish()
}

/// The device name as the server stores and shows it (control characters
/// removed, at most 80 characters, trimmed), so the MAC covers exactly
/// what the approver sees.
pub fn clean_device_name(name: &str) -> String {
    name.chars()
        .filter(|c| !c.is_control())
        .take(CLI_LOGIN_MAX_DEVICE_NAME)
        .collect::<String>()
        .trim()
        .to_owned()
}

/// A device without a session (for example `pbx login`) asking a signed-in
/// browser for the account details.
///
/// The device picks the request ID and a 256-bit secret, creates an
/// ephemeral X-Wing key pair and registers the ID, the public key, its name
/// and
///
/// ```text
/// mac = HMAC-SHA256(HKDF-SHA256(ikm = secret, salt = id, info = "passbox/v1/cli-login"),
///                   canonical("passbox/v1/cli-login-request", id, ephemeral_pk, device_name))
/// ```
///
/// with the server. The secret travels only in the fragment of the link
/// the user opens in the web vault (`#/cli-login/{id}#{secret}`), which
/// browsers never send to a server. The web vault checks the MAC, so a
/// server that swaps in its own key (or renames the device) is detected,
/// and seals the email, account ID and Secret Key to the ephemeral key
/// (purpose `device-link`, context `canonical("passbox/v1/seal-context/cli-login", id)`).
/// The master password is never transferred.
pub struct CliLoginRequest {
    id: String,
    secret: Zeroizing<String>,
    device_name: String,
    key: EncryptionKey,
    mac: Vec<u8>,
}

impl core::fmt::Debug for CliLoginRequest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CliLoginRequest")
            .field("id", &self.id)
            .field("device_name", &self.device_name)
            .finish_non_exhaustive()
    }
}

impl CliLoginRequest {
    /// A new request with a fresh ID, secret and ephemeral key.
    pub fn new(device_name: &str) -> Result<Self> {
        let id = crate::id::new_id()?;
        let secret = Zeroizing::new(encoding::encode(
            &Zeroizing::new(random::bytes::<CLI_LOGIN_SECRET_LEN>()?)[..],
        ));
        let device_name = clean_device_name(device_name);
        let key = EncryptionKey::generate()?;
        let mac = cli_login_mac(
            &id,
            &encoding::decode(&secret)?,
            &key.public_key(),
            &device_name,
        )?
        .finalize()
        .into_bytes()
        .to_vec();
        Ok(Self {
            id,
            secret,
            device_name,
            key,
            mac,
        })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    /// The name the MAC covers (cleaned like the server does).
    pub fn device_name(&self) -> &str {
        &self.device_name
    }

    pub fn public_key(&self) -> Vec<u8> {
        self.key.public_key()
    }

    pub fn mac(&self) -> &[u8] {
        &self.mac
    }

    /// The web vault route with the secret: append it to the web vault's
    /// URL (`https://app.passbox.net/` + this). Only the fragment carries
    /// the secret.
    pub fn link_fragment(&self) -> String {
        format!("#/cli-login/{}#{}", self.id, self.secret.as_str())
    }

    /// Opens the sealed payload (JSON).
    pub fn open(&self, sealed: &str) -> Result<String> {
        let public_key = self.key.public_key();
        let plaintext = self.key.open(
            &ephemeral_key_hash(&public_key),
            PURPOSE,
            &cli_login_context(&self.id),
            &encoding::decode(sealed)?,
        )?;
        ensure_json(&plaintext)?;
        String::from_utf8(plaintext.to_vec())
            .map_err(|_| Error::InvalidData("payload is not UTF-8".into()))
    }
}

/// The signed-in browser's side: built from the ID and the secret in the
/// link's fragment.
pub struct CliLoginApproval {
    id: String,
    secret: Zeroizing<Vec<u8>>,
}

impl core::fmt::Debug for CliLoginApproval {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CliLoginApproval")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl CliLoginApproval {
    /// Checks the shape of the ID and the secret from the link.
    pub fn new(id: &str, secret: &str) -> Result<Self> {
        if !crate::id::is_valid_id(id) {
            return Err(Error::InvalidDeviceCode);
        }
        let secret =
            Zeroizing::new(encoding::decode(secret.trim()).map_err(|_| Error::InvalidDeviceCode)?);
        if secret.len() != CLI_LOGIN_SECRET_LEN {
            return Err(Error::InvalidDeviceCode);
        }
        Ok(Self {
            id: id.to_owned(),
            secret,
        })
    }

    /// Parses `#/cli-login/{id}#{secret}` (or `cli-login/{id}#{secret}`).
    pub fn from_fragment(fragment: &str) -> Result<Self> {
        let rest = fragment
            .trim_start_matches('#')
            .trim_start_matches('/')
            .strip_prefix("cli-login/")
            .ok_or(Error::InvalidDeviceCode)?;
        let (id, secret) = rest.split_once('#').ok_or(Error::InvalidDeviceCode)?;
        Self::new(id.trim_end_matches('/'), secret)
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    /// Checks that the key and the device name the server returned are the
    /// ones the requesting device registered.
    pub fn verify(&self, ephemeral_pk: &[u8], device_name: &str, mac: &[u8]) -> Result<()> {
        cli_login_mac(&self.id, &self.secret, ephemeral_pk, device_name)?
            .verify_slice(mac)
            .map_err(|_| Error::InvalidDeviceCode)
    }

    /// Verifies the request and seals `payload_json` (email, account ID and
    /// Secret Key) to its ephemeral key.
    pub fn seal(
        &self,
        ephemeral_pk: &[u8],
        device_name: &str,
        mac: &[u8],
        payload_json: &str,
    ) -> Result<String> {
        self.verify(ephemeral_pk, device_name, mac)?;
        ensure_json(payload_json.as_bytes())?;
        let sealed = identity::seal(
            ephemeral_pk,
            &ephemeral_key_hash(ephemeral_pk),
            PURPOSE,
            &cli_login_context(&self.id),
            payload_json.as_bytes(),
        )?;
        Ok(encoding::encode(&sealed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_device_receives_the_payload() {
        let short_id = new_short_id().unwrap();
        assert!(is_short_id(&short_id));
        let offer = DeviceLinkOffer::new(&short_id).unwrap();
        let code = offer.code();
        assert_eq!(code.len(), 19);
        assert!(code.starts_with(&short_id));
        // Typed in lower case with O instead of 0 still works.
        let typed = code.to_lowercase().replace('0', "o");
        assert!(DeviceLinkRequest::is_valid_code(&typed));
        let device = DeviceLinkRequest::new(&typed).unwrap();
        assert_eq!(device.short_id(), short_id);
        let payload = r#"{"email":"ada@example.com","accountId":"a","secretKey":"P1-X"}"#;
        let sealed = offer
            .seal(&device.public_key(), device.mac(), payload)
            .unwrap();
        assert_eq!(device.open(&sealed).unwrap(), payload);
    }

    #[test]
    fn a_swapped_key_or_wrong_code_is_detected() {
        let offer = DeviceLinkOffer::new("AB12").unwrap();
        let device = DeviceLinkRequest::new(&offer.code()).unwrap();
        // A server substituting its own ephemeral key cannot produce the MAC.
        let attacker = EncryptionKey::generate().unwrap();
        assert_eq!(
            offer.seal(&attacker.public_key(), device.mac(), "{}"),
            Err(Error::InvalidDeviceCode)
        );
        // A device that typed a different secret fails too.
        let mut wrong = offer.code();
        wrong.replace_range(18..19, if wrong.ends_with('A') { "B" } else { "A" });
        let other = DeviceLinkRequest::new(&wrong).unwrap();
        assert!(
            offer
                .verify_claim(&other.public_key(), other.mac())
                .is_err()
        );
        // Another device cannot open what was sealed for this one.
        let sealed = offer
            .seal(&device.public_key(), device.mac(), "{}")
            .unwrap();
        assert!(other.open(&sealed).is_err());
        // Malformed codes and IDs.
        assert!(DeviceLinkRequest::new("ABCD-EFGH").is_err());
        assert!(DeviceLinkOffer::new("ab1").is_err());
        assert!(!DeviceLinkRequest::is_valid_code("ABCD-EFGH-JKMN-PQR!"));
    }

    #[test]
    fn cli_login_round_trip() {
        let request = CliLoginRequest::new("pbx  laptop\u{7}").unwrap();
        assert_eq!(request.device_name(), "pbx  laptop");
        let fragment = request.link_fragment();
        assert!(fragment.starts_with(&format!("#/cli-login/{}#", request.id())));
        let approval = CliLoginApproval::from_fragment(&fragment).unwrap();
        assert_eq!(approval.id(), request.id());
        let payload = r#"{"email":"ada@example.com","accountId":"a","secretKey":"P1-X"}"#;
        let sealed = approval
            .seal(
                &request.public_key(),
                request.device_name(),
                request.mac(),
                payload,
            )
            .unwrap();
        assert_eq!(request.open(&sealed).unwrap(), payload);
        // Without the leading "#/" too.
        assert!(CliLoginApproval::from_fragment(&fragment[2..]).is_ok());
    }

    #[test]
    fn cli_login_detects_a_swapped_key_or_name() {
        let request = CliLoginRequest::new("pbx laptop").unwrap();
        let approval = CliLoginApproval::from_fragment(&request.link_fragment()).unwrap();
        let attacker = EncryptionKey::generate().unwrap();
        // A server substituting its own key or renaming the device cannot
        // produce the MAC without the secret.
        assert_eq!(
            approval.seal(&attacker.public_key(), "pbx laptop", request.mac(), "{}"),
            Err(Error::InvalidDeviceCode)
        );
        assert_eq!(
            approval.verify(&request.public_key(), "pbx work laptop", request.mac()),
            Err(Error::InvalidDeviceCode)
        );
        // A different secret (another link) fails.
        let other = CliLoginRequest::new("pbx laptop").unwrap();
        let wrong = CliLoginApproval::new(
            request.id(),
            other.link_fragment().rsplit('#').next().unwrap(),
        )
        .unwrap();
        assert!(
            wrong
                .verify(&request.public_key(), "pbx laptop", request.mac())
                .is_err()
        );
        // Another request cannot open the payload.
        let sealed = approval
            .seal(&request.public_key(), "pbx laptop", request.mac(), "{}")
            .unwrap();
        assert!(other.open(&sealed).is_err());
        // Malformed links.
        assert!(CliLoginApproval::from_fragment("#/cli-login/abc#def").is_err());
        assert!(CliLoginApproval::new(request.id(), "short").is_err());
        assert!(CliLoginApproval::from_fragment(&format!("#/cli-login/{}", request.id())).is_err());
    }

    #[test]
    fn the_two_directions_do_not_mix() {
        // The same secret bytes, ID and key give different MACs in the two
        // directions, and a payload sealed for one does not open in the other.
        let request = CliLoginRequest::new("").unwrap();
        let approval = CliLoginApproval::from_fragment(&request.link_fragment()).unwrap();
        let device_mac =
            claim_mac(request.id(), request.secret.as_str(), &request.public_key()).unwrap();
        assert!(
            approval
                .verify(&request.public_key(), "", &device_mac)
                .is_err()
        );
        let sealed = encoding::encode(
            &identity::seal(
                &request.public_key(),
                &ephemeral_key_hash(&request.public_key()),
                PURPOSE,
                &context(request.id()),
                b"{}",
            )
            .unwrap(),
        );
        assert!(request.open(&sealed).is_err());
    }
}
