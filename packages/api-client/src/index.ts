import { type BreachApi, breachApi } from "./breach";
import { type CloudApi, cloudApi, type ServerExtensions } from "./cloud";
import { type ComfortApi, comfortApi } from "./comfort";
import { type DeveloperApi, developerApi } from "./developer";
import { type OrgAdminApi, orgAdminApi } from "./orgAdmin";
import {
  type CliLoginApi,
  cliLoginApi,
  type DeviceLinkApi,
  deviceLinkApi,
  type EmergencyApi,
  emergencyApi,
  type RecoveryApi,
  recoveryApi,
} from "./recovery";
import { type SsoApi, ssoApi } from "./sso";

export * from "./breach";
export * from "./cloud";
export * from "./comfort";
export * from "./developer";
export * from "./orgAdmin";
export * from "./recovery";
export * from "./sso";

/** Argon2id cost parameters. Mirrors `passbox_core::kdf::KdfParams`. */
export interface KdfParams {
  memoryKib: number;
  iterations: number;
  parallelism: number;
}

export interface Health {
  status: "ok";
}

/** Who may create an account on a server. */
export type RegistrationMode = "open" | "invite_only" | "domains";

export type MailLocale = "en" | "de";

/**
 * Minimum strength of new master passwords. The server never sees the
 * password, so clients enforce it (together with their own minimum).
 */
export interface PasswordPolicy {
  /** Lowest strength score: 3 (strong) or 4 (very strong). */
  minScore: number;
  /** Lowest number of characters (at least 12). */
  minLength: number;
}

export interface ServerMeta {
  name: string;
  version: string;
  apiVersion: number;
  minKdfParams: KdfParams;
  /** Name the admins gave the server. Missing on servers before instance settings. */
  instanceName?: string;
  registration?: RegistrationMode;
  /** In `domains` mode: the email domains that may register. */
  allowedDomains?: string[];
  /** Where users get help, if the admins set it. */
  supportUrl?: string | null;
  defaultLocale?: MailLocale;
  passwordPolicy?: PasswordPolicy;
  /** Whether the server loads website icons (`/api/v1/icons/{domain}`). Missing on older servers. */
  icons?: boolean;
  /** Whether `/api/v1/breach/range/{prefix}` proxies Have I Been Pwned. Missing on older servers. */
  breachProxy?: boolean;
  /** Whether email breach monitoring is available. Missing on older servers. */
  emailMonitoring?: boolean;
  /** Whether `/api/v1/breaches/catalog` serves the breach catalogue. Missing on older servers. */
  breachCatalog?: boolean;
  /** Most members a family may have, if the server limits it (403 `family_limit_reached`). */
  familyMemberLimit?: number;
  /** Additions of the server; `cloud` only on the hosted service. */
  extensions?: ServerExtensions;
}

export interface PreloginResponse {
  accountId: string;
  kdfSalt: string;
  kdfParams: KdfParams;
}

export interface NewVault {
  id: string;
  encryptedKey: string;
  encryptedMeta: string;
}

export interface RegisterFinishRequest {
  accountId: string;
  email: string;
  registrationUpload: string;
  kdfSalt: string;
  kdfParams: KdfParams;
  encryptedAccountKey: string;
  vault: NewVault;
  /** Token from an invitation link (`#/?invite=…`). */
  inviteToken?: string;
  /** Language for mails from the server. */
  locale?: MailLocale;
}

export interface LoginStartResponse {
  loginId: string;
  credentialResponse: string;
}

export interface LoginFinishResponse {
  token: string;
  accountId: string;
  sessionId: string;
  expiresAt: number;
  /**
   * Store it on the device and send it with the next `loginStart`; it
   * replaces the token sent there. It exempts the device from the per-email
   * login lockout and grants no access by itself.
   */
  deviceToken: string;
  /** Unused recovery codes left, after signing in with one. */
  recoveryCodesRemaining?: number;
}

export type TwoFactorMethod = "totp" | "webauthn" | "recovery";

/** A credential the browser may use, as in `PublicKeyCredentialDescriptor` (ID as Base64url). */
export interface WebAuthnCredentialDescriptor {
  type: "public-key";
  id: string;
}

/** `PublicKeyCredentialRequestOptions` with binary values as Base64url. */
export interface WebAuthnRequestOptionsJson {
  challenge: string;
  rpId: string;
  allowCredentials: WebAuthnCredentialDescriptor[];
  timeout: number;
  userVerification: "required" | "preferred" | "discouraged";
}

/** `PublicKeyCredentialCreationOptions` with binary values as Base64url. */
export interface WebAuthnCreationOptionsJson {
  challenge: string;
  rp: { id: string; name: string };
  user: { id: string; name: string; displayName: string };
  pubKeyCredParams: { type: "public-key"; alg: number }[];
  timeout: number;
  attestation: "none";
  excludeCredentials: WebAuthnCredentialDescriptor[];
  authenticatorSelection: {
    residentKey: "discouraged" | "preferred" | "required";
    userVerification: "required" | "preferred" | "discouraged";
  };
}

/**
 * Returned by `loginFinish` instead of a session when the account has
 * two-factor authentication on and this device is not remembered. Complete
 * it with `loginTwoFactor` within 5 minutes.
 */
export interface TwoFactorChallenge {
  twoFactorRequired: true;
  challengeToken: string;
  expiresAt: number;
  methods: TwoFactorMethod[];
  /** Present when the account has security keys for this origin. */
  webauthn?: WebAuthnRequestOptionsJson;
}

export type LoginFinishResult = LoginFinishResponse | TwoFactorChallenge;

export function isTwoFactorChallenge(result: LoginFinishResult): result is TwoFactorChallenge {
  return (result as TwoFactorChallenge).twoFactorRequired === true;
}

/** A WebAuthn assertion (`navigator.credentials.get`), binary values as Base64url. */
export interface WebAuthnAssertionJson {
  credentialId: string;
  clientDataJson: string;
  authenticatorData: string;
  signature: string;
}

/** A WebAuthn registration (`navigator.credentials.create`), binary values as Base64url. */
export interface WebAuthnAttestationJson {
  clientDataJson: string;
  attestationObject: string;
}

/** A second factor: a 6-digit code, a recovery code or a security key. */
export type SecondFactor =
  | { method: "totp"; code: string }
  | { method: "recovery"; code: string }
  | { method: "webauthn"; webauthn: WebAuthnAssertionJson };

export interface SecurityKeyInfo {
  id: string;
  name: string;
  createdAt: number;
  /** 0 if never used. */
  lastUsedAt: number;
}

export interface TwoFactorStatus {
  /** Whether sign-ins need a second factor. */
  enabled: boolean;
  totp: boolean;
  securityKeys: SecurityKeyInfo[];
  recoveryCodesRemaining: number;
}

export type ClientKind = "web" | "extension" | "desktop" | "ios" | "android" | "cli";

export interface SessionInfo {
  id: string;
  deviceName: string;
  clientKind: ClientKind | "";
  ip: string;
  createdAt: number;
  lastUsedAt: number;
  expiresAt: number;
  /** True for the session making the request. */
  current: boolean;
}

export type AccountEventKind =
  | "account_created"
  | "login"
  | "login_failed"
  | "logout"
  | "session_revoked"
  | "other_sessions_revoked"
  | "password_changed"
  | "login_two_factor"
  | "two_factor_failed"
  | "two_factor_enabled"
  | "two_factor_disabled"
  | "two_factor_method_added"
  | "two_factor_method_removed"
  | "recovery_code_used"
  | "recovery_codes_regenerated"
  | "keys_published"
  | "org_created"
  | "org_deleted"
  | "org_invitation_created"
  | "org_invitation_accepted"
  | "org_membership_confirmed"
  | "org_member_confirmed"
  | "org_role_changed"
  | "org_membership_suspended"
  | "org_membership_reactivated"
  | "org_membership_removed"
  | "org_member_removed"
  | "vault_shared"
  | "vault_unshared"
  | "vault_member_changed"
  | "vault_key_rotated"
  | "group_joined"
  | "group_left"
  | "account_recovery_code_created"
  | "account_recovery_code_removed"
  | "account_recovery_failed"
  | "account_recovered_code"
  | "account_recovered_org"
  | "org_recovery_enabled"
  | "org_recovery_admin_added"
  | "org_recovery_enrolled"
  | "org_recovery_withdrawn"
  | "org_recovery_requested"
  | "org_recovery_approved"
  | "org_recovery_denied"
  | "org_member_recovered"
  | "emergency_contact_added"
  | "emergency_contact_removed"
  | "emergency_invitation_accepted"
  | "emergency_access_confirmed"
  | "emergency_access_requested"
  | "emergency_access_approved"
  | "emergency_access_denied"
  | "emergency_access_used"
  | "device_link_created"
  | "device_link_approved"
  | "service_account_created"
  | "service_account_access_changed"
  | "service_account_revoked"
  | "service_account_deleted"
  | "agent_grant_requested"
  | "agent_grant_approved"
  | "agent_grant_denied"
  | "agent_grant_revoked"
  | "agent_request_access"
  | "agent_run"
  | "agent_inject"
  | "agent_create";

export interface AccountEvent {
  id: string;
  kind: AccountEventKind | string;
  deviceName: string;
  clientKind: ClientKind | "";
  ip: string;
  createdAt: number;
}

export interface Account {
  accountId: string;
  email: string;
  kdfSalt: string;
  kdfParams: KdfParams;
  encryptedAccountKey: string;
  /** Whether the account may use the instance administration. */
  instanceAdmin?: boolean;
}

/** A change of the account's address that waits for the code mailed to the new one. */
export interface PendingEmailChange {
  newEmail: string;
  /** When the code expires (Unix ms). */
  expiresAt: number;
}

/** Preferences the server needs: mail language and notifications. */
export interface AccountPreferences {
  /** `null`: the server's default language. */
  locale: MailLocale | null;
  /** Mail when a new device signs in. */
  notifyNewDevice: boolean;
}

export interface InstanceSettings {
  instanceName: string;
  registration: RegistrationMode;
  allowedDomains: string[];
  /** `""` for none. */
  supportUrl: string;
  defaultLocale: MailLocale;
  passwordPolicy: PasswordPolicy;
  /**
   * AI agents and service accounts per member (fair use). `null` or absent:
   * `PASSBOX_AGENT_LIMIT_PER_MEMBER`; 0 = unlimited.
   */
  agentLimitPerMember?: number | null;
}

/** What the server holds; guests, agents and service accounts are never billable members. */
export interface InstanceUsage {
  accounts: number;
  organizations: number;
  /** Accounts that are confirmed members (not guests) of an organization. */
  members: number;
  /** Accounts that are only guests. */
  guests: number;
  serviceAccounts: number;
}

export interface MailStatus {
  /** False when no SMTP server is configured: mails are only written to the server log. */
  configured: boolean;
  transport: "smtps" | "starttls" | "smtp" | "camelmailer" | "log";
  host: string | null;
  from: string;
  publicUrl: string | null;
  pending: number;
  failed: number;
  lastSentAt: number | null;
  lastError: string | null;
}

export interface AdminSettings {
  settings: InstanceSettings;
  mail: MailStatus;
  /** Admins configured with `PASSBOX_ADMIN_EMAILS`. */
  envAdminEmails: string[];
  /** `PASSBOX_AGENT_LIMIT_PER_MEMBER` (0 = unlimited). Older servers omit it. */
  envAgentLimitPerMember?: number;
  usage?: InstanceUsage;
}

export interface AdminUser {
  id: string;
  email: string;
  createdAt: number;
  lastActivityAt: number | null;
  status: "active" | "disabled";
  disabledAt: number | null;
  instanceAdmin: boolean;
  activeSessions: number;
  /** `null` while the server has no two-step sign-in. */
  twoFactorEnabled: boolean | null;
}

export interface AdminUsers {
  users: AdminUser[];
  total: number;
}

export type AdminEventAction =
  | "instance_admin_bootstrap"
  | "settings_updated"
  | "user_disabled"
  | "user_enabled"
  | "test_mail_sent"
  | "invite_created"
  | "invite_used"
  | "invite_revoked";

export interface AdminEvent {
  seq: number;
  id: string;
  actorId: string;
  actorEmail: string;
  action: AdminEventAction | string;
  target: string;
  details: Record<string, unknown> | null;
  ip: string;
  createdAt: number;
  prevHash: string;
  hash: string;
}

export interface AdminEvents {
  /** Newest first. */
  events: AdminEvent[];
  /** Result of checking the whole hash chain on the server. */
  chain: { valid: boolean; length: number; brokenAt: number | null };
}

export interface Invite {
  id: string;
  email: string;
  invitedBy: string;
  createdAt: number;
  expiresAt: number;
  usedAt: number | null;
  status: "pending" | "used" | "expired";
}

export interface InviteCreated extends Invite {
  /** The invitation link, also sent by mail; `null` if the server knows no public address. */
  link: string | null;
  mailConfigured: boolean;
}

/** Instance administration; every call needs an instance admin (else 403 `forbidden`). */
export interface AdminApi {
  adminSettings(): Promise<AdminSettings>;
  updateAdminSettings(settings: InstanceSettings): Promise<AdminSettings>;
  adminUsers(query?: { q?: string; limit?: number; offset?: number }): Promise<AdminUsers>;
  disableUser(id: string): Promise<void>;
  enableUser(id: string): Promise<void>;
  sendTestMail(to?: string): Promise<{ id: string; to: string; mailConfigured: boolean }>;
  adminEvents(query?: { limit?: number; before?: number }): Promise<AdminEvents>;
  adminInvites(): Promise<Invite[]>;
  createInvite(req: { email: string; locale?: MailLocale; linkBase?: string }): Promise<InviteCreated>;
  revokeInvite(id: string): Promise<void>;
}

export interface SyncVault {
  id: string;
  /** Empty for shared vaults: their keys arrive in `sharing.vaultKeys`. */
  encryptedKey: string;
  encryptedMeta: string;
  revision: number;
  updatedAt: number;
  /** Set for shared (organization) vaults. */
  orgId?: string;
  /** Key epoch of `encryptedMeta`; absent (0) for personal vaults. */
  keyEpoch?: number;
}

export interface SyncItem {
  id: string;
  vaultId: string;
  revision: number;
  /** `null` for deleted items. */
  encryptedData: string | null;
  deleted: boolean;
  updatedAt: number;
  /** Vault key epoch of `encryptedData` (0 for personal vaults). */
  keyEpoch?: number;
  /** When the item was created (Unix ms). Missing on older servers. */
  createdAt?: number;
}

/** An earlier, still encrypted version of an item (`GET /api/v1/items/{id}/versions`). */
export interface ItemVersionRecord {
  revision: number;
  keyEpoch: number;
  encryptedData: string;
  updatedAt: number;
  /** Public ID of the session (device) that saved it, if known. */
  updatedBy: string | null;
}

/** A website icon from `GET /api/v1/icons/{domain}`. */
export interface IconResponse {
  contentType: string;
  bytes: Uint8Array;
}

/** Path of a domain's website icon on the server (needs a session token). */
export function iconPath(domain: string): string {
  return `/api/v1/icons/${encodeURIComponent(domain.trim().toLowerCase())}`;
}

export interface SyncResponse {
  cursor: number;
  vaults: SyncVault[];
  items: SyncItem[];
  /**
   * Organizations, rosters, groups, sealed keys and manifests (only with
   * `sharing`). Opaque to this package; `@passbox/core-wasm` verifies it.
   */
  sharing?: Record<string, unknown>;
}

/** Account key pairs as stored on the server (`/api/v1/account/keys`). */
export interface AccountKeys {
  keyVersion: number;
  /** Base64url canonical public bundle (self-signed). */
  bundle: string;
  bundleSignature: string;
  /** Private keys, encrypted with the account key. */
  encryptedPrivate: string;
}

export interface InvitationCreated {
  id: string;
  /** Shown once; the server keeps only its hash. */
  token: string;
  /** `/invite/{token}`, relative to the web app. */
  path: string;
  expiresAt: number;
}

export interface OrgInvitationInfo {
  id: string;
  email: string;
  role: string;
  status: string;
  createdBy: string;
  createdAt: number;
  expiresAt: number;
}

export interface InvitationPreview {
  orgId: string;
  orgKind: "family" | "team";
  email: string;
  role: string;
  expiresAt: number;
  /** Email of the admin who invited (servers before this field omit it). */
  inviterEmail?: string;
  /**
   * The organization's admins will be able to restore the invitee's access
   * (recovery is on and required). The app must say so before accepting.
   */
  recovery?: boolean;
}

/**
 * The sharing endpoints. Request bodies are built and signed by
 * `@passbox/core-wasm` (`Keyring.createOrg`, `shareVault`, ...); see
 * docs/architecture/sharing.md and docs/api/openapi.yaml.
 */
export interface SharingApi {
  ownKeys(): Promise<AccountKeys>;
  publishKeys(keys: AccountKeys): Promise<void>;
  /** Key directory lookup with a proof from `since` (last verified head size). */
  lookupKey(accountId: string, since: number): Promise<unknown>;
  createOrg(body: unknown): Promise<{ id: string; seq: number; defaultVaultId?: string | null }>;
  updateOrg(orgId: string, body: { revision: number; metaEpoch: number; encryptedMeta: string }): Promise<void>;
  deleteOrg(orgId: string): Promise<void>;
  rotateOrgKey(orgId: string, body: unknown): Promise<void>;
  invite(orgId: string, body: { email: string; role: string; linkFragment?: string }): Promise<InvitationCreated>;
  invitations(orgId: string): Promise<OrgInvitationInfo[]>;
  revokeInvitation(orgId: string, invitationId: string): Promise<void>;
  previewInvitation(token: string): Promise<InvitationPreview>;
  acceptInvitation(token: string): Promise<{ orgId: string; role: string }>;
  confirmMember(orgId: string, accountId: string, body: unknown): Promise<void>;
  updateMember(orgId: string, accountId: string, body: unknown): Promise<void>;
  suspendMember(orgId: string, accountId: string): Promise<void>;
  reactivateMember(orgId: string, accountId: string): Promise<void>;
  removeMember(orgId: string, accountId: string): Promise<{ vaults: string[]; groups: string[] }>;
  createGroup(orgId: string, body: unknown): Promise<unknown>;
  updateGroup(orgId: string, groupId: string, body: { metaEpoch: number; encryptedMeta: string }): Promise<void>;
  deleteGroup(orgId: string, groupId: string): Promise<void>;
  addGroupMember(orgId: string, groupId: string, body: unknown): Promise<unknown>;
  rotateGroup(orgId: string, groupId: string, body: unknown): Promise<{ vaults?: string[] }>;
  createSharedVault(orgId: string, body: unknown): Promise<{ seq: number; keyEpoch: number }>;
  putVaultMember(vaultId: string, body: unknown): Promise<{ seq: number; keyEpoch: number }>;
  rotateVault(vaultId: string, body: unknown): Promise<{ seq: number; keyEpoch: number }>;
  putWrappedKey(vaultId: string, keyEpoch: number, wrappedKey: string): Promise<void>;
  reencryptItems(
    vaultId: string,
    items: { id: string; revision: number; keyEpoch: number; encryptedData: string }[],
  ): Promise<{ id: string; status: "ok" | "conflict"; revision: number }[]>;
}

export interface WriteResponse {
  revision: number;
  seq: number;
}

export interface ErrorBody {
  error: string;
  message: string;
  /** `limit` comes with `family_limit_reached`. */
  details?: { currentRevision?: number; limit?: number } & Record<string, unknown>;
}

/** Thrown when the server answers with a non-2xx status. */
export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly path: string,
    readonly body: ErrorBody | undefined,
  ) {
    super(body?.message ?? `Passbox API request to ${path} failed with status ${status}`);
    this.name = "ApiError";
  }

  /** Machine-readable error code, for example `conflict` or `invalid_credentials`. */
  get code(): string | undefined {
    return this.body?.error;
  }
}

export interface ClientOptions {
  /** Server origin, for example `https://passbox.example.com`. Defaults to the current origin. */
  baseUrl?: string;
  fetch?: typeof globalThis.fetch;
  /** Returns the session token sent as bearer token, if any. */
  getToken?: () => string | undefined;
}

export interface PassboxApi extends AdminApi, CloudApi {
  health(): Promise<Health>;
  meta(): Promise<ServerMeta>;
  prelogin(email: string): Promise<PreloginResponse>;
  registerStart(req: { accountId: string; email: string; registrationRequest: string; inviteToken?: string }): Promise<{
    registrationResponse: string;
  }>;
  registerFinish(req: RegisterFinishRequest): Promise<{ accountId: string }>;
  loginStart(req: {
    email: string;
    credentialRequest: string;
    /** The device token from this device's last successful login. */
    deviceToken?: string;
  }): Promise<LoginStartResponse>;
  loginFinish(req: {
    loginId: string;
    credentialFinalization: string;
    deviceName?: string;
    clientKind?: ClientKind;
    /** `location.origin` of a web client, to be offered its security keys. */
    origin?: string;
    /** Proof of an SSO sign-in (`sso.redeem`), when the organization requires SSO. */
    ssoProof?: string;
  }): Promise<LoginFinishResult>;
  loginTwoFactor(
    req: SecondFactor & { challengeToken: string; rememberDevice?: boolean },
  ): Promise<LoginFinishResponse>;
  logout(): Promise<void>;
  account(): Promise<Account>;
  preferences(): Promise<AccountPreferences>;
  /** Changes the given preferences; `locale: ""` resets to the server default. */
  updatePreferences(changes: { locale?: MailLocale | ""; notifyNewDevice?: boolean }): Promise<AccountPreferences>;
  accountEvents(limit?: number): Promise<AccountEvent[]>;
  /** The pending change of the account's address, or `null`. */
  emailChangePending(): Promise<PendingEmailChange | null>;
  /** Mails a code to the new address. Needs a login in the last 10 minutes. */
  emailChangeStart(req: { email: string; locale?: string | undefined }): Promise<PendingEmailChange>;
  /** Replaces the address with the pending one. Fails with `invalid_two_factor_code`, `code_expired` or `email_taken`. */
  emailChangeConfirm(code: string): Promise<{ email: string }>;
  emailChangeCancel(): Promise<void>;
  passwordChangeStart(req: { registrationRequest: string }): Promise<{ registrationResponse: string }>;
  passwordChangeFinish(req: {
    registrationUpload: string;
    kdfSalt: string;
    kdfParams: KdfParams;
    encryptedAccountKey: string;
  }): Promise<void>;
  twoFactorStatus(): Promise<TwoFactorStatus>;
  /** Needs a login in the last 10 minutes. */
  totpStart(): Promise<{ secret: string; uri: string }>;
  totpConfirm(code: string): Promise<{ recoveryCodes?: string[] }>;
  totpRemove(): Promise<void>;
  webauthnRegisterStart(origin: string): Promise<{ registrationId: string; publicKey: WebAuthnCreationOptionsJson }>;
  webauthnRegisterFinish(req: {
    registrationId: string;
    name: string;
    credential: WebAuthnAttestationJson;
  }): Promise<{ id: string; recoveryCodes?: string[] }>;
  webauthnRemove(id: string): Promise<void>;
  regenerateRecoveryCodes(): Promise<{ recoveryCodes: string[] }>;
  /** A challenge for checking a second factor while signed in (needed for security keys). */
  twoFactorChallenge(origin?: string): Promise<Omit<TwoFactorChallenge, "twoFactorRequired">>;
  disableTwoFactor(req: SecondFactor & { challengeToken?: string }): Promise<void>;
  sessions(): Promise<SessionInfo[]>;
  revokeSession(id: string): Promise<void>;
  revokeOtherSessions(): Promise<void>;
  /** With `sharing`, shared vaults and the sharing state are included. */
  sync(since: number, options?: { sharing?: boolean }): Promise<SyncResponse>;
  createVault(vault: NewVault): Promise<WriteResponse>;
  updateVault(id: string, req: { revision: number; encryptedMeta: string; keyEpoch?: number }): Promise<WriteResponse>;
  putItem(
    id: string,
    req: { vaultId: string; revision: number; encryptedData: string; keyEpoch?: number },
  ): Promise<WriteResponse>;
  sharing: SharingApi;
  /** Recovery code, organization recovery. */
  recovery: RecoveryApi;
  /** Emergency access. */
  emergency: EmergencyApi;
  /** Adding a device by code. */
  deviceLinks: DeviceLinkApi;
  /** Signing in `pbx` (or another device without a session) from this browser. */
  cliLogins: CliLoginApi;
  /** Single sign-on, trusted devices and SCIM. */
  sso: SsoApi;
  /** Organization administration: policies, audit log, reports. */
  orgAdmin: OrgAdminApi;
  breach: BreachApi;
  /** Service accounts and AI agent grants. */
  developer: DeveloperApi;
  /** Moving items, attachments, share links and access requests. */
  comfort: ComfortApi;
  deleteItem(id: string, revision: number): Promise<WriteResponse>;
  /** Earlier versions of an item, newest first (up to 20). */
  itemVersions(id: string): Promise<{ versions: ItemVersionRecord[] }>;
  /** The website icon of `domain`, or `null` when there is none (404/400 or icons turned off). */
  icon(domain: string): Promise<IconResponse | null>;
}

export function createClient(options: ClientOptions = {}): PassboxApi {
  const baseUrl = (options.baseUrl ?? "").replace(/\/+$/, "");
  const doFetch = options.fetch ?? globalThis.fetch.bind(globalThis);

  async function call<T>(method: string, path: string, body?: unknown): Promise<T> {
    const headers: Record<string, string> = { accept: "application/json" };
    const token = options.getToken?.();
    if (token) headers.authorization = `Bearer ${token}`;
    if (body !== undefined) headers["content-type"] = "application/json";
    const init: RequestInit = { method, headers };
    if (body !== undefined) init.body = JSON.stringify(body);

    const response = await doFetch(`${baseUrl}${path}`, init);
    if (!response.ok) {
      let errorBody: ErrorBody | undefined;
      try {
        errorBody = (await response.json()) as ErrorBody;
      } catch {
        errorBody = undefined;
      }
      throw new ApiError(response.status, path, errorBody);
    }
    if (response.status === 204) return undefined as T;
    // CSV exports (the audit log).
    if (response.headers?.get("content-type")?.startsWith("text/csv")) return (await response.text()) as T;
    return (await response.json()) as T;
  }

  /** A request with a binary body or answer (attachments). */
  async function raw(method: string, path: string, body?: Uint8Array): Promise<Response> {
    const headers: Record<string, string> = { accept: "application/octet-stream, application/json" };
    const token = options.getToken?.();
    if (token) headers.authorization = `Bearer ${token}`;
    const init: RequestInit = { method, headers };
    if (body !== undefined) {
      headers["content-type"] = "application/octet-stream";
      init.body = body as unknown as BodyInit;
    }
    const response = await doFetch(`${baseUrl}${path}`, init);
    if (!response.ok) {
      let errorBody: ErrorBody | undefined;
      try {
        errorBody = (await response.json()) as ErrorBody;
      } catch {
        errorBody = undefined;
      }
      throw new ApiError(response.status, path, errorBody);
    }
    return response;
  }

  return {
    health: () => call("GET", "/health"),
    meta: () => call("GET", "/api/v1/meta"),
    prelogin: (email) => call("POST", "/api/v1/auth/prelogin", { email }),
    registerStart: (req) => call("POST", "/api/v1/auth/register/start", req),
    registerFinish: (req) => call("POST", "/api/v1/auth/register/finish", req),
    loginStart: (req) => call("POST", "/api/v1/auth/login/start", req),
    loginFinish: (req) => call("POST", "/api/v1/auth/login/finish", req),
    loginTwoFactor: (req) => call("POST", "/api/v1/auth/login/two-factor", req),
    logout: () => call("POST", "/api/v1/auth/logout", {}),
    account: () => call("GET", "/api/v1/account"),
    preferences: () => call("GET", "/api/v1/account/preferences"),
    updatePreferences: (changes) => call("PUT", "/api/v1/account/preferences", changes),
    accountEvents: (limit = 50) => call("GET", `/api/v1/account/events?limit=${encodeURIComponent(limit)}`),
    emailChangePending: () => call("GET", "/api/v1/account/email"),
    emailChangeStart: (req) => call("POST", "/api/v1/account/email", req),
    emailChangeConfirm: (code) => call("POST", "/api/v1/account/email/confirm", { code }),
    emailChangeCancel: () => call("DELETE", "/api/v1/account/email"),
    passwordChangeStart: (req) => call("POST", "/api/v1/account/password/start", req),
    passwordChangeFinish: (req) => call("POST", "/api/v1/account/password/finish", req),
    twoFactorStatus: () => call("GET", "/api/v1/account/two-factor"),
    totpStart: () => call("POST", "/api/v1/account/two-factor/totp/start", {}),
    totpConfirm: (code) => call("POST", "/api/v1/account/two-factor/totp/confirm", { code }),
    totpRemove: () => call("DELETE", "/api/v1/account/two-factor/totp"),
    webauthnRegisterStart: (origin) => call("POST", "/api/v1/account/two-factor/webauthn/register/start", { origin }),
    webauthnRegisterFinish: (req) => call("POST", "/api/v1/account/two-factor/webauthn/register/finish", req),
    webauthnRemove: (id) => call("DELETE", `/api/v1/account/two-factor/webauthn/${encodeURIComponent(id)}`),
    regenerateRecoveryCodes: () => call("POST", "/api/v1/account/two-factor/recovery-codes", {}),
    twoFactorChallenge: (origin) => call("POST", "/api/v1/account/two-factor/challenge", origin ? { origin } : {}),
    disableTwoFactor: (req) => call("POST", "/api/v1/account/two-factor/disable", req),
    sessions: () => call("GET", "/api/v1/sessions"),
    revokeSession: (id) => call("DELETE", `/api/v1/sessions/${encodeURIComponent(id)}`),
    revokeOtherSessions: () => call("POST", "/api/v1/sessions/revoke-others", {}),
    sync: (since, syncOptions) =>
      call("GET", `/api/v1/sync?since=${encodeURIComponent(since)}${syncOptions?.sharing ? "&sharing=1" : ""}`),
    createVault: (vault) => call("POST", "/api/v1/vaults", vault),
    updateVault: (id, req) => call("PUT", `/api/v1/vaults/${encodeURIComponent(id)}`, req),
    putItem: (id, req) => call("PUT", `/api/v1/items/${encodeURIComponent(id)}`, req),
    deleteItem: (id, revision) =>
      call("DELETE", `/api/v1/items/${encodeURIComponent(id)}?revision=${encodeURIComponent(revision)}`),
    itemVersions: (id) => call("GET", `/api/v1/items/${encodeURIComponent(id)}/versions`),
    icon: async (domain) => {
      const headers: Record<string, string> = { accept: "image/*" };
      const token = options.getToken?.();
      if (token) headers.authorization = `Bearer ${token}`;
      const path = iconPath(domain);
      const response = await doFetch(`${baseUrl}${path}`, { method: "GET", headers });
      if (response.status === 404 || response.status === 400) return null;
      if (!response.ok) {
        let errorBody: ErrorBody | undefined;
        try {
          errorBody = (await response.json()) as ErrorBody;
        } catch {
          errorBody = undefined;
        }
        throw new ApiError(response.status, path, errorBody);
      }
      return {
        contentType: response.headers.get("content-type") ?? "application/octet-stream",
        bytes: new Uint8Array(await response.arrayBuffer()),
      };
    },
    adminSettings: () => call("GET", "/api/v1/admin/settings"),
    updateAdminSettings: (settings) => call("PUT", "/api/v1/admin/settings", settings),
    adminUsers: (query = {}) => call("GET", `/api/v1/admin/users${queryString(query)}`),
    disableUser: (id) => call("POST", `/api/v1/admin/users/${encodeURIComponent(id)}/disable`, {}),
    enableUser: (id) => call("POST", `/api/v1/admin/users/${encodeURIComponent(id)}/enable`, {}),
    sendTestMail: (to) => call("POST", "/api/v1/admin/mail/test", to ? { to } : {}),
    adminEvents: (query = {}) => call("GET", `/api/v1/admin/events${queryString(query)}`),
    adminInvites: () => call("GET", "/api/v1/admin/invites"),
    createInvite: (req) => call("POST", "/api/v1/admin/invites", req),
    revokeInvite: (id) => call("DELETE", `/api/v1/admin/invites/${encodeURIComponent(id)}`),
    ...cloudApi(call),
    sharing: sharingApi(call),
    recovery: recoveryApi(call),
    emergency: emergencyApi(call),
    deviceLinks: deviceLinkApi(call),
    cliLogins: cliLoginApi(call),
    sso: ssoApi(call),
    orgAdmin: orgAdminApi(call),
    breach: breachApi(
      call,
      async (path) => {
        const headers: Record<string, string> = { accept: "text/plain" };
        const token = options.getToken?.();
        if (token) headers.authorization = `Bearer ${token}`;
        const response = await doFetch(`${baseUrl}${path}`, { method: "GET", headers });
        if (response.status === 404) return null;
        if (!response.ok) {
          let errorBody: ErrorBody | undefined;
          try {
            errorBody = (await response.json()) as ErrorBody;
          } catch {
            errorBody = undefined;
          }
          throw new ApiError(response.status, path, errorBody);
        }
        return response.text();
      },
      async (path, headers) => {
        const response = await doFetch(`${baseUrl}${path}`, { method: "GET", headers });
        if (response.status === 304 || response.status === 404) {
          return { status: response.status, etag: response.headers.get("etag"), body: null };
        }
        if (!response.ok) {
          let errorBody: ErrorBody | undefined;
          try {
            errorBody = (await response.json()) as ErrorBody;
          } catch {
            errorBody = undefined;
          }
          throw new ApiError(response.status, path, errorBody);
        }
        return { status: response.status, etag: response.headers.get("etag"), body: await response.json() };
      },
    ),
    developer: developerApi(call),
    comfort: comfortApi(call, raw),
  };
}

type Call = <T>(method: string, path: string, body?: unknown) => Promise<T>;

function sharingApi(call: Call): SharingApi {
  const e = encodeURIComponent;
  const org = (id: string) => `/api/v1/orgs/${e(id)}`;
  const member = (orgId: string, accountId: string) => `${org(orgId)}/members/${e(accountId)}`;
  const group = (orgId: string, groupId: string) => `${org(orgId)}/groups/${e(groupId)}`;
  const vault = (id: string) => `/api/v1/vaults/${e(id)}`;
  return {
    ownKeys: () => call("GET", "/api/v1/account/keys"),
    publishKeys: (keys) => call("PUT", "/api/v1/account/keys", keys),
    lookupKey: (accountId, since) => call("GET", `/api/v1/keys/${e(accountId)}?since=${e(since)}`),
    createOrg: (body) => call("POST", "/api/v1/orgs", body),
    updateOrg: (orgId, body) => call("PUT", org(orgId), body),
    deleteOrg: (orgId) => call("DELETE", org(orgId)),
    rotateOrgKey: (orgId, body) => call("POST", `${org(orgId)}/rotate-key`, body),
    invite: (orgId, body) => call("POST", `${org(orgId)}/invitations`, body),
    invitations: (orgId) => call("GET", `${org(orgId)}/invitations`),
    revokeInvitation: (orgId, id) => call("DELETE", `${org(orgId)}/invitations/${e(id)}`),
    previewInvitation: (token) => call("GET", `/api/v1/invitations/${e(token)}`),
    acceptInvitation: (token) => call("POST", "/api/v1/invitations/accept", { token }),
    confirmMember: (orgId, accountId, body) => call("POST", `${member(orgId, accountId)}/confirm`, body),
    updateMember: (orgId, accountId, body) => call("PUT", member(orgId, accountId), body),
    suspendMember: (orgId, accountId) => call("POST", `${member(orgId, accountId)}/suspend`, {}),
    reactivateMember: (orgId, accountId) => call("POST", `${member(orgId, accountId)}/reactivate`, {}),
    removeMember: (orgId, accountId) => call("DELETE", member(orgId, accountId)),
    createGroup: (orgId, body) => call("POST", `${org(orgId)}/groups`, body),
    updateGroup: (orgId, groupId, body) => call("PUT", group(orgId, groupId), body),
    deleteGroup: (orgId, groupId) => call("DELETE", group(orgId, groupId)),
    addGroupMember: (orgId, groupId, body) => call("POST", `${group(orgId, groupId)}/members`, body),
    rotateGroup: (orgId, groupId, body) => call("POST", `${group(orgId, groupId)}/rotate`, body),
    createSharedVault: (orgId, body) => call("POST", `${org(orgId)}/vaults`, body),
    putVaultMember: (vaultId, body) => call("POST", `${vault(vaultId)}/members`, body),
    rotateVault: (vaultId, body) => call("POST", `${vault(vaultId)}/rotate`, body),
    putWrappedKey: (vaultId, keyEpoch, wrappedKey) =>
      call("PUT", `${vault(vaultId)}/keys/${e(keyEpoch)}/wrapped`, { wrappedKey }),
    reencryptItems: (vaultId, items) => call("POST", `${vault(vaultId)}/items/batch`, { items }),
  };
}

/** `?a=1&b=x` from the defined values, or `""`. */
function queryString(params: Record<string, string | number | undefined>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== "") search.set(key, String(value));
  }
  const query = search.toString();
  return query ? `?${query}` : "";
}
