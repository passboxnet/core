import {
  type AccessRequestRecord,
  type Account,
  type AccountEvent,
  type AccountKeys,
  type AccountPreferences,
  type AdminApi,
  type AgentUsage,
  ApiError,
  type AttachmentUsageResponse,
  type AuditExport,
  type AuditQuery,
  type BillingInterval,
  type BreachCatalog,
  type ChainCheck,
  type ClientKind,
  type CloudBilling,
  type EmailMonitoring,
  type InvitationPreview,
  isTwoFactorChallenge,
  type KdfParams,
  type LoginFinishResult,
  type MailLocale,
  type MonitoredEmail,
  type MoveItemUpload,
  type OrgAdminApi,
  type OrgInvitationInfo,
  type OrgLock,
  type PassboxApi,
  type PendingEmailChange,
  type RecoveryGrant,
  type RecoveryStatus,
  type SecondFactor,
  type SessionInfo,
  type SignedClientEvent,
  type SsoApi,
  type SsoOption,
  type SsoRedeemed,
  type SsoStart,
  type SsoUnlockResponse,
  type SyncResponse,
  type TrustedDevicesResponse,
  type TrustedDeviceUpload,
  type TwoFactorChallenge,
  type TwoFactorMethod,
  type TwoFactorStatus,
  type WebAuthnRequestOptionsJson,
} from "@passbox/api-client";
import type * as Core from "@passbox/core-wasm";
import { bundledSiteIcon, isBundledSite } from "@passbox/site-icons";
import {
  type EffectivePolicy,
  NEW_ORG_POLICY_RULES,
  NO_POLICY,
  type OrgPolicy,
  type PolicyRules,
  PolicyViolationError,
  securityAggregate,
} from "./admin";
import {
  ALIAS_FIELD,
  ALIAS_PROVIDER_NAMES,
  ALIAS_TAG,
  type AliasProvider,
  type AliasSettings,
  createAlias,
  isAliasProvider,
} from "./aliases";
import {
  type AnalysisCore,
  analyzeSecurity,
  type BreachedSite,
  type BreachMode,
  bundledBreachCatalog,
  type CatalogInfo,
  checkLookalike,
  DEFAULT_REPORT_OPTIONS,
  type ExposedEmail,
  type FindingKind,
  type Lookalike,
  type ReportOptions,
  type SecurityReport,
  siteBreachCounts,
  withDismissed,
} from "./analysis";
import {
  type AgentEventRecord,
  type AgentRequest,
  type CreatedServiceAccount,
  type ServiceAccount,
  type ServiceAccountEventRecord,
  type ServiceAccountPermission,
  type ServiceAccountVaultChoice,
  serviceAccountState,
} from "./developer";
import {
  type Attachment,
  categoryName,
  FIELD,
  fieldValue,
  type ItemData,
  PASSWORD_HISTORY_LEN,
  parseItemData,
  parseVaultMeta,
  serializeItemData,
  TRASH_RETENTION_MS,
  UNKNOWN_CATEGORY,
} from "./items";
import {
  CliLoginExpiredError,
  type CliLoginRequestInfo,
  CliLoginVerificationError,
  type CodeRecoveryStart,
  type DeviceLinkStart,
  type DeviceLinkState,
  type EmergencyContact,
  type EmergencyVaults,
  InvalidDeviceCodeError,
  InvalidRecoveryCodeError,
  type LinkedAccount,
  ORG_RECOVERY_KEY,
  type OrgRecoveryInfo,
  type OrgRecoveryRequestStatus,
  type PendingOrgRecovery,
  RECOVERY_OPTIONS_KEY,
  RecoveryExpiredError,
  type RecoveryOptions,
  type RecoveryRequest,
  type RecoveryResult,
  RecoveryVerificationError,
} from "./recovery";
import {
  analyzeVault,
  breachHashParts,
  countInRange,
  estimateStrength,
  fetchPwnedRange,
  type Strength,
  type VaultHealth,
} from "./security";
import { type ShareLink, type ShareSnapshot, shareLinkUrl } from "./shareLinks";
import {
  type Invitation,
  type KeyLookup,
  type Org,
  type OrgGroup,
  type OrgRole,
  orgLocks,
  type PrincipalType,
  parseInvitationLink,
  type SharedVault,
  type SharingReport,
  type SharingView,
  type SharingWarning,
  type VaultAccess,
  type VaultRole,
  withOrgLocks,
} from "./sharing";
import type { PendingDeviceApproval, TrustedDeviceSecret } from "./sso";
import type { KeyValueStorage } from "./storage";
import { type CredentialsContainerLike, createCredential, getAssertion } from "./webauthn";

type CoreModule = typeof Core;

const EMPTY_SHARING: SharingView = { orgs: [], vaults: [], warnings: [] };

/**
 * What this device remembers about the signed-in account. Like 1Password, the
 * Secret Key is kept on trusted devices so users only type it once per device.
 * Nothing here decrypts data without the master password.
 */
export interface DeviceAccount {
  email: string;
  accountId: string;
  secretKey: string;
  kdfSalt: string;
  kdfParams: KdfParams;
}

export interface Vault {
  id: string;
  name: string;
  revision: number;
  /** The organization of a shared vault; `undefined` for personal vaults. */
  orgId?: string;
  /** Current key epoch (0 or absent for personal vaults). */
  keyEpoch?: number;
  /** This account's verified role: personal vaults are `manage`. */
  role?: VaultRole | undefined;
}

export interface Item {
  id: string;
  vaultId: string;
  revision: number;
  updatedAt: number;
  /** When the item was created (Unix ms); 0 or absent when the server did not say. */
  createdAt?: number;
  /** Vault key epoch the item is encrypted with (0 or absent for personal vaults). */
  keyEpoch?: number;
  data: ItemData;
}

/** An earlier version of an item ("Eintragsverlauf"). */
export interface ItemVersion {
  revision: number;
  /** When this version was saved (Unix ms). */
  updatedAt: number;
  /** Public ID of the session (device) that saved it, if known; see `sessions()`. */
  updatedBy: string | null;
  /** `null` when it cannot be decrypted here (an old key epoch of a shared vault). */
  data: ItemData | null;
}

/** How an item was used on this device. */
export type UsageKind = "copy" | "autofill" | "open";

/** Device-local usage of an item; never synced. */
export interface ItemUsage {
  /** Last copy, autofill or open (Unix ms; 0 = never). */
  lastUsedAt: number;
  /** Last autofill (Unix ms; 0 = never). */
  lastAutofilledAt: number;
  useCount: number;
}

/** A problem shown in an item's security check. Same codes as the Rust client. */
export type ItemProblem = "weak" | "reused" | "insecure_url" | "missing_totp" | "breached";

export interface ItemHealth {
  /** In the order weak, reused, insecure URL, missing 2FA, breached. */
  problems: ItemProblem[];
  /** Strength score 0–4 of the password, or `null` without one. */
  strength: number | null;
  /** Other items with the same password. */
  reusedWith: string[];
  /** Breach count from this session's `checkBreachedItems`, or `null` if unknown. */
  breachCount: number | null;
}

/** A login whose password appears in known data breaches. */
export interface BreachedItem {
  itemId: string;
  count: number;
}

/** An item a bulk change could not apply to. */
export interface BulkFailure {
  itemId: string;
  error: string;
}

/**
 * What a short-lived process needs to resume an unlocked session without the
 * master password: the keyring encrypted under a one-time session key, plus
 * the server session token. Keep it in memory-only storage only (for example
 * `chrome.storage.session`) and discard it on lock.
 */
export interface SessionState {
  accountId: string;
  sessionKey: string;
  blob: string;
  token: string;
}

export type ClientStatus = "signed-out" | "locked" | "unlocked";

/** One item for `PassboxClient.importItems`. */
export interface ImportEntry {
  data: ItemData;
  /** Update this existing item instead of creating a new one. */
  updateId?: string;
}

export interface ImportItemsOptions {
  /** Called after each item with the number processed so far. */
  onProgress?: (done: number, total: number) => void;
  signal?: AbortSignal;
  /** Requests in flight at once (default 6). */
  concurrency?: number;
  /** Items between snapshot updates (default 200). */
  batchSize?: number;
}

export interface ImportItemsResult {
  created: number;
  updated: number;
  failed: { title: string; error: string }[];
}

export interface ClientSnapshot {
  status: ClientStatus;
  email: string | undefined;
  vaults: Vault[];
  /** Items sorted by title, without those in the trash or the archive. */
  items: Item[];
  /** Items in the trash, most recently trashed first. */
  trash: Item[];
  /** Archived items (not in the trash), most recently archived first. */
  archive: Item[];
  /** Items or vaults that could not be decrypted (tampered or unsupported). */
  errors: string[];
  /** Organizations with verified members and groups. */
  orgs: Org[];
  /** Shared vaults with verified members and roles. */
  sharedVaults: SharedVault[];
  /** Problems found while verifying sharing data, for example changed keys. */
  sharingWarnings: SharingWarning[];
  /** Policies in force per organization. */
  policies: OrgPolicy[];
  /** Every policy this account is bound by, combined. */
  effectivePolicy: EffectivePolicy;
}

/** Thrown when the email, master password or Secret Key is wrong. */
export class InvalidCredentialsError extends Error {
  constructor() {
    super("The email, master password or Secret Key is incorrect.");
    this.name = "InvalidCredentialsError";
  }
}

/** Thrown when an item was changed on another device in the meantime. */
export class ConflictError extends Error {
  constructor() {
    super("This item was changed on another device. The latest version has been loaded.");
    this.name = "ConflictError";
  }
}

/**
 * Thrown by `signIn`, `unlock`, `reauthenticate` and `changeMasterPassword`
 * when the password was right but the account needs a second factor on this
 * device. The client keeps the login pending (in memory, for 5 minutes):
 * finish it with `completeTwoFactor` or `completeTwoFactorWithSecurityKey`,
 * or drop it with `cancelTwoFactor`.
 */
export class TwoFactorRequiredError extends Error {
  readonly methods: TwoFactorMethod[];
  /** Options for a security key, when the account has one for this site. */
  readonly webauthn: WebAuthnRequestOptionsJson | undefined;
  readonly expiresAt: number;

  constructor(challenge: TwoFactorChallenge) {
    super("This account needs a second factor to sign in.");
    this.name = "TwoFactorRequiredError";
    this.methods = challenge.methods;
    this.webauthn = challenge.webauthn;
    this.expiresAt = challenge.expiresAt;
  }
}

/** The two-factor code, recovery code or security key was not accepted. Try again. */
export class InvalidTwoFactorCodeError extends Error {
  constructor() {
    super("The two-factor code is incorrect.");
    this.name = "InvalidTwoFactorCodeError";
  }
}

/** The pending login expired or was used up; sign in or unlock again. */
export class TwoFactorExpiredError extends Error {
  constructor() {
    super("The sign-in expired. Start again.");
    this.name = "TwoFactorExpiredError";
  }
}

/** The server needs a recent login for this change; call `reauthenticate` first. */
export class ReauthenticationRequiredError extends Error {
  constructor() {
    super("Enter your master password again to confirm this change.");
    this.name = "ReauthenticationRequiredError";
  }
}

/** Maps the server's two-factor error codes to typed errors. */
function twoFactorError(error: unknown): unknown {
  if (!(error instanceof ApiError)) return error;
  switch (error.code) {
    case "invalid_two_factor_code":
      return new InvalidTwoFactorCodeError();
    case "two_factor_expired":
      return new TwoFactorExpiredError();
    case "reauthentication_required":
      return new ReauthenticationRequiredError();
    default:
      return error;
  }
}

/** Why a login runs: it decides what a completed second step does. */
type LoginPurpose = "signIn" | "unlock" | "reauth";

interface PendingTwoFactor {
  account: DeviceAccount;
  keys: Core.MasterKeys;
  challenge: TwoFactorChallenge;
  purpose: LoginPurpose;
}

/** A login counts as recent for this long (the server allows 10 minutes). */
const RECENT_LOGIN_MS = 9 * 60 * 1000;

/** How a second factor for turning two-factor sign-in off is given. */
export type DisableFactor =
  | { method: "totp" | "recovery"; code: string }
  | { method: "webauthn"; credentials?: CredentialsContainerLike };

const ACCOUNT_KEY = "passbox.account";
/**
 * Sharing trust store (pinned keys, organization fingerprints, verified key
 * directory head, manifest versions), per account. Public data whose
 * integrity matters: a changed copy could hide a key change.
 */
const TRUST_KEY = "passbox.trust";
/**
 * The server's device token for this device. It exempts the device from the
 * per-email login lockout (so failed logins by someone else cannot block
 * unlocking) and grants no access by itself. Every login replaces it.
 */
const DEVICE_TOKEN_KEY = "passbox.deviceToken";
/** Signed item usage events waiting for upload, per account. */
const USAGE_QUEUE_KEY = "passbox.usageQueue";
const MAX_USAGE_QUEUE = 1000;
const USAGE_FLUSH_DELAY_MS = 5000;
/** When the security aggregate was last reported, per account and organization. */
const SECURITY_REPORT_KEY = "passbox.securityReport";
const SECURITY_REPORT_INTERVAL_MS = 24 * 60 * 60 * 1000;
/** The breach catalogue from the server (public data, the same for everyone): `{ etag, catalog }`. */
const BREACH_CATALOG_KEY = "passbox.breachCatalog";
/** Per account: the newest catalogue date the user was alerted about (Unix ms). */
const BREACH_SEEN_KEY = "passbox.breachSeen";

/** What `refreshBreachCatalog` found. */
export interface BreachCatalogStatus {
  /** The server offers the catalogue (otherwise the bundled snapshot is used). */
  available: boolean;
  /** A newer catalogue was downloaded just now. */
  changed: boolean;
  version: string;
  /** Newest added or modified date of its entries (Unix ms). */
  updatedAt: number;
  entries: number;
  bundled: boolean;
}

/** What a client reports about an item of an organization's vault. */
export type ClientAuditAction = "item_viewed" | "secret_revealed" | "item_copied" | "item_filled";
/** Device-local item usage per account, encrypted with the account key. */
const USAGE_KEY = "passbox.usage";
/** Associated-data purpose of share link labels (`Keyring.encryptLocal`). */
const SHARE_LINK_PURPOSE = "share-link-label";

function roleRank(role: string): number {
  return role === "manage" ? 3 : role === "edit" ? 2 : role === "view" ? 1 : 0;
}

/** Someone who can see items in a vault, for `movePreview`. */
export interface MoveAudienceMember {
  accountId: string;
  /** Empty when this device does not know it. */
  email: string;
  role: string;
}

/** Who gains, loses and keeps access when items move (`movePreview`). */
export interface MovePreview {
  gain: MoveAudienceMember[];
  lose: MoveAudienceMember[];
  keep: MoveAudienceMember[];
}

/** Associated-data purpose of the usage map (`Keyring.encryptLocal`). */
const USAGE_PURPOSE = "item-usage";
/** Content types the server serves for website icons. */
const ICON_TYPES = new Set(["image/png", "image/x-icon", "image/jpeg", "image/gif", "image/webp"]);

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(binary);
}

/** Maps recovery error codes to typed errors. */
function recoveryError(error: unknown): unknown {
  if (error instanceof ApiError && error.code === "recovery_expired") return new RecoveryExpiredError();
  return error;
}

function cliLoginError(error: unknown): unknown {
  if (error instanceof ApiError && (error.code === "cli_login_expired" || error.status === 404)) {
    return new CliLoginExpiredError();
  }
  return error;
}

function deviceLinkError(error: unknown): unknown {
  if (error instanceof ApiError && error.code === "device_link_expired") return new InvalidDeviceCodeError();
  return error;
}

function isInvalidCredentials(error: unknown): boolean {
  return (
    (error instanceof Error && error.name === "InvalidCredentialsError") ||
    (error instanceof ApiError && error.code === "invalid_credentials")
  );
}

export interface PassboxClientOptions {
  core: CoreModule;
  /** API client whose `getToken` returns `client.token`. Use `createApi`. */
  api: PassboxApi;
  storage: KeyValueStorage;
  /** Identifies this device in the user's device list. */
  device?: { name: string; kind: ClientKind };
  /**
   * The web origin (`location.origin`) of a browser client, so sign-ins
   * offer the security keys registered for it.
   */
  origin?: string;
  /** Origin of the web app for invitation links, for example `https://passbox.example.com`. */
  linkBase?: string;
}

/**
 * Account, keys and vault data of one signed-in user.
 *
 * Unlocking always performs a full OPAQUE login, so the session token only
 * lives in memory and never needs to be stored.
 */
export class PassboxClient {
  private readonly core: CoreModule;
  private readonly api: PassboxApi;
  private readonly storage: KeyValueStorage;
  private readonly device: { name: string; kind: ClientKind } | undefined;
  private readonly origin: string | undefined;
  /** A login waiting for its second factor. */
  private pending: PendingTwoFactor | undefined;
  /** When the current session token was issued by a full login (ms). */
  private loginAt = 0;
  private readonly linkBase: string | undefined;
  private keyring: Core.Keyring | undefined;
  /** The account key encrypted with the master keys, kept to verify the master password offline. */
  private accountKeyCiphertext: string | undefined;
  private cursor = 0;
  private vaults = new Map<string, Vault>();
  private items = new Map<string, Item>();
  private errors = new Map<string, string>();
  private sharingView: SharingView = EMPTY_SHARING;
  /** Organizations the server holds read-only, from the last sync. */
  private orgLocks = new Map<string, OrgLock>();
  /** Website icons as data URLs (`null` = none), by domain. */
  private icons = new Map<string, Promise<string | null>>();
  /** Breach counts by password from `checkBreachedItems`; cleared on lock. */
  private breachCounts = new Map<string, number>();
  /** A full breach check ran since unlocking. */
  private breachChecked = false;
  /** The last email monitoring results, for the security report; cleared on lock. */
  private exposedEmails: ExposedEmail[] = [];
  /**
   * How breach checks reach Have I Been Pwned: `auto` (through the Passbox
   * server when it offers it, otherwise directly), `server` or `direct`.
   */
  breachMode: BreachMode = "auto";
  private listeners = new Set<() => void>();
  private snapshot: ClientSnapshot;
  /** A recovery by code waiting for its second factor. */
  private pendingCodeRecovery: { grant: RecoveryGrant; keys: Core.RecoveryKeys } | undefined;
  /** A proven recovery: the recovered account key and the token to set new credentials. */
  private recovering: { grant: RecoveryGrant; keyring: Core.Keyring } | undefined;
  private accountKeyCiphertextAfterRecovery: string | undefined;
  /** Device links opened on this device, by link ID. */
  private deviceLinkOffers = new Map<string, Core.DeviceLinkOffer>();
  /** The device code this (new) device entered. */
  private deviceLinkRequest: { request: Core.DeviceLinkRequest; claimToken: string } | undefined;
  /** Proof of an SSO sign-in for the next login (organizations that require SSO). */
  private ssoProof: string | undefined;
  /** Strength score of the master password entered at the last unlock. */
  private passwordScore: number | undefined;
  private usageTimer: ReturnType<typeof setTimeout> | undefined;
  /** Session token of the current unlock. */
  token: string | undefined;

  constructor(options: PassboxClientOptions) {
    this.core = options.core;
    this.api = options.api;
    this.storage = options.storage;
    this.device = options.device;
    this.origin = options.origin;
    this.linkBase = options.linkBase;
    this.snapshot = this.buildSnapshot();
  }

  // --- State -------------------------------------------------------------------

  get deviceAccount(): DeviceAccount | undefined {
    const raw = this.storage.getItem(ACCOUNT_KEY);
    return raw ? (JSON.parse(raw) as DeviceAccount) : undefined;
  }

  getSnapshot = (): ClientSnapshot => this.snapshot;

  subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  };

  private emit() {
    this.snapshot = this.buildSnapshot();
    for (const listener of this.listeners) listener();
  }

  private buildSnapshot(): ClientSnapshot {
    const account = this.deviceAccount;
    const sharing = this.sharingView;
    const roles = new Map(sharing.vaults.map((v) => [v.vaultId, v.role ?? undefined]));
    return {
      status: this.keyring ? "unlocked" : account ? "locked" : "signed-out",
      email: account?.email,
      vaults: [...this.vaults.values()]
        .map((vault) => ({ ...vault, role: vault.orgId ? roles.get(vault.id) : ("manage" as const) }))
        .sort((a, b) => a.name.localeCompare(b.name)),
      orgs: sharing.orgs,
      sharedVaults: sharing.vaults,
      sharingWarnings: sharing.warnings,
      policies: sharing.policies ?? [],
      effectivePolicy: sharing.effectivePolicy ?? NO_POLICY,
      items: [...this.items.values()]
        .filter((item) => item.data.trashedAt === undefined && item.data.archivedAt === undefined)
        .sort((a, b) => a.data.title.localeCompare(b.data.title)),
      archive: [...this.items.values()]
        .filter((item) => item.data.trashedAt === undefined && item.data.archivedAt !== undefined)
        .sort((a, b) => (b.data.archivedAt ?? 0) - (a.data.archivedAt ?? 0)),
      trash: [...this.items.values()]
        .filter((item) => item.data.trashedAt !== undefined)
        .sort((a, b) => (b.data.trashedAt ?? 0) - (a.data.trashedAt ?? 0)),
      errors: [...this.errors.values()],
    };
  }

  // --- Account -----------------------------------------------------------------

  /**
   * Creates an account with a personal vault and unlocks it. Returns the new
   * Secret Key, which the user must store in their Emergency Kit.
   *
   * `inviteToken` comes from an invitation link and is needed when the server
   * only allows invited accounts; `locale` is the language of mails.
   */
  async signUp(
    email: string,
    password: string,
    options: { inviteToken?: string; locale?: MailLocale } = {},
  ): Promise<{ secretKey: string; accountId: string }> {
    const { core } = this;
    const account: DeviceAccount = {
      email: email.trim().toLowerCase(),
      accountId: core.newId(),
      secretKey: core.generateSecretKey(),
      kdfSalt: core.generateKdfSalt(),
      kdfParams: JSON.parse(core.defaultKdfParams()) as KdfParams,
    };
    const keys = this.deriveKeys(account, password);
    try {
      const registration = core.RegistrationFlow.start(keys);
      const { registrationResponse } = await this.api.registerStart({
        accountId: account.accountId,
        email: account.email,
        registrationRequest: registration.request,
        ...(options.inviteToken ? { inviteToken: options.inviteToken } : {}),
      });
      const registrationUpload = registration.finish(registrationResponse);
      registration.free();

      const keyring = core.Keyring.create(keys, account.accountId);
      const vault = JSON.parse(keyring.createVault(JSON.stringify({ name: "Private" }))) as {
        id: string;
        encryptedKey: string;
        encryptedMeta: string;
      };
      await this.api.registerFinish({
        accountId: account.accountId,
        email: account.email,
        registrationUpload,
        kdfSalt: account.kdfSalt,
        kdfParams: account.kdfParams,
        encryptedAccountKey: keyring.encryptedAccountKey ?? "",
        vault,
        ...(options.inviteToken ? { inviteToken: options.inviteToken } : {}),
        ...(options.locale ? { locale: options.locale } : {}),
      });
      keyring.free();

      await this.login(account, keys, "signIn");
      this.storage.setItem(ACCOUNT_KEY, JSON.stringify(account));
      await this.sync();
      return { secretKey: account.secretKey, accountId: account.accountId };
    } finally {
      keys.free();
    }
  }

  /**
   * Signs in on a new device with email, master password and Secret Key.
   * Throws `TwoFactorRequiredError` when the account needs a second factor.
   */
  async signIn(email: string, password: string, secretKey: string, options: { ssoProof?: string } = {}): Promise<void> {
    const normalizedEmail = email.trim().toLowerCase();
    let normalizedKey: string;
    try {
      normalizedKey = this.core.normalizeSecretKey(secretKey);
    } catch {
      throw new InvalidCredentialsError();
    }
    const prelogin = await this.api.prelogin(normalizedEmail);
    const account: DeviceAccount = {
      email: normalizedEmail,
      accountId: prelogin.accountId,
      secretKey: normalizedKey,
      kdfSalt: prelogin.kdfSalt,
      kdfParams: prelogin.kdfParams,
    };
    const keys = this.deriveKeys(account, password);
    this.ssoProof = options.ssoProof;
    try {
      await this.login(account, keys, "signIn");
      this.storage.setItem(ACCOUNT_KEY, JSON.stringify(account));
    } finally {
      this.ssoProof = undefined;
      this.releaseKeys(keys);
    }
    this.passwordScore = this.estimateStrength(password).score;
    await this.sync();
  }

  /**
   * Unlocks the account remembered on this device. Throws
   * `TwoFactorRequiredError` when the account needs a second factor and
   * this device is not remembered.
   */
  async unlock(password: string, options: { ssoProof?: string } = {}): Promise<void> {
    const account = this.deviceAccount;
    if (!account) throw new Error("no account on this device");
    const keys = this.deriveKeys(account, password);
    this.ssoProof = options.ssoProof;
    try {
      await this.login(account, keys, "unlock");
    } finally {
      this.ssoProof = undefined;
      this.releaseKeys(keys);
    }
    this.passwordScore = this.estimateStrength(password).score;
    await this.sync();
    void this.flushItemUsage().catch(() => undefined);
  }

  // --- Two-factor sign-in ----------------------------------------------------------

  /** The login waiting for a second factor, if any. */
  get pendingTwoFactor(): TwoFactorChallenge | undefined {
    return this.pending?.challenge;
  }

  /**
   * Completes the pending login with a 6-digit code or a recovery code.
   * `rememberDevice` skips the second step on this device for 30 days.
   * Throws `InvalidTwoFactorCodeError` (try again) or `TwoFactorExpiredError`
   * (start over). Returns the number of recovery codes left after using one.
   */
  async completeTwoFactor(
    factor: SecondFactor,
    options: { rememberDevice?: boolean } = {},
  ): Promise<{ recoveryCodesRemaining?: number }> {
    const pending = this.pending;
    if (!pending) throw new TwoFactorExpiredError();
    let session: Awaited<ReturnType<PassboxApi["loginTwoFactor"]>>;
    try {
      session = await this.api.loginTwoFactor({
        ...factor,
        challengeToken: pending.challenge.challengeToken,
        rememberDevice: options.rememberDevice ?? false,
      });
    } catch (error) {
      const typed = twoFactorError(error);
      if (typed instanceof TwoFactorExpiredError) this.cancelTwoFactor();
      throw typed;
    }
    this.pending = undefined;
    try {
      if (session.deviceToken) this.storage.setItem(DEVICE_TOKEN_KEY, session.deviceToken);
      await this.useSession(pending.keys, session.token, pending.purpose);
      if (pending.purpose === "signIn") this.storage.setItem(ACCOUNT_KEY, JSON.stringify(pending.account));
    } finally {
      pending.keys.free();
    }
    if (pending.purpose !== "reauth") await this.sync();
    return session.recoveryCodesRemaining === undefined
      ? {}
      : { recoveryCodesRemaining: session.recoveryCodesRemaining };
  }

  /**
   * Completes the pending login with a security key or passkey: asks the
   * browser (`navigator.credentials` unless `credentials` is given) to sign
   * the server's challenge.
   */
  async completeTwoFactorWithSecurityKey(
    options: { rememberDevice?: boolean; credentials?: CredentialsContainerLike; signal?: AbortSignal } = {},
  ): Promise<{ recoveryCodesRemaining?: number }> {
    const request = this.pending?.challenge.webauthn;
    if (!request) throw new TwoFactorExpiredError();
    const webauthn = await getAssertion(options.credentials ?? navigator.credentials, request, options.signal);
    return this.completeTwoFactor(
      { method: "webauthn", webauthn },
      options.rememberDevice === undefined ? {} : { rememberDevice: options.rememberDevice },
    );
  }

  /** Drops the pending login. */
  cancelTwoFactor(): void {
    this.pending?.keys.free();
    this.pending = undefined;
  }

  /**
   * Proves the master password again with a fresh login, for changes the
   * server only accepts from a recent login (adding a second factor, for
   * example). The vault stays unlocked; a wrong password throws
   * `InvalidCredentialsError` without locking. May throw
   * `TwoFactorRequiredError`; then `completeTwoFactor` finishes it.
   */
  async reauthenticate(password: string): Promise<void> {
    const account = this.deviceAccount;
    if (!account) throw new Error("no account on this device");
    const keys = await this.checkedKeys(account, password);
    try {
      await this.login(account, keys, "reauth");
    } finally {
      this.releaseKeys(keys);
    }
  }

  /** Whether the session comes from a login recent enough for sensitive changes. */
  get hasRecentLogin(): boolean {
    return this.token !== undefined && Date.now() - this.loginAt < RECENT_LOGIN_MS;
  }

  /** Two-factor status of the account. */
  async twoFactorStatus(): Promise<TwoFactorStatus> {
    this.requireKeyring();
    return this.api.twoFactorStatus();
  }

  /**
   * Starts setting up an authenticator app. Show `uri` as a QR code (and
   * `secret` for typing), then call `confirmTotpSetup` with a first code.
   * Throws `ReauthenticationRequiredError` without a recent login.
   */
  async startTotpSetup(): Promise<{ secret: string; uri: string }> {
    this.requireKeyring();
    return this.twoFactorCall(() => this.api.totpStart());
  }

  /** Turns the authenticator app on. Returns new recovery codes (shown once) if the account had none. */
  async confirmTotpSetup(code: string): Promise<{ recoveryCodes?: string[] }> {
    this.requireKeyring();
    return this.twoFactorCall(() => this.api.totpConfirm(code.replace(/\s/g, "")));
  }

  /** Removes the authenticator app (only while a security key remains). */
  async removeTotp(): Promise<void> {
    this.requireKeyring();
    await this.twoFactorCall(() => this.api.totpRemove());
  }

  /**
   * Registers a security key or passkey as a second factor: the browser asks
   * the user to touch it. Returns new recovery codes if the account had none.
   */
  async addSecurityKey(
    name: string,
    options: { credentials?: CredentialsContainerLike; origin?: string; signal?: AbortSignal } = {},
  ): Promise<{ recoveryCodes?: string[] }> {
    this.requireKeyring();
    const origin = options.origin ?? this.origin ?? globalThis.location?.origin ?? "";
    const { registrationId, publicKey } = await this.twoFactorCall(() => this.api.webauthnRegisterStart(origin));
    const credential = await createCredential(options.credentials ?? navigator.credentials, publicKey, options.signal);
    const result = await this.twoFactorCall(() =>
      this.api.webauthnRegisterFinish({ registrationId, name, credential }),
    );
    return result.recoveryCodes ? { recoveryCodes: result.recoveryCodes } : {};
  }

  /** Removes a security key (only while another second factor remains). */
  async removeSecurityKey(id: string): Promise<void> {
    this.requireKeyring();
    await this.twoFactorCall(() => this.api.webauthnRemove(id));
  }

  /** Replaces all recovery codes with 10 new ones, shown once. */
  async regenerateRecoveryCodes(): Promise<string[]> {
    this.requireKeyring();
    return (await this.twoFactorCall(() => this.api.regenerateRecoveryCodes())).recoveryCodes;
  }

  /**
   * Turns two-factor sign-in off. Needs a current code, a recovery code or
   * the security key (`{ method: "webauthn" }`).
   */
  async disableTwoFactor(factor: DisableFactor): Promise<void> {
    this.requireKeyring();
    if (factor.method !== "webauthn") {
      await this.twoFactorCall(() => this.api.disableTwoFactor(factor));
      return;
    }
    const challenge = await this.twoFactorCall(() => this.api.twoFactorChallenge(this.origin));
    if (!challenge.webauthn) throw new Error("no security key for this site");
    const webauthn = await getAssertion(factor.credentials ?? navigator.credentials, challenge.webauthn);
    await this.twoFactorCall(() =>
      this.api.disableTwoFactor({ method: "webauthn", webauthn, challengeToken: challenge.challengeToken }),
    );
  }

  private async twoFactorCall<T>(call: () => Promise<T>): Promise<T> {
    try {
      return await call();
    } catch (error) {
      throw twoFactorError(error);
    }
  }

  // --- Account security ----------------------------------------------------------

  /** Devices signed in to this account. */
  async sessions(): Promise<SessionInfo[]> {
    this.requireKeyring();
    return this.api.sessions();
  }

  /** Signs out one device. */
  async revokeSession(id: string): Promise<void> {
    this.requireKeyring();
    await this.api.revokeSession(id);
  }

  /** Signs out every device except this one. */
  async revokeOtherSessions(): Promise<void> {
    this.requireKeyring();
    await this.api.revokeOtherSessions();
  }

  /** The account as the server sees it, including whether it is an instance admin. */
  async accountInfo(): Promise<Account> {
    this.requireKeyring();
    return this.api.account();
  }

  /** Mail language and notification settings stored on the server. */
  async preferences(): Promise<AccountPreferences> {
    this.requireKeyring();
    return this.api.preferences();
  }

  async updatePreferences(changes: {
    locale?: MailLocale | "";
    notifyNewDevice?: boolean;
  }): Promise<AccountPreferences> {
    this.requireKeyring();
    return this.api.updatePreferences(changes);
  }

  /**
   * Instance administration (settings, accounts, mail, invitations, audit
   * log). The server answers 403 `forbidden` unless the account is an
   * instance admin.
   */
  get admin(): AdminApi {
    this.requireKeyring();
    return this.api;
  }

  /** Recent sign-ins, failed attempts and other security events. */
  async activity(limit = 50): Promise<AccountEvent[]> {
    this.requireKeyring();
    return this.api.accountEvents(limit);
  }

  /**
   * Changes the master password. The current password is checked on the
   * device; unless the session comes from a recent login, a fresh login
   * follows (the server only accepts the change from a recent login), which
   * may throw `TwoFactorRequiredError`: complete it and call this again.
   * Vaults and items stay as they are; every other device is signed out.
   */
  async changeMasterPassword(currentPassword: string, newPassword: string): Promise<void> {
    const account = this.deviceAccount;
    if (!account) throw new Error("no account on this device");
    this.requireKeyring();
    const currentKeys = await this.checkedKeys(account, currentPassword);
    try {
      if (!this.hasRecentLogin) await this.login(account, currentKeys, "reauth");
    } finally {
      this.releaseKeys(currentKeys);
    }
    const keyring = this.requireKeyring();
    const next: DeviceAccount = { ...account, kdfSalt: this.core.generateKdfSalt() };
    const newKeys = this.deriveKeys(next, newPassword);
    try {
      const registration = this.core.RegistrationFlow.start(newKeys);
      const { registrationResponse } = await this.api.passwordChangeStart({
        registrationRequest: registration.request,
      });
      const registrationUpload = registration.finish(registrationResponse);
      registration.free();
      const encryptedAccountKey = keyring.wrapAccountKey(newKeys);
      await this.api.passwordChangeFinish({
        registrationUpload,
        kdfSalt: next.kdfSalt,
        kdfParams: next.kdfParams,
        encryptedAccountKey,
      });
      this.storage.setItem(ACCOUNT_KEY, JSON.stringify(next));
      this.accountKeyCiphertext = encryptedAccountKey;
    } finally {
      newKeys.free();
    }
  }

  /** The change of the account's address that waits for its code, if any. */
  async pendingEmailChange(): Promise<PendingEmailChange | null> {
    this.requireKeyring();
    return this.api.emailChangePending();
  }

  /**
   * Starts changing the account's address: the server mails a code to
   * `newEmail`, and `confirmEmailChange` finishes the change. Unless the
   * session comes from a recent login, a fresh login with `password`
   * follows first, which may throw `TwoFactorRequiredError`: complete it and
   * call this again.
   */
  async startEmailChange(password: string, newEmail: string, locale?: string): Promise<PendingEmailChange> {
    const account = this.deviceAccount;
    if (!account) throw new Error("no account on this device");
    this.requireKeyring();
    if (!this.hasRecentLogin) {
      const keys = await this.checkedKeys(account, password);
      try {
        await this.login(account, keys, "reauth");
      } finally {
        this.releaseKeys(keys);
      }
    }
    return this.api.emailChangeStart({ email: newEmail.trim().toLowerCase(), locale });
  }

  /**
   * Finishes the change with the mailed code. This device signs in with the
   * new address from now on; other devices need it at their next sign-in.
   */
  async confirmEmailChange(code: string): Promise<string> {
    this.requireKeyring();
    const { email } = await this.api.emailChangeConfirm(code);
    const account = this.deviceAccount;
    if (account) this.storage.setItem(ACCOUNT_KEY, JSON.stringify({ ...account, email }));
    this.emit();
    return email;
  }

  async cancelEmailChange(): Promise<void> {
    this.requireKeyring();
    await this.api.emailChangeCancel();
  }

  /**
   * Checks the master password without contacting the server: derives the
   * keys locally and tries to open the account key with them. Use it to
   * confirm the user before showing the Emergency Kit or other sensitive
   * screens. Requires an unlocked vault.
   */
  async verifyMasterPassword(password: string): Promise<boolean> {
    const keyring = this.requireKeyring();
    const account = this.deviceAccount;
    if (!account) return false;
    // A resumed session (`restoreSession`) has no ciphertext yet; fetch it once.
    this.accountKeyCiphertext ??= keyring.encryptedAccountKey ?? (await this.api.account()).encryptedAccountKey;
    let keys: Core.MasterKeys;
    try {
      keys = this.deriveKeys(account, password);
    } catch (error) {
      if (error instanceof InvalidCredentialsError) return false;
      throw error;
    }
    try {
      this.core.Keyring.unlock(keys, account.accountId, this.accountKeyCiphertext).free();
      return true;
    } catch (error) {
      if (isInvalidCredentials(error)) return false;
      throw error;
    } finally {
      keys.free();
    }
  }

  /** Exports the unlocked session, or `undefined` when locked. */
  exportSession(): SessionState | undefined {
    const account = this.deviceAccount;
    if (!this.keyring || !this.token || !account) return undefined;
    const { sessionKey, blob } = JSON.parse(this.keyring.exportSession()) as { sessionKey: string; blob: string };
    return { accountId: account.accountId, sessionKey, blob, token: this.token };
  }

  /**
   * Resumes a session exported with `exportSession` and syncs. Throws (and
   * stays locked) if the state does not belong to this device's account or
   * the server session has ended.
   */
  async restoreSession(state: SessionState): Promise<void> {
    const account = this.deviceAccount;
    if (!account || account.accountId !== state.accountId) throw new Error("session belongs to another account");
    this.clearSession();
    this.keyring = this.core.Keyring.importSession(state.sessionKey, state.accountId, state.blob);
    this.loadTrust(this.keyring, state.accountId);
    this.token = state.token;
    try {
      await this.sync();
    } catch (error) {
      if (error instanceof ApiError && error.status === 401) {
        this.clearSession();
        this.emit();
      }
      throw error;
    }
  }

  /** Forgets all decrypted data and keys. The account stays on this device. */
  lock(): void {
    this.cancelTwoFactor();
    // The API client reads the token when the request starts, so start the
    // logout before clearing it. Best effort: the session expires anyway.
    const logout = this.token ? this.api.logout() : undefined;
    this.clearSession();
    void logout?.catch(() => undefined);
    this.emit();
  }

  /** Locks and removes the account from this device. */
  signOut(): void {
    const account = this.deviceAccount;
    this.lock();
    if (account) this.storage.removeItem(`${USAGE_KEY}.${account.accountId}`);
    this.storage.removeItem(ACCOUNT_KEY);
    this.storage.removeItem(DEVICE_TOKEN_KEY);
    this.emit();
  }

  private clearSession() {
    this.keyring?.free();
    this.keyring = undefined;
    this.accountKeyCiphertext = undefined;
    this.token = undefined;
    this.loginAt = 0;
    this.cursor = 0;
    this.vaults.clear();
    this.items.clear();
    this.errors.clear();
    this.breachCounts.clear();
    this.breachChecked = false;
    this.exposedEmails = [];
    this.sharingView = EMPTY_SHARING;
    this.orgLocks = new Map();
    this.passwordScore = undefined;
    if (this.usageTimer) clearTimeout(this.usageTimer);
    this.usageTimer = undefined;
  }

  private deriveKeys(account: DeviceAccount, password: string): Core.MasterKeys {
    try {
      return this.core.MasterKeys.derive(
        password,
        account.secretKey,
        account.accountId,
        account.kdfSalt,
        JSON.stringify(account.kdfParams),
      );
    } catch (error) {
      throw isInvalidCredentials(error) ? new InvalidCredentialsError() : error;
    }
  }

  /** Frees master keys unless a pending second step still needs them. */
  private releaseKeys(keys: Core.MasterKeys) {
    if (this.pending?.keys !== keys) keys.free();
  }

  /**
   * Derives the master keys and, while unlocked, checks them on the device
   * against the account key, so a typo never reaches the server.
   */
  private async checkedKeys(account: DeviceAccount, password: string): Promise<Core.MasterKeys> {
    const keys = this.deriveKeys(account, password);
    const keyring = this.keyring;
    if (!keyring) return keys;
    try {
      this.accountKeyCiphertext ??= keyring.encryptedAccountKey ?? (await this.api.account()).encryptedAccountKey;
      this.core.Keyring.unlock(keys, account.accountId, this.accountKeyCiphertext).free();
      return keys;
    } catch (error) {
      keys.free();
      throw isInvalidCredentials(error) ? new InvalidCredentialsError() : error;
    }
  }

  /** Runs the OPAQUE login. Returns a session or the second-factor challenge. */
  private async authenticate(account: DeviceAccount, keys: Core.MasterKeys): Promise<LoginFinishResult> {
    const flow = this.core.LoginFlow.start(keys);
    try {
      // The server ignores a device token that belongs to another account.
      const deviceToken = this.storage.getItem(DEVICE_TOKEN_KEY) ?? undefined;
      const start = await this.api.loginStart({
        email: account.email,
        credentialRequest: flow.request,
        ...(deviceToken ? { deviceToken } : {}),
      });
      const credentialFinalization = flow.finish(start.credentialResponse);
      const finish = await this.api.loginFinish({
        loginId: start.loginId,
        credentialFinalization,
        ...(this.device ? { deviceName: this.device.name, clientKind: this.device.kind } : {}),
        ...(this.origin ? { origin: this.origin } : {}),
        ...(this.ssoProof ? { ssoProof: this.ssoProof } : {}),
      });
      // A proof is single use, also when the login failed.
      this.ssoProof = undefined;
      if (!isTwoFactorChallenge(finish) && finish.deviceToken) {
        this.storage.setItem(DEVICE_TOKEN_KEY, finish.deviceToken);
      }
      return finish;
    } catch (error) {
      throw isInvalidCredentials(error) ? new InvalidCredentialsError() : error;
    } finally {
      flow.free();
    }
  }

  /**
   * Runs the OPAQUE login and unlocks the keyring (or, to reauthenticate,
   * only replaces the session token). When the account needs a second
   * factor, keeps `keys` for the pending login and throws
   * `TwoFactorRequiredError`.
   */
  private async login(account: DeviceAccount, keys: Core.MasterKeys, purpose: LoginPurpose): Promise<void> {
    let result: LoginFinishResult;
    try {
      result = await this.authenticate(account, keys);
    } catch (error) {
      if (purpose !== "reauth") this.clearSession();
      throw error;
    }
    if (isTwoFactorChallenge(result)) {
      if (purpose !== "reauth") this.clearSession();
      this.cancelTwoFactor();
      this.pending = { account, keys, challenge: result, purpose };
      if (purpose !== "reauth") this.emit();
      throw new TwoFactorRequiredError(result);
    }
    await this.useSession(keys, result.token, purpose);
  }

  /** Takes a session token from a complete login. */
  private async useSession(keys: Core.MasterKeys, token: string, purpose: LoginPurpose) {
    if (purpose === "reauth") {
      this.token = token;
      this.loginAt = Date.now();
      return;
    }
    try {
      this.clearSession();
      this.token = token;
      const remote = await this.api.account();
      this.keyring = this.core.Keyring.unlock(keys, remote.accountId, remote.encryptedAccountKey);
      this.loadTrust(this.keyring, remote.accountId);
      this.accountKeyCiphertext = remote.encryptedAccountKey;
      this.loginAt = Date.now();
    } catch (error) {
      this.clearSession();
      throw isInvalidCredentials(error) ? new InvalidCredentialsError() : error;
    }
  }

  // --- Sync --------------------------------------------------------------------

  /** Fetches and decrypts everything that changed since the last sync. */
  async sync(): Promise<void> {
    const keyring = this.requireKeyring();
    await this.ensureAccountKeys(keyring);
    const since = this.cursor;
    const delta = await this.api.sync(since, { sharing: true });
    if (this.keyring !== keyring) return; // locked meanwhile
    const missingKey = await this.apply(keyring, delta);
    if (missingKey && since !== 0 && this.keyring === keyring) {
      // A shared vault's key could not be opened: fetch everything again once.
      const full = await this.api.sync(0, { sharing: true });
      if (this.keyring !== keyring) return;
      await this.apply(keyring, full);
    }
    this.emit();
  }

  /** Loads the account's key pairs, creating and publishing them on the first unlock after the update. */
  private async ensureAccountKeys(keyring: Core.Keyring): Promise<void> {
    if (keyring.hasAccountKeys()) return;
    let keys: AccountKeys | undefined;
    try {
      keys = await this.api.sharing.ownKeys();
    } catch (error) {
      if (!(error instanceof ApiError && error.status === 404)) throw error;
    }
    if (this.keyring !== keyring || keyring.hasAccountKeys()) return;
    if (keys) {
      keyring.loadAccountKeys(keys.bundle, keys.bundleSignature, keys.encryptedPrivate);
    } else {
      const upload = JSON.parse(keyring.createAccountKeys(Date.now())) as AccountKeys;
      await this.api.sharing.publishKeys(upload);
    }
  }

  private loadTrust(keyring: Core.Keyring, accountId: string) {
    const raw = this.storage.getItem(`${TRUST_KEY}.${accountId}`);
    if (!raw) return;
    try {
      keyring.setTrustStore(raw);
    } catch {
      // An unreadable trust store starts over (trust on first use).
    }
  }

  private saveTrust(keyring: Core.Keyring) {
    this.storage.setItem(`${TRUST_KEY}.${keyring.accountId}`, keyring.trustStore());
  }

  /** Applies a sync delta. Returns whether a verified shared vault is missing its current key. */
  private async apply(keyring: Core.Keyring, delta: SyncResponse): Promise<boolean> {
    let uploads: SharingReport["wrappedKeys"] = [];
    if (delta.sharing) {
      const report = JSON.parse(keyring.applySharing(JSON.stringify(delta.sharing))) as SharingReport;
      this.orgLocks = orgLocks(delta.sharing);
      this.sharingView = withOrgLocks(report.view, this.orgLocks);
      uploads = report.wrappedKeys;
      this.saveTrust(keyring);
      const accessible = new Set(report.view.vaults.map((v) => v.vaultId));
      for (const vault of [...this.vaults.values()]) {
        if (vault.orgId && !accessible.has(vault.id)) {
          this.vaults.delete(vault.id);
          for (const item of [...this.items.values()]) if (item.vaultId === vault.id) this.items.delete(item.id);
        }
      }
    }
    for (const vault of delta.vaults) {
      const keyEpoch = vault.keyEpoch ?? 0;
      try {
        if (!vault.orgId && !keyring.hasVault(vault.id)) keyring.addVault(vault.id, vault.encryptedKey);
        const meta = parseVaultMeta(keyring.decryptVaultMetaAt(vault.id, keyEpoch, vault.encryptedMeta));
        this.vaults.set(vault.id, {
          id: vault.id,
          name: meta.name,
          revision: vault.revision,
          keyEpoch,
          ...(vault.orgId ? { orgId: vault.orgId } : {}),
        });
        this.errors.delete(vault.id);
      } catch (error) {
        this.errors.set(vault.id, `Vault ${vault.id} could not be decrypted: ${String(error)}`);
      }
    }
    for (const item of delta.items) {
      if (item.deleted || item.encryptedData === null) {
        // A tombstone from a vault the item moved out of: keep the item when
        // this device already has it in its new vault.
        const known = this.items.get(item.id);
        if (known && known.vaultId !== item.vaultId) continue;
        this.items.delete(item.id);
        this.errors.delete(item.id);
        continue;
      }
      try {
        const keyEpoch = item.keyEpoch ?? 0;
        const json = keyring.decryptItemAt(item.vaultId, keyEpoch, item.id, item.revision, item.encryptedData);
        this.items.set(item.id, {
          id: item.id,
          vaultId: item.vaultId,
          revision: item.revision,
          updatedAt: item.updatedAt,
          createdAt: item.createdAt ?? 0,
          keyEpoch,
          data: parseItemData(json),
        });
        this.errors.delete(item.id);
      } catch (error) {
        this.items.delete(item.id);
        this.errors.set(item.id, `Item ${item.id} could not be decrypted: ${String(error)}`);
      }
    }
    this.cursor = Math.max(this.cursor, delta.cursor);
    // Own copies of newly opened vault keys; best effort.
    for (const upload of uploads) {
      await this.api.sharing.putWrappedKey(upload.vaultId, upload.keyEpoch, upload.wrappedKey).catch(() => undefined);
    }
    return this.sharingView.vaults.some((v) => v.verified && !v.hasKey);
  }

  private requireKeyring(): Core.Keyring {
    if (!this.keyring) throw new Error("vault is locked");
    return this.keyring;
  }

  // --- Editing -----------------------------------------------------------------

  /** Creates a new vault and returns its ID. */
  async createVault(name: string): Promise<string> {
    const keyring = this.requireKeyring();
    this.ensurePersonalVaultsAllowed();
    const vault = JSON.parse(keyring.createVault(JSON.stringify({ name }))) as {
      id: string;
      encryptedKey: string;
      encryptedMeta: string;
    };
    await this.api.createVault(vault);
    await this.sync();
    return vault.id;
  }

  /** Renames a vault. */
  async renameVault(id: string, name: string): Promise<void> {
    const keyring = this.requireKeyring();
    const vault = this.vaults.get(id);
    if (!vault) throw new Error("unknown vault");
    const revision = vault.revision + 1;
    try {
      await this.api.updateVault(id, {
        revision,
        encryptedMeta: keyring.encryptVaultMetaAt(id, vault.keyEpoch ?? 0, JSON.stringify({ name })),
        ...(vault.orgId ? { keyEpoch: vault.keyEpoch ?? 0 } : {}),
      });
    } catch (error) {
      await this.handleWriteError(error);
    }
    await this.sync();
  }

  /** Creates an item and returns its ID. */
  async createItem(vaultId: string, data: ItemData): Promise<string> {
    if (!this.vaults.get(vaultId)?.orgId) this.ensurePersonalVaultsAllowed();
    const id = this.core.newId();
    await this.writeItem(vaultId, id, 1, data);
    return id;
  }

  /**
   * Saves a new version of an existing item. A replaced password is added
   * to the password history; history and trash state always come from the
   * stored version, not from `data`.
   */
  async updateItem(id: string, data: ItemData): Promise<void> {
    const item = this.items.get(id);
    if (!item) throw new Error("unknown item");
    await this.writeItem(item.vaultId, id, item.revision + 1, this.nextVersion(item, data));
  }

  private nextVersion(item: Item, data: ItemData): ItemData {
    const {
      passwordHistory: _ignored,
      trashedAt: _trashed,
      archivedAt: _archived,
      attachments: _attachments,
      ...rest
    } = data;
    const next: ItemData = rest;
    // Archive state and attachments have their own calls; an editor with an
    // older copy cannot undo them. An unknown category stays when the
    // editor only knows "other".
    if (item.data.archivedAt !== undefined) next.archivedAt = item.data.archivedAt;
    if (item.data.attachments?.length) next.attachments = item.data.attachments;
    if (next.category === "other" && categoryName(next) === "other" && categoryName(item.data) !== "other") {
      next.category = item.data.category;
      const unknown = (item.data as ItemData & { [UNKNOWN_CATEGORY]?: string })[UNKNOWN_CATEGORY];
      if (unknown) (next as ItemData & { [UNKNOWN_CATEGORY]?: string })[UNKNOWN_CATEGORY] = unknown;
    }
    const oldPassword = fieldValue(item.data, FIELD.password);
    let history = item.data.passwordHistory ?? [];
    if (oldPassword !== undefined && fieldValue(data, FIELD.password) !== oldPassword) {
      history = [{ value: oldPassword, replacedAt: Date.now() }, ...history].slice(0, PASSWORD_HISTORY_LEN);
    }
    if (history.length > 0) next.passwordHistory = history;
    if (item.data.trashedAt !== undefined) next.trashedAt = item.data.trashedAt;
    return next;
  }

  /**
   * Creates many items (and, with `updateId`, updates existing ones as
   * `updateItem` does) with several requests in flight and a single sync at
   * the end, for imports of tens of thousands of items. Progress is reported
   * after each item; the snapshot is refreshed every `batchSize` items.
   * Items that fail are reported and do not stop the import. Stops early
   * when `signal` is aborted.
   */
  async importItems(
    vaultId: string,
    entries: readonly ImportEntry[],
    options: ImportItemsOptions = {},
  ): Promise<ImportItemsResult> {
    const keyring = this.requireKeyring();
    if (!this.vaults.has(vaultId)) throw new Error("unknown vault");
    const maxConcurrency = Math.max(1, options.concurrency ?? 6);
    const batchSize = Math.max(1, options.batchSize ?? 200);
    const result: ImportItemsResult = { created: 0, updated: 0, failed: [] };
    const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
    // Fewer requests run in parallel while the server is struggling (for
    // example 503 responses while its connection pool is exhausted), more
    // again once it recovers.
    let limit = maxConcurrency;
    let streak = 0;
    let next = 0;
    let done = 0;
    let sinceEmit = 0;
    const active = () => next < entries.length && !options.signal?.aborted && this.keyring === keyring;

    /** One write, retried on server errors and dropped connections. */
    const save = async (entry: ImportEntry) => {
      const existing = entry.updateId ? this.items.get(entry.updateId) : undefined;
      const id = existing?.id ?? this.core.newId();
      for (let attempt = 0; ; attempt++) {
        try {
          if (existing) {
            await this.putItem(existing.vaultId, id, existing.revision + 1, this.nextVersion(existing, entry.data));
            result.updated++;
          } else {
            await this.putItem(vaultId, id, 1, entry.data);
            result.created++;
          }
          if (++streak >= 20 && limit < maxConcurrency) {
            limit++;
            streak = 0;
          }
          return;
        } catch (error) {
          const retryable =
            error instanceof TypeError || (error instanceof ApiError && (error.status >= 500 || error.status === 429));
          // A create that reached the server before the connection dropped.
          if (attempt > 0 && !existing && error instanceof ApiError && error.code === "conflict") {
            result.created++;
            return;
          }
          if (!retryable || attempt >= 7 || options.signal?.aborted) throw error;
          limit = Math.max(1, Math.floor(limit / 2));
          streak = 0;
          await sleep(Math.min(2000, 50 * 2 ** attempt) * (0.5 + Math.random()));
        }
      }
    };

    const worker = async (index: number) => {
      while (active()) {
        if (index >= limit) {
          await sleep(50);
          continue;
        }
        const entry = entries[next++] as ImportEntry;
        try {
          await save(entry);
        } catch (error) {
          result.failed.push({
            title: entry.data.title,
            error: error instanceof Error ? error.message : String(error),
          });
        }
        done++;
        options.onProgress?.(done, entries.length);
        if (++sinceEmit >= batchSize) {
          sinceEmit = 0;
          this.emit();
          // Let the UI paint between batches.
          await sleep(0);
        }
      }
    };
    await Promise.all(Array.from({ length: Math.min(maxConcurrency, entries.length) }, (_, i) => worker(i)));
    this.emit();
    if (this.keyring === keyring) await this.sync();
    return result;
  }

  /** Moves an item to the trash. It can be restored for 30 days. */
  async trashItem(id: string): Promise<void> {
    await this.setTrashed(id, Date.now());
  }

  /** Restores an item from the trash. */
  async restoreItem(id: string): Promise<void> {
    await this.setTrashed(id, undefined);
  }

  private async setTrashed(id: string, at: number | undefined) {
    const item = this.items.get(id);
    if (!item) throw new Error("unknown item");
    const { trashedAt: _previous, ...data } = item.data;
    await this.writeItem(item.vaultId, id, item.revision + 1, at === undefined ? data : { ...data, trashedAt: at });
  }

  /**
   * Permanently deletes items that have been in the trash for more than 30
   * days, or every trashed item when `all` is set. Items changed on another
   * device meanwhile are skipped. Returns the number deleted.
   */
  async purgeTrash(all = false): Promise<number> {
    const cutoff = Date.now() - TRASH_RETENTION_MS;
    let deleted = 0;
    for (const item of this.snapshot.trash) {
      if (!all && (item.data.trashedAt ?? Number.POSITIVE_INFINITY) > cutoff) continue;
      try {
        await this.deleteItem(item.id);
        deleted++;
      } catch (error) {
        if (!(error instanceof ConflictError)) throw error;
      }
    }
    return deleted;
  }

  /**
   * Rates a password with the account email (and `extraInputs`, such as an
   * email typed during sign-up) as context.
   */
  estimateStrength(password: string, extraInputs: readonly string[] = []): Strength {
    return estimateStrength(this.core, password, [...this.strengthContext(), ...extraInputs]);
  }

  /** Watchtower analysis of the items outside the trash. */
  health(): VaultHealth {
    return analyzeVault(this.core, this.snapshot.items, this.strengthContext());
  }

  // --- Item extras ---------------------------------------------------------------

  /**
   * Earlier versions of an item (up to 20, newest first), decrypted here.
   * To restore one, pass its `data` to `updateItem`: that saves it as a new
   * version and keeps the password history.
   */
  async itemHistory(id: string): Promise<ItemVersion[]> {
    const keyring = this.requireKeyring();
    const item = this.items.get(id);
    if (!item) throw new Error("unknown item");
    const { versions } = await this.api.itemVersions(id);
    return versions.map((version) => {
      let data: ItemData | null = null;
      try {
        data = parseItemData(
          keyring.decryptItemAt(item.vaultId, version.keyEpoch, id, version.revision, version.encryptedData),
        );
      } catch {
        data = null;
      }
      return { revision: version.revision, updatedAt: version.updatedAt, updatedBy: version.updatedBy, data };
    });
  }

  /**
   * The website icon of `domain` as a `data:` URL for an `<img>`, or `null`.
   * Popular sites come from the icons bundled with the app
   * (`@passbox/site-icons`) without any request; for those the server is
   * never asked. Others are loaded through the user's own server (no
   * request reaches the website from this device). Cached in memory.
   * Respect the user's icon setting.
   */
  iconUrl(domain: string): Promise<string | null> {
    const key = domain.trim().toLowerCase();
    if (!key) return Promise.resolve(null);
    let icon = this.icons.get(key);
    if (!icon) {
      icon = this.loadIcon(key).catch((error: unknown) => {
        // Try again next time (offline, rate limited).
        this.icons.delete(key);
        throw error;
      });
      this.icons.set(key, icon);
    }
    return icon;
  }

  private async loadIcon(key: string): Promise<string | null> {
    let bundled = false;
    try {
      bundled = await isBundledSite(key);
    } catch {
      // The bundled pack could not be loaded: only the server can help.
    }
    if (bundled) {
      // A bundled site that cannot be drawn shows its monogram; asking the
      // server instead would tell it about the site.
      return bundledSiteIcon(key).catch(() => null);
    }
    const response = await this.api.icon(key);
    return response && ICON_TYPES.has(response.contentType)
      ? `data:${response.contentType};base64,${bytesToBase64(response.bytes)}`
      : null;
  }

  /**
   * Checks the passwords of all logins outside the trash against Have I
   * Been Pwned (k-anonymity, see `breachCount`) and returns the breached
   * ones, most breached first. Results stay in memory until the vault locks
   * and feed `itemHealth`. Opt-in only.
   */
  async checkBreachedItems(
    fetchImpl?: typeof globalThis.fetch,
    onProgress?: (done: number, total: number) => void,
  ): Promise<BreachedItem[]> {
    const byPassword = new Map<string, string[]>();
    for (const item of this.snapshot.items) {
      const password = item.data.category === "login" ? fieldValue(item.data, FIELD.password) : undefined;
      if (password) byPassword.set(password, [...(byPassword.get(password) ?? []), item.id]);
    }
    const ranges = new Map<string, Promise<string>>();
    const found: BreachedItem[] = [];
    let done = 0;
    onProgress?.(0, byPassword.size);
    for (const [password, ids] of byPassword) {
      let count = this.breachCounts.get(password);
      if (count === undefined) {
        const { prefix, suffix } = await breachHashParts(password);
        let range = ranges.get(prefix);
        if (!range) {
          range = this.breachRange(prefix, fetchImpl);
          ranges.set(prefix, range);
        }
        count = countInRange(await range, suffix);
        this.breachCounts.set(password, count);
      }
      const times = count;
      if (times > 0) found.push(...ids.map((itemId) => ({ itemId, count: times })));
      onProgress?.(++done, byPassword.size);
    }
    this.breachChecked = true;
    this.emit();
    return found.sort((a, b) => b.count - a.count || a.itemId.localeCompare(b.itemId));
  }

  /** Whether a full breach check ran since unlocking. */
  get breachCheckDone(): boolean {
    return this.breachChecked;
  }

  /** One padded range, through the server or directly (see `breachMode`). */
  private async breachRange(prefix: string, fetchImpl?: typeof globalThis.fetch): Promise<string> {
    if (fetchImpl || this.breachMode === "direct") return fetchPwnedRange(prefix, fetchImpl);
    const body = await this.api.breach.range(prefix);
    if (body !== null) return body;
    if (this.breachMode === "auto") return fetchPwnedRange(prefix);
    throw new Error("your Passbox server does not offer breach checks");
  }

  // --- Security analysis ----------------------------------------------------------

  /**
   * The vault security analysis: score, findings with fixes and the "fix
   * these first" list, computed locally in the shared core. Breach findings
   * appear after `checkBreachedItems`, email exposures after `emailMonitoring`.
   */
  securityReport(options: ReportOptions = DEFAULT_REPORT_OPTIONS, now = Date.now()): SecurityReport {
    const items = this.snapshot.items;
    let breachCounts: Record<string, number> | undefined;
    if (this.breachChecked) {
      breachCounts = {};
      for (const item of items) {
        const password = fieldValue(item.data, FIELD.password);
        const count = password ? this.breachCounts.get(password) : undefined;
        if (count !== undefined) breachCounts[item.id] = count;
      }
    }
    return analyzeSecurity(this.core as unknown as AnalysisCore, items, {
      ...options,
      now,
      userInputs: this.strengthContext(),
      breachCounts,
      exposedEmails: this.exposedEmails,
      siteBreaches: this.storedBreachCatalog()?.catalog,
    });
  }

  // --- Breach catalogue ("compromised websites") ------------------------------------

  private cachedCatalog: { raw: string; value: { etag: string | null; catalog: BreachCatalog } } | undefined;

  private storedBreachCatalog(): { etag: string | null; catalog: BreachCatalog } | undefined {
    const raw = this.storage.getItem(BREACH_CATALOG_KEY);
    if (!raw) return undefined;
    if (this.cachedCatalog?.raw === raw) return this.cachedCatalog.value;
    try {
      const value = JSON.parse(raw) as { etag: string | null; catalog: BreachCatalog };
      if (!Array.isArray(value.catalog?.breaches)) return undefined;
      this.cachedCatalog = { raw, value };
      return value;
    } catch {
      return undefined;
    }
  }

  private bundledCatalogInfo(): Omit<CatalogInfo, "bundled"> {
    return (
      bundledBreachCatalog(this.core as unknown as AnalysisCore) ?? {
        version: "bundled",
        updatedAt: 0,
        entries: 0,
        source: "Have I Been Pwned",
        sourceUrl: "https://haveibeenpwned.com/",
        license: "CC BY 4.0",
      }
    );
  }

  /** The breach catalogue in use on this device: from the server, or the bundled snapshot. */
  breachCatalogStatus(available = true, changed = false): BreachCatalogStatus {
    const stored = this.storedBreachCatalog()?.catalog;
    if (stored) {
      return {
        available,
        changed,
        version: stored.version,
        updatedAt: stored.updatedAt,
        entries: stored.breaches.length,
        bundled: false,
      };
    }
    const bundled = this.bundledCatalogInfo();
    return {
      available,
      changed,
      version: bundled.version,
      updatedAt: bundled.updatedAt,
      entries: bundled.entries,
      bundled: true,
    };
  }

  /**
   * Checks the server's breach catalogue and downloads it (conditionally,
   * with the stored `ETag`) when it is newer than the one on this device.
   * One document for everyone, no session needed: the server never learns
   * which sites the user has. Matching happens in `securityReport`.
   */
  async refreshBreachCatalog(): Promise<BreachCatalogStatus> {
    const version = await this.api.breach.catalogVersion();
    if (!version) return this.breachCatalogStatus(false);
    const stored = this.storedBreachCatalog();
    const local = this.breachCatalogStatus();
    // An older catalogue than ours (a server that has not fetched yet) is not worth downloading.
    if (stored?.catalog.version === version.version || version.updatedAt < local.updatedAt) {
      return local;
    }
    const response = await this.api.breach.catalog(stored?.etag ?? null);
    if (response.status === "unavailable") return this.breachCatalogStatus(false);
    if (response.status === "not_modified") return local;
    this.storage.setItem(BREACH_CATALOG_KEY, JSON.stringify({ etag: response.etag, catalog: response.catalog }));
    this.emit();
    return this.breachCatalogStatus(true, true);
  }

  private breachSeenKey(): string | undefined {
    const account = this.keyring?.accountId ?? this.deviceAccount?.accountId;
    return account ? `${BREACH_SEEN_KEY}.${account}` : undefined;
  }

  /**
   * Breached websites with open, not dismissed findings that were published
   * (or changed) after the last `acknowledgeBreachAlerts`: notify the user
   * about these, then acknowledge. Breaches already in the bundled snapshot
   * show in the security check but are not announced.
   */
  breachAlerts(options: ReportOptions = DEFAULT_REPORT_OPTIONS, now = Date.now()): BreachedSite[] {
    const catalog = this.storedBreachCatalog()?.catalog;
    const key = this.breachSeenKey();
    if (!catalog || !key) return [];
    const seen = Number(this.storage.getItem(key) ?? this.bundledCatalogInfo().updatedAt) || 0;
    const changedAt = new Map(
      catalog.breaches.map((b) => [b.name, Math.max(Date.parse(b.addedDate) || 0, Date.parse(b.modifiedDate) || 0)]),
    );
    const report = this.securityReport(options, now);
    const dismissed = new Set(
      report.findings.filter((f) => f.kind === "breached_site" && f.dismissed).map((f) => f.itemId),
    );
    return report.breachedSites.filter(
      (site) =>
        (changedAt.get(site.name) ?? 0) > seen && [...site.affected, ...site.possibly].some((id) => !dismissed.has(id)),
    );
  }

  /** Marks the current catalogue as announced. */
  acknowledgeBreachAlerts(): void {
    const key = this.breachSeenKey();
    if (key) this.storage.setItem(key, String(this.breachCatalogStatus().updatedAt));
  }

  /** Dismisses (or restores) one finding of one item; stored encrypted in the item and synced. */
  async dismissFinding(itemId: string, kind: FindingKind, dismissed: boolean): Promise<void> {
    const item = this.items.get(itemId);
    if (!item) throw new Error("unknown item");
    const data = withDismissed(item.data, kind, dismissed);
    if (data) await this.updateItem(itemId, data);
  }

  /** Whether `host` looks like a saved login domain or a well-known site (phishing). Local. */
  checkLookalike(host: string): Lookalike | null {
    const saved: string[] = [];
    for (const item of this.snapshot.items) {
      if (item.data.category !== "login") continue;
      const url = fieldValue(item.data, FIELD.url);
      if (!url) continue;
      try {
        saved.push(new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(url) ? url : `https://${url}`).hostname);
      } catch {
        // Not a URL.
      }
    }
    return checkLookalike(this.core as unknown as AnalysisCore, host, saved);
  }

  // --- Email breach monitoring (server) ---------------------------------------------

  /** The server's email breach monitoring and its results (also used by `securityReport`). */
  async emailMonitoring(): Promise<EmailMonitoring> {
    const monitoring = await this.api.breach.emails();
    this.exposedEmails = monitoring.emails
      .filter((e) => e.verified)
      .map((e) => ({
        email: e.email,
        breaches: e.breaches.map((b) => ({
          name: b.name,
          title: b.title,
          domain: b.domain,
          breachDate: b.breachDate,
          dataClasses: b.dataClasses,
        })),
      }));
    this.emit();
    return monitoring;
  }

  /**
   * Starts monitoring an address; the server mails a confirmation code to
   * it. Once confirmed, the address (never a password) is sent to Have I
   * Been Pwned. Tell the user before calling this.
   */
  addMonitoredEmail(email: string, locale?: string): Promise<MonitoredEmail> {
    return this.api.breach.addEmail(email, locale);
  }

  async verifyMonitoredEmail(id: string, code: string): Promise<MonitoredEmail> {
    const email = await this.api.breach.verifyEmail(id, code);
    await this.emailMonitoring().catch(() => undefined);
    return email;
  }

  async checkMonitoredEmail(id: string): Promise<MonitoredEmail> {
    const email = await this.api.breach.checkEmail(id);
    await this.emailMonitoring().catch(() => undefined);
    return email;
  }

  async removeMonitoredEmail(id: string): Promise<void> {
    await this.api.breach.removeEmail(id);
    await this.emailMonitoring().catch(() => undefined);
  }

  // --- Email aliases ---------------------------------------------------------------

  /** Alias services set up in the vault (items tagged `alias-service` with a provider and key). */
  aliasServices(): { itemId: string; provider: AliasProvider; providerName: string; title: string }[] {
    return this.snapshot.items.flatMap((item) => {
      const provider = fieldValue(item.data, ALIAS_FIELD.provider);
      if (!isAliasProvider(provider) || !fieldValue(item.data, ALIAS_FIELD.apiKey)) return [];
      return [{ itemId: item.id, provider, providerName: ALIAS_PROVIDER_NAMES[provider], title: item.data.title }];
    });
  }

  /** Saves an alias service's API key as a vault item; returns its ID. */
  addAliasService(vaultId: string, settings: AliasSettings): Promise<string> {
    const fields: ItemData["fields"] = [
      { id: ALIAS_FIELD.provider, label: "Provider", type: "text", value: settings.provider },
      { id: ALIAS_FIELD.apiKey, label: "API key", type: "concealed", value: settings.apiKey.trim() },
    ];
    if (settings.baseUrl?.trim())
      fields.push({ id: ALIAS_FIELD.baseUrl, label: "Server", type: "url", value: settings.baseUrl.trim() });
    if (settings.aliasDomain?.trim())
      fields.push({ id: ALIAS_FIELD.domain, label: "Alias domain", type: "text", value: settings.aliasDomain.trim() });
    return this.createItem(vaultId, {
      v: 1,
      category: "other",
      title: ALIAS_PROVIDER_NAMES[settings.provider],
      fields,
      notes: "",
      tags: [ALIAS_TAG],
      favorite: false,
    });
  }

  /** Creates an email alias for `forDomain` with the service in `serviceItemId`, directly with the provider. */
  async createAlias(serviceItemId: string, forDomain: string, fetchImpl?: typeof globalThis.fetch): Promise<string> {
    const item = this.items.get(serviceItemId);
    const provider = item ? fieldValue(item.data, ALIAS_FIELD.provider) : undefined;
    if (!item || !isAliasProvider(provider)) throw new Error("not an alias service");
    return createAlias(
      {
        provider,
        apiKey: fieldValue(item.data, ALIAS_FIELD.apiKey) ?? "",
        baseUrl: fieldValue(item.data, ALIAS_FIELD.baseUrl),
        aliasDomain: fieldValue(item.data, ALIAS_FIELD.domain),
      },
      forDomain,
      fetchImpl,
    );
  }

  /** The problems of one item for its security check card. */
  itemHealth(id: string): ItemHealth {
    const item = this.items.get(id);
    if (!item) throw new Error("unknown item");
    const result: ItemHealth = { problems: [], strength: null, reusedWith: [], breachCount: null };
    if (item.data.category !== "login" || item.data.trashedAt !== undefined) return result;
    const health = this.health();
    const password = fieldValue(item.data, FIELD.password);
    if (password) result.strength = this.estimateStrength(password).score;
    if (health.weak.includes(id)) result.problems.push("weak");
    const group = health.reused.find((ids) => ids.includes(id));
    if (group) {
      result.problems.push("reused");
      result.reusedWith = group.filter((other) => other !== id);
    }
    if (health.insecureUrls.includes(id)) result.problems.push("insecure_url");
    if (health.withoutTotp.includes(id)) result.problems.push("missing_totp");
    const count = password ? this.breachCounts.get(password) : undefined;
    if (count !== undefined) {
      result.breachCount = count;
      if (count > 0) result.problems.push("breached");
    }
    return result;
  }

  private usageStorageKey(keyring: Core.Keyring): string {
    return `${USAGE_KEY}.${keyring.accountId}`;
  }

  private loadUsage(keyring: Core.Keyring): Record<string, ItemUsage> {
    const raw = this.storage.getItem(this.usageStorageKey(keyring));
    if (!raw) return {};
    try {
      return (
        (JSON.parse(keyring.decryptLocal(USAGE_PURPOSE, raw)) as { items?: Record<string, ItemUsage> }).items ?? {}
      );
    } catch {
      return {};
    }
  }

  /**
   * Records a use of an item on this device ("Zuletzt verwendet",
   * "Letztes Auto-Ausfüllen"). Stored encrypted in this device's storage,
   * never sent to the server.
   */
  recordItemUse(id: string, kind: UsageKind): ItemUsage {
    const keyring = this.requireKeyring();
    if (!this.items.has(id)) throw new Error("unknown item");
    const all = this.loadUsage(keyring);
    const now = Date.now();
    const previous = all[id] ?? { lastUsedAt: 0, lastAutofilledAt: 0, useCount: 0 };
    const usage: ItemUsage = {
      lastUsedAt: now,
      lastAutofilledAt: kind === "autofill" ? now : previous.lastAutofilledAt,
      useCount: previous.useCount + 1,
    };
    const items: Record<string, ItemUsage> = { [id]: usage };
    for (const [other, value] of Object.entries(all)) {
      if (other !== id && this.items.has(other)) items[other] = value;
    }
    this.storage.setItem(this.usageStorageKey(keyring), keyring.encryptLocal(USAGE_PURPOSE, JSON.stringify({ items })));
    return usage;
  }

  /** This device's usage of an item, if it was used here. */
  itemUsage(id: string): ItemUsage | undefined {
    return this.loadUsage(this.requireKeyring())[id];
  }

  /** This device's usage of all items by ID, for sorting by recent use. */
  itemUsages(): Record<string, ItemUsage> {
    return this.loadUsage(this.requireKeyring());
  }

  /** Moves several items to the trash with one sync at the end. Returns the items that failed. */
  async trashItems(ids: readonly string[]): Promise<BulkFailure[]> {
    const at = Date.now();
    return this.bulk(ids, (data) => (data.trashedAt === undefined ? { ...data, trashedAt: at } : undefined));
  }

  /** Archives several items with one sync at the end. Returns the items that failed. */
  async archiveItems(ids: readonly string[]): Promise<BulkFailure[]> {
    const at = Date.now();
    return this.bulk(ids, (data) => (data.archivedAt === undefined ? { ...data, archivedAt: at } : undefined));
  }

  /** Takes several items out of the archive with one sync at the end. Returns the items that failed. */
  async unarchiveItems(ids: readonly string[]): Promise<BulkFailure[]> {
    return this.bulk(ids, (data) => {
      if (data.archivedAt === undefined) return undefined;
      const { archivedAt: _archived, ...rest } = data;
      return rest;
    });
  }

  /** Marks several items as favorites (or not) with one sync at the end. Returns the items that failed. */
  async setFavorite(ids: readonly string[], favorite: boolean): Promise<BulkFailure[]> {
    return this.bulk(ids, (data) => (data.favorite === favorite ? undefined : { ...data, favorite }));
  }

  private async bulk(ids: readonly string[], change: (data: ItemData) => ItemData | undefined): Promise<BulkFailure[]> {
    const keyring = this.requireKeyring();
    const failed: BulkFailure[] = [];
    let changed = false;
    for (const id of new Set(ids)) {
      const item = this.items.get(id);
      if (!item) {
        failed.push({ itemId: id, error: "unknown item" });
        continue;
      }
      const next = change(item.data);
      if (!next) continue;
      try {
        await this.putItem(item.vaultId, id, item.revision + 1, next);
        changed = true;
      } catch (error) {
        failed.push({ itemId: id, error: error instanceof Error ? error.message : String(error) });
      }
    }
    if (changed) this.emit();
    if ((changed || failed.length > 0) && this.keyring === keyring) await this.sync();
    return failed;
  }

  private strengthContext(): string[] {
    const account = this.deviceAccount;
    return account ? [account.email] : [];
  }

  /** Permanently deletes an item on all devices. Prefer `trashItem`. */
  async deleteItem(id: string): Promise<void> {
    const item = this.items.get(id);
    if (!item) return;
    try {
      await this.api.deleteItem(id, item.revision + 1);
    } catch (error) {
      await this.handleWriteError(error);
    }
    this.items.delete(id);
    this.emit();
    await this.sync();
  }

  private async writeItem(vaultId: string, id: string, revision: number, data: ItemData) {
    try {
      await this.putItem(vaultId, id, revision, data);
      this.emit();
    } catch (error) {
      await this.handleWriteError(error);
    }
    await this.sync();
  }

  /** Encrypts and uploads one item version without syncing. */
  private async putItem(vaultId: string, id: string, revision: number, data: ItemData) {
    const keyring = this.requireKeyring();
    const keyEpoch = this.vaults.get(vaultId)?.keyEpoch ?? 0;
    const encryptedData = keyring.encryptItemAt(vaultId, keyEpoch, id, revision, serializeItemData(data));
    const result = await this.api.putItem(id, {
      vaultId,
      revision,
      encryptedData,
      ...(keyEpoch ? { keyEpoch } : {}),
    });
    if (this.keyring === keyring) {
      const createdAt = this.items.get(id)?.createdAt ?? Date.now();
      this.items.set(id, { id, vaultId, revision: result.revision, updatedAt: Date.now(), createdAt, keyEpoch, data });
    }
  }

  // --- Organizations and sharing -------------------------------------------------
  //
  // Signing, sealing and verification happen in the Rust core (WebAssembly);
  // these methods run the HTTP calls and multi-step flows. See
  // docs/architecture/sharing.md.

  private viewNow(): SharingView {
    return this.sharingView;
  }

  /** Organizations with verified members and groups. */
  orgs(): Org[] {
    return this.viewNow().orgs;
  }

  /** One organization; throws if unknown. */
  org(orgId: string): Org {
    const org = this.viewNow().orgs.find((o) => o.id === orgId);
    if (!org) throw new Error("unknown organization");
    return org;
  }

  /** Shared vaults with verified members, roles and key state. */
  sharedVaults(): SharedVault[] {
    return this.viewNow().vaults;
  }

  /** Problems found while verifying sharing data (for example `key_changed`). */
  sharingWarnings(): SharingWarning[] {
    return this.viewNow().warnings;
  }

  /** Ownership and this account's role for a vault. */
  vaultAccess(vaultId: string): VaultAccess {
    const shared = this.viewNow().vaults.find((v) => v.vaultId === vaultId);
    if (shared) {
      return { vaultId, orgId: shared.orgId, role: shared.role ?? undefined, verified: shared.verified };
    }
    const vault = this.vaults.get(vaultId);
    if (vault && !vault.orgId) return { vaultId, orgId: undefined, role: "manage", verified: true };
    throw new Error("unknown vault");
  }

  /** Fingerprint of this account's own keys, for comparing with others. */
  ownFingerprint(): string {
    const fingerprint = this.requireKeyring().ownFingerprint();
    if (!fingerprint) throw new Error("the account has no key pairs yet");
    return fingerprint;
  }

  /**
   * Looks up an account's key in the key directory and verifies the proof.
   * New keys are pinned; `status: "changed"` must be accepted with `acceptKeyChange`.
   */
  async lookupKey(accountId: string): Promise<KeyLookup> {
    const keyring = this.requireKeyring();
    const since = (JSON.parse(keyring.trustStore()) as { directory?: { size?: number } }).directory?.size ?? 0;
    const response = await this.api.sharing.lookupKey(accountId, since);
    const lookup = JSON.parse(keyring.verifyDirectoryLookup(accountId, JSON.stringify(response))) as KeyLookup;
    this.saveTrust(keyring);
    return lookup;
  }

  /** Checks that the key directory lists this account's own key. */
  async verifyOwnKey(): Promise<KeyLookup> {
    return this.lookupKey(this.requireKeyring().accountId);
  }

  /** Trusts the current key of an account after a change. Returns its fingerprint. */
  acceptKeyChange(accountId: string): string {
    const keyring = this.requireKeyring();
    const fingerprint = keyring.acceptKeyChange(accountId);
    this.saveTrust(keyring);
    this.sharingView = withOrgLocks(JSON.parse(keyring.sharingView()) as SharingView, this.orgLocks);
    this.emit();
    return fingerprint;
  }

  /** Creates a family organization with its shared family vault. Returns the organization ID. */
  async createFamily(name: string, vaultName: string): Promise<string> {
    return this.createOrg("family", name, vaultName);
  }

  /** Creates a team organization. Returns its ID. */
  async createTeam(name: string): Promise<string> {
    return this.createOrg("team", name, undefined);
  }

  private async createOrg(kind: "family" | "team", name: string, vaultName: string | undefined): Promise<string> {
    await this.sync();
    const keyring = this.requireKeyring();
    const body = JSON.parse(
      keyring.createOrg(
        kind,
        JSON.stringify({ name }),
        vaultName === undefined ? undefined : JSON.stringify({ name: vaultName }),
        Date.now(),
      ),
    ) as { id: string };
    await this.api.sharing.createOrg(body);
    await this.sync();
    await this.setUpNewOrg(body.id);
    return body.id;
  }

  /**
   * Organization recovery is on by default: a new
   * organization gets its recovery key and a first policy that requires
   * enrollment, and the creator enrolls. Admins can turn both off later.
   */
  private async setUpNewOrg(orgId: string): Promise<void> {
    await this.setUpOrgRecovery(orgId);
    await this.setOrgPolicy(orgId, NEW_ORG_POLICY_RULES);
    await this.enrollOrgRecovery(orgId);
  }

  /** Renames an organization (admins). */
  async renameOrg(orgId: string, name: string): Promise<void> {
    const keyring = this.requireKeyring();
    const org = await this.orgRecord(orgId);
    await this.api.sharing.updateOrg(orgId, {
      revision: org.revision + 1,
      metaEpoch: org.metaEpoch,
      encryptedMeta: keyring.encryptOrgMeta(orgId, org.metaEpoch, JSON.stringify({ name })),
    });
    await this.sync();
  }

  private async orgRecord(orgId: string): Promise<{ revision: number; metaEpoch: number }> {
    const delta = await this.api.sync(this.cursor, { sharing: true });
    const orgs = (delta.sharing?.orgs ?? []) as { id: string; revision: number; metaEpoch: number }[];
    const org = orgs.find((o) => o.id === orgId);
    if (!org) throw new Error("unknown organization");
    return org;
  }

  /** Deletes an organization with all its vaults (owner only). */
  async deleteOrg(orgId: string): Promise<void> {
    await this.api.sharing.deleteOrg(orgId);
    await this.sync();
  }

  /**
   * Invites someone by email. Returns the link (with the organization
   * fingerprint); the server also mails it when a mailer is configured.
   * `linkBase` defaults to the API base URL (the web app's origin).
   */
  async invite(orgId: string, email: string, role: Exclude<OrgRole, "owner">, linkBase?: string): Promise<Invitation> {
    const keyring = this.requireKeyring();
    const [root] = JSON.parse(keyring.orgFingerprint(orgId)) as [string, string];
    const linkFragment = `org=${root}`;
    const created = await this.api.sharing.invite(orgId, { email, role, linkFragment });
    const base = (linkBase ?? this.linkBase ?? "").replace(/\/+$/, "");
    return {
      id: created.id,
      token: created.token,
      link: `${base}${created.path}#${linkFragment}`,
      expiresAt: created.expiresAt,
    };
  }

  /** Pending invitations (admins). */
  async invitations(orgId: string): Promise<OrgInvitationInfo[]> {
    return this.api.sharing.invitations(orgId);
  }

  async revokeInvitation(orgId: string, invitationId: string): Promise<void> {
    await this.api.sharing.revokeInvitation(orgId, invitationId);
  }

  /** What an invitation link (or token) is for; works before signing in. */
  async previewInvitation(link: string): Promise<InvitationPreview> {
    return this.api.sharing.previewInvitation(parseInvitationLink(link).token);
  }

  /**
   * Accepts an invitation for the signed-in account (which must have the
   * invited email) and returns the organization ID. The organization
   * fingerprint in the link is pinned. Membership stays `accepted` until an
   * admin confirms it.
   */
  async acceptInvitation(link: string): Promise<string> {
    const { token, orgRoot } = parseInvitationLink(link);
    await this.sync();
    const preview = await this.api.sharing.previewInvitation(token);
    const keyring = this.requireKeyring();
    if (orgRoot) {
      keyring.pinOrgRoot(preview.orgId, orgRoot);
      this.saveTrust(keyring);
    }
    const accepted = await this.api.sharing.acceptInvitation(token);
    await this.sync();
    return accepted.orgId;
  }

  /**
   * Confirms a member who accepted an invitation (admins): verifies their key
   * in the key directory, attests it and seals the organization key. In a
   * family the member also gets the family vault (edit). Returns the attested
   * fingerprint for optional comparison with the member.
   */
  async confirmMember(orgId: string, accountId: string): Promise<string> {
    await this.sync();
    const lookup = await this.lookupKey(accountId);
    if (lookup.status === "changed") throw new Error("the member's key changed; compare fingerprints first");
    const keyring = this.requireKeyring();
    const body = JSON.parse(keyring.confirmMember(orgId, accountId, Date.now())) as { fingerprint: string };
    await this.api.sharing.confirmMember(orgId, accountId, body);
    await this.sync();
    const org = this.org(orgId);
    const vaultId = org.defaultVaultId;
    // Guests only see what is shared with them: no family vault.
    const guest = org.members.some((m) => m.accountId === accountId && m.role === "guest");
    if (
      org.kind === "family" &&
      !guest &&
      vaultId &&
      this.sharedVaults().some((v) => v.vaultId === vaultId && v.role === "manage")
    ) {
      await this.shareVault(vaultId, "account", accountId, "edit");
    }
    return body.fingerprint;
  }

  /** Changes a member's role (admins; admin rights only by the owner). */
  async setMemberRole(orgId: string, accountId: string, role: Exclude<OrgRole, "owner">): Promise<void> {
    const body = JSON.parse(this.requireKeyring().setMemberRole(orgId, accountId, role, Date.now()));
    await this.api.sharing.updateMember(orgId, accountId, body);
    await this.sync();
  }

  /** Blocks a member on the server (not cryptographic; `removeMember` rotates keys). */
  async suspendMember(orgId: string, accountId: string): Promise<void> {
    await this.api.sharing.suspendMember(orgId, accountId);
    await this.sync();
  }

  async reactivateMember(orgId: string, accountId: string): Promise<void> {
    await this.api.sharing.reactivateMember(orgId, accountId);
    await this.sync();
  }

  /**
   * Removes a member and rotates every key they had: their groups, the vaults
   * they could open (items re-encrypted) and the organization key; members
   * they attested are re-attested. Vaults this account cannot manage stay
   * `rotationPending` for their managers.
   */
  async removeMember(orgId: string, accountId: string): Promise<void> {
    await this.sync();
    const attestations = JSON.parse(this.requireKeyring().reattestMembers(orgId, accountId, Date.now())) as {
      accountId: string;
    }[];
    const removed = await this.api.sharing.removeMember(orgId, accountId);
    await this.sync();
    for (const groupId of removed.groups) {
      if (this.org(orgId).groups.some((g) => g.id === groupId && g.isMember)) {
        await this.rotateGroup(orgId, groupId, [accountId]);
      }
    }
    await this.sync();
    await this.rotatePendingVaults(orgId, [["account", accountId]]);
    for (const attestation of attestations) {
      await this.api.sharing.updateMember(orgId, attestation.accountId, attestation);
    }
    await this.sync();
    await this.api.sharing.rotateOrgKey(orgId, JSON.parse(this.requireKeyring().rotateOrgKey(orgId, Date.now())));
    await this.sync();
  }

  /** Leaves an organization (not possible for its owner). */
  async leaveOrg(orgId: string): Promise<void> {
    await this.api.sharing.removeMember(orgId, this.requireKeyring().accountId);
    await this.sync();
  }

  /** Creates a shared vault in an organization (owners and admins). Returns its ID. */
  async createSharedVault(orgId: string, name: string): Promise<string> {
    const body = JSON.parse(this.requireKeyring().createSharedVault(orgId, JSON.stringify({ name }), Date.now())) as {
      id: string;
    };
    await this.api.sharing.createSharedVault(orgId, body);
    await this.sync();
    return body.id;
  }

  /**
   * Shares a vault with an account or group, or changes a member's role.
   * Refused while the member's key changed and the change was not accepted.
   */
  async shareVault(vaultId: string, principalType: PrincipalType, principalId: string, role: VaultRole): Promise<void> {
    const body = JSON.parse(this.requireKeyring().shareVault(vaultId, principalType, principalId, role, Date.now()));
    await this.api.sharing.putVaultMember(vaultId, body);
    await this.sync();
  }

  /**
   * Removes a member from a vault: rotates the vault key and re-encrypts every
   * item, so the former member cannot read anything added later (they may
   * have kept what they saw).
   */
  async unshareVault(vaultId: string, principalType: PrincipalType, principalId: string): Promise<void> {
    await this.rotateVaultKey(vaultId, [[principalType, principalId]]);
  }

  /** Verified members of a shared vault. */
  vaultMembers(vaultId: string): SharedVault {
    const vault = this.sharedVaults().find((v) => v.vaultId === vaultId);
    if (!vault) throw new Error("unknown vault");
    return vault;
  }

  /** Rotates the vaults of an organization marked for rotation that this account manages. */
  async rotatePendingVaults(orgId: string, removed: [PrincipalType, string][] = []): Promise<void> {
    const pending = this.sharedVaults().filter(
      (v) => v.orgId === orgId && v.rotationPending && v.hasKey && v.role === "manage",
    );
    for (const vault of pending) await this.rotateVaultKey(vault.vaultId, removed);
  }

  /** Rotates a vault's key (without `removed`) and re-encrypts its items. */
  async rotateVaultKey(vaultId: string, removed: [PrincipalType, string][] = []): Promise<void> {
    await this.sync();
    const vault = this.vaults.get(vaultId);
    if (!vault) throw new Error("unknown vault");
    const body = JSON.parse(
      this.requireKeyring().rotateVault(
        vaultId,
        JSON.stringify(removed),
        JSON.stringify({ name: vault.name }),
        Date.now(),
      ),
    ) as { keyEpoch: number };
    await this.api.sharing.rotateVault(vaultId, body);
    await this.sync();
    await this.reencryptVault(vaultId, body.keyEpoch);
  }

  /** Re-encrypts the items of a vault still at an older key epoch, 100 per request. */
  async reencryptVault(vaultId: string, keyEpoch: number): Promise<void> {
    for (let attempt = 0; attempt < 2; attempt++) {
      const keyring = this.requireKeyring();
      const stale = [...this.items.values()].filter((i) => i.vaultId === vaultId && (i.keyEpoch ?? 0) < keyEpoch);
      if (stale.length === 0) return;
      for (let i = 0; i < stale.length; i += 100) {
        const batch = stale.slice(i, i + 100).map((item) => ({
          id: item.id,
          revision: item.revision + 1,
          keyEpoch,
          encryptedData: keyring.encryptItemAt(
            vaultId,
            keyEpoch,
            item.id,
            item.revision + 1,
            serializeItemData(item.data),
          ),
        }));
        await this.api.sharing.reencryptItems(vaultId, batch);
      }
      await this.sync();
    }
  }

  /** Groups of an organization. */
  groups(orgId: string): OrgGroup[] {
    return this.org(orgId).groups;
  }

  /** Creates a group (admins); the creator is always a member. Returns its ID. */
  async createGroup(orgId: string, name: string, members: string[] = []): Promise<string> {
    const body = JSON.parse(
      this.requireKeyring().createGroup(orgId, JSON.stringify({ name }), JSON.stringify(members), Date.now()),
    ) as { id: string };
    await this.api.sharing.createGroup(orgId, body);
    await this.sync();
    return body.id;
  }

  async renameGroup(orgId: string, groupId: string, name: string): Promise<void> {
    const { metaEpoch } = await this.orgRecord(orgId);
    await this.api.sharing.updateGroup(orgId, groupId, {
      metaEpoch,
      encryptedMeta: this.requireKeyring().encryptGroupMeta(orgId, groupId, metaEpoch, JSON.stringify({ name })),
    });
    await this.sync();
  }

  /** Deletes a group (admins). Unshare its vaults first. */
  async deleteGroup(orgId: string, groupId: string): Promise<void> {
    await this.api.sharing.deleteGroup(orgId, groupId);
    await this.sync();
  }

  /** Adds a member to a group: one sealing of the group key. */
  async addGroupMember(orgId: string, groupId: string, accountId: string): Promise<void> {
    const body = JSON.parse(this.requireKeyring().addGroupMember(groupId, accountId, Date.now()));
    await this.api.sharing.addGroupMember(orgId, groupId, body);
    await this.sync();
  }

  /** Removes a member from a group: rotates the group key and the vaults shared with the group. */
  async removeGroupMember(orgId: string, groupId: string, accountId: string): Promise<void> {
    await this.rotateGroup(orgId, groupId, [accountId]);
    await this.sync();
    await this.rotatePendingVaults(orgId);
  }

  private async rotateGroup(orgId: string, groupId: string, removed: string[]): Promise<void> {
    const body = JSON.parse(this.requireKeyring().rotateGroup(groupId, JSON.stringify(removed), Date.now()));
    await this.api.sharing.rotateGroup(orgId, groupId, body);
  }

  // --- Recovery code --------------------------------------------------------------

  /** Recovery options set up on the server (recovery code, organization escrows). */
  async recoveryStatus(): Promise<RecoveryStatus> {
    this.requireKeyring();
    return this.api.recovery.status();
  }

  /**
   * Creates a recovery code (replacing an earlier one) and returns it in
   * display format. Show it once, for the Emergency Kit; it is not stored.
   * Throws `ReauthenticationRequiredError` without a recent login.
   */
  async createRecoveryCode(): Promise<string> {
    const keyring = this.requireKeyring();
    const code = this.core.generateRecoveryCode();
    const keys = this.core.RecoveryKeys.fromCode(code);
    try {
      const flow = this.core.RegistrationFlow.startRecovery(keys);
      const { registrationResponse } = await this.twoFactorCall(() =>
        this.api.recovery.codeStart({ registrationRequest: flow.request }),
      );
      const registrationUpload = flow.finish(registrationResponse);
      flow.free();
      await this.twoFactorCall(() =>
        this.api.recovery.codeFinish({
          registrationUpload,
          wrappedAccountKey: keyring.wrapAccountKeyForRecovery(keys),
        }),
      );
    } finally {
      keys.free();
    }
    await this.refreshRecoveryOptions().catch(() => undefined);
    return code;
  }

  /** Deletes the recovery code. Throws `ReauthenticationRequiredError` without a recent login. */
  async removeRecoveryCode(): Promise<void> {
    this.requireKeyring();
    await this.twoFactorCall(() => this.api.recovery.codeDelete());
    await this.refreshRecoveryOptions().catch(() => undefined);
  }

  /** Whether `input` is a complete recovery code (checked on the device, including the checksum). */
  isRecoveryCode(input: string): boolean {
    return this.core.isRecoveryCode(input);
  }

  /**
   * What recovery options this device remembers for its account (also while
   * locked, for "Forgot master password?"). `undefined` before the first
   * unlock after the update.
   */
  get recoveryOptions(): RecoveryOptions | undefined {
    const account = this.deviceAccount;
    if (!account) return undefined;
    const raw = this.storage.getItem(`${RECOVERY_OPTIONS_KEY}.${account.accountId}`);
    if (!raw) return undefined;
    try {
      return JSON.parse(raw) as RecoveryOptions;
    } catch {
      return undefined;
    }
  }

  /** Refreshes `recoveryOptions` from the server. Call after unlocking (best effort). */
  async refreshRecoveryOptions(): Promise<RecoveryOptions> {
    const keyring = this.requireKeyring();
    const [status, emergency] = await Promise.all([
      this.api.recovery.status(),
      this.api.emergency.list().catch(() => ({ granted: [], received: [] })),
    ]);
    const names = new Map(this.sharingView.orgs.map((o) => [o.id, o.name ?? undefined]));
    const options: RecoveryOptions = {
      accountId: keyring.accountId,
      recoveryCode: status.recoveryCode !== null,
      orgs: status.orgEscrows.map((e) => ({ orgId: e.orgId, name: names.get(e.orgId) })),
      emergencyContacts: emergency.granted.length + emergency.received.length,
      updatedAt: Date.now(),
    };
    this.storage.setItem(`${RECOVERY_OPTIONS_KEY}.${keyring.accountId}`, JSON.stringify(options));
    return options;
  }

  /**
   * Starts recovering an account with its recovery code (while signed out or
   * locked). A wrong code throws `InvalidCredentialsError`, a malformed one
   * `InvalidRecoveryCodeError`. When the result names `twoFactorMethods`,
   * finish with `completeRecoveryTwoFactor`; then `finishRecovery` sets the
   * new master password.
   */
  async startCodeRecovery(email: string, recoveryCode: string): Promise<CodeRecoveryStart> {
    this.cancelRecovery();
    const { core } = this;
    let keys: Core.RecoveryKeys;
    try {
      keys = core.RecoveryKeys.fromCode(recoveryCode);
    } catch {
      throw new InvalidRecoveryCodeError();
    }
    let grant: RecoveryGrant;
    const flow = core.LoginFlow.startRecovery(keys);
    try {
      const start = await this.api.recovery.loginStart({
        email: email.trim().toLowerCase(),
        credentialRequest: flow.request,
      });
      let credentialFinalization: string;
      try {
        credentialFinalization = flow.finish(start.credentialResponse);
      } catch (error) {
        throw isInvalidCredentials(error) ? new InvalidCredentialsError() : error;
      }
      grant = await this.api.recovery.loginFinish({
        loginId: start.loginId,
        credentialFinalization,
        ...(this.device ? { deviceName: this.device.name, clientKind: this.device.kind } : {}),
      });
    } catch (error) {
      keys.free();
      throw isInvalidCredentials(error) ? new InvalidCredentialsError() : error;
    } finally {
      flow.free();
    }
    if (grant.twoFactorMethods) {
      this.pendingCodeRecovery = { grant, keys };
      return { accountId: grant.accountId, email: grant.email, twoFactorMethods: grant.twoFactorMethods };
    }
    try {
      this.openCodeRecovery(grant, keys);
    } finally {
      keys.free();
    }
    return { accountId: grant.accountId, email: grant.email };
  }

  /** The second factor of a recovery by code (`totp` code or a two-factor recovery code). */
  async completeRecoveryTwoFactor(method: "totp" | "recovery", code: string): Promise<void> {
    const pending = this.pendingCodeRecovery;
    if (!pending) throw new RecoveryExpiredError();
    let grant: RecoveryGrant;
    try {
      grant = await this.api.recovery.twoFactor({
        recoveryToken: pending.grant.recoveryToken,
        method,
        code: code.replace(/\s/g, ""),
      });
    } catch (error) {
      throw recoveryError(twoFactorError(error));
    }
    this.pendingCodeRecovery = undefined;
    try {
      this.openCodeRecovery(grant, pending.keys);
    } finally {
      pending.keys.free();
    }
  }

  private openCodeRecovery(grant: RecoveryGrant, keys: Core.RecoveryKeys) {
    if (!grant.wrappedAccountKey) throw new RecoveryExpiredError();
    const keyring = this.core.Keyring.unlockWithRecovery(keys, grant.accountId, grant.wrappedAccountKey);
    this.verifyRecoveredKeyring(keyring, grant);
    this.recovering = { grant, keyring };
  }

  /** The recovered key must open the account's own key pairs (published in the key directory). */
  private verifyRecoveredKeyring(keyring: Core.Keyring, grant: RecoveryGrant) {
    if (!grant.accountKeys) return;
    try {
      keyring.loadAccountKeys(
        grant.accountKeys.bundle,
        grant.accountKeys.bundleSignature,
        grant.accountKeys.encryptedPrivate,
      );
    } catch {
      keyring.free();
      throw new RecoveryVerificationError();
    }
  }

  /** Whether a recovery is ready for `finishRecovery`. */
  get recoveryReady(): boolean {
    return this.recovering !== undefined;
  }

  /**
   * Sets a new master password for the recovered account. Creates a new
   * Secret Key and a new recovery code (the old ones stop working), signs
   * out every other device and unlocks this one. Show the result in a new
   * Emergency Kit.
   */
  async finishRecovery(newPassword: string): Promise<RecoveryResult> {
    const recovering = this.recovering;
    if (!recovering) throw new RecoveryExpiredError();
    const { core } = this;
    const { grant, keyring } = recovering;
    const account: DeviceAccount = {
      email: grant.email,
      accountId: grant.accountId,
      secretKey: core.generateSecretKey(),
      kdfSalt: core.generateKdfSalt(),
      kdfParams: JSON.parse(core.defaultKdfParams()) as KdfParams,
    };
    const keys = this.deriveKeys(account, newPassword);
    const recoveryCode = core.generateRecoveryCode();
    const codeKeys = core.RecoveryKeys.fromCode(recoveryCode);
    try {
      const registration = core.RegistrationFlow.start(keys);
      const codeRegistration = core.RegistrationFlow.startRecovery(codeKeys);
      let session: Awaited<ReturnType<PassboxApi["recovery"]["completeFinish"]>>;
      try {
        const start = await this.api.recovery.completeStart({
          recoveryToken: grant.recoveryToken,
          registrationRequest: registration.request,
          recoveryRegistrationRequest: codeRegistration.request,
        });
        const registrationUpload = registration.finish(start.registrationResponse);
        const codeUpload = codeRegistration.finish(start.recoveryRegistrationResponse ?? "");
        const encryptedAccountKey = keyring.wrapAccountKey(keys);
        session = await this.api.recovery.completeFinish({
          recoveryToken: grant.recoveryToken,
          registrationUpload,
          kdfSalt: account.kdfSalt,
          kdfParams: account.kdfParams,
          encryptedAccountKey,
          recoveryCode: {
            registrationUpload: codeUpload,
            wrappedAccountKey: keyring.wrapAccountKeyForRecovery(codeKeys),
          },
        });
        this.accountKeyCiphertextAfterRecovery = encryptedAccountKey;
      } catch (error) {
        throw recoveryError(error);
      } finally {
        registration.free();
        codeRegistration.free();
      }
      this.recovering = undefined;
      this.clearSession();
      this.storage.setItem(ACCOUNT_KEY, JSON.stringify(account));
      if (session.deviceToken) this.storage.setItem(DEVICE_TOKEN_KEY, session.deviceToken);
      this.storage.removeItem(ORG_RECOVERY_KEY);
      this.keyring = keyring;
      this.loadTrust(keyring, account.accountId);
      this.accountKeyCiphertext = this.accountKeyCiphertextAfterRecovery;
      this.token = session.token;
      this.loginAt = Date.now();
      await this.sync();
      await this.refreshRecoveryOptions().catch(() => undefined);
      return { accountId: account.accountId, email: account.email, secretKey: account.secretKey, recoveryCode };
    } finally {
      keys.free();
      codeKeys.free();
    }
  }

  /** Drops a recovery in progress (keys are wiped). */
  cancelRecovery(): void {
    this.pendingCodeRecovery?.keys.free();
    this.pendingCodeRecovery = undefined;
    this.recovering?.keyring.free();
    this.recovering = undefined;
  }

  // --- Organization recovery ------------------------------------------------------------

  /** The organization's recovery setup, verified against its roster. */
  async orgRecovery(orgId: string): Promise<OrgRecoveryInfo> {
    const keyring = this.requireKeyring();
    const state = await this.api.recovery.orgState(orgId);
    const base: OrgRecoveryInfo = {
      orgId,
      available: false,
      admins: [],
      canApprove: false,
      enrolled: state.escrow !== null && state.escrow.keyVersion === state.key?.keyVersion,
      ...(state.escrow ? { enrolledAt: state.escrow.createdAt } : {}),
      ...(state.enrolled ? { enrolledMembers: state.enrolled } : {}),
      ...(state.pendingRequests !== undefined ? { pendingRequests: state.pendingRequests } : {}),
    };
    if (!state.key) return base;
    try {
      const info = JSON.parse(keyring.verifyOrgRecovery(orgId, JSON.stringify(state.key))) as {
        keyVersion: number;
        fingerprint: string;
        admins: string[];
        canApprove: boolean;
      };
      return { ...base, available: true, ...info };
    } catch (error) {
      return { ...base, problem: String(error) };
    }
  }

  /** Sets up recovery for an organization (owners and admins); seals the recovery key for this account. */
  async setUpOrgRecovery(orgId: string): Promise<void> {
    const keyring = this.requireKeyring();
    const state = await this.api.recovery.orgState(orgId);
    const version = (state.key?.keyVersion ?? 0) + 1;
    const body = JSON.parse(keyring.createOrgRecoveryKey(orgId, version, Date.now()));
    await this.api.recovery.createOrgKey(orgId, body);
  }

  /** Lets another verified admin approve requests (this account must hold the key). */
  async addRecoveryAdmin(orgId: string, adminId: string): Promise<void> {
    const keyring = this.requireKeyring();
    const state = await this.api.recovery.orgState(orgId);
    if (!state.key) throw new Error("the organization has not set up recovery");
    const body = JSON.parse(keyring.grantOrgRecovery(orgId, JSON.stringify(state.key), adminId, Date.now()));
    await this.api.recovery.addOrgGrant(orgId, body);
  }

  /** Opts in: escrows the account key with the organization's verified recovery key. */
  async enrollOrgRecovery(orgId: string): Promise<void> {
    const keyring = this.requireKeyring();
    const state = await this.api.recovery.orgState(orgId);
    if (!state.key) throw new Error("the organization has not set up recovery");
    const body = JSON.parse(keyring.enrollOrgRecovery(orgId, JSON.stringify(state.key), Date.now()));
    await this.api.recovery.putEscrow(orgId, body);
    await this.refreshRecoveryOptions().catch(() => undefined);
  }

  /**
   * Enrolls in the recovery of every organization whose policy requires it
   * and that has recovery set up (on by default for new organizations;
   * members were told when they joined). Guests are never enrolled.
   * Returns the organizations enrolled now; failures (for example before an
   * admin confirmed the membership) are retried next time.
   */
  async enrollRequiredOrgRecovery(): Promise<string[]> {
    const required = this.getSnapshot().effectivePolicy.recoveryEnrollmentOrgs;
    if (required.length === 0) return [];
    const status = await this.recoveryStatus();
    const enrolled = new Set(status.orgEscrows.map((e) => e.orgId));
    const done: string[] = [];
    for (const orgId of required) {
      if (enrolled.has(orgId)) continue;
      try {
        await this.enrollOrgRecovery(orgId);
        done.push(orgId);
      } catch (error) {
        console.warn("Could not enroll in organization recovery yet", error);
      }
    }
    return done;
  }

  /**
   * Turns recovery off for the whole organization (owners and admins): the
   * recovery key, admins' copies and members' escrows are deleted. The
   * server refuses while the policy requires recovery (`recovery_required`).
   */
  async turnOffOrgRecovery(orgId: string): Promise<void> {
    this.requireKeyring();
    await this.api.recovery.turnOff(orgId);
    await this.refreshRecoveryOptions().catch(() => undefined);
  }

  /** Opts out: deletes the escrow. */
  async withdrawOrgRecovery(orgId: string): Promise<void> {
    this.requireKeyring();
    await this.api.recovery.deleteEscrow(orgId);
    await this.refreshRecoveryOptions().catch(() => undefined);
  }

  /** Open requests (admins who hold the key), each with the code to compare with the member. */
  async recoveryRequests(orgId: string): Promise<RecoveryRequest[]> {
    this.requireKeyring();
    const requests = await this.api.recovery.orgRequests(orgId);
    return requests.map((r) => ({ ...r, requestCode: this.core.recoveryRequestCode(r.ephemeralKey) }));
  }

  /**
   * Approves a request after the member's identity was verified out of band
   * and the request code compared. This device briefly holds the member's
   * account key while it re-seals it for the requesting device.
   */
  async approveRecoveryRequest(orgId: string, request: RecoveryRequest): Promise<void> {
    const keyring = this.requireKeyring();
    const state = await this.api.recovery.orgState(orgId);
    if (!state.key) throw new Error("the organization has not set up recovery");
    const { requestCode: _, email: __, ...record } = request;
    const body = JSON.parse(keyring.approveOrgRecovery(JSON.stringify(state.key), JSON.stringify(record), Date.now()));
    await this.api.recovery.approveRequest(orgId, request.id, body);
  }

  async denyRecoveryRequest(orgId: string, requestId: string): Promise<void> {
    this.requireKeyring();
    await this.api.recovery.denyRequest(orgId, requestId);
  }

  /**
   * Asks the organization to recover the account (while signed out or
   * locked). Keeps the request on this device; show `requestCode` and ask
   * the member to read it to the admin.
   */
  async requestOrgRecovery(email: string, orgId?: string): Promise<PendingOrgRecovery> {
    const key = this.core.RecoveryRequestKey.generate();
    try {
      const created = await this.api.recovery.orgRequest({
        email: email.trim().toLowerCase(),
        ...(orgId ? { orgId } : {}),
        ephemeralKey: key.publicKey,
        ...(this.device ? { deviceName: this.device.name } : {}),
      });
      const pending: PendingOrgRecovery = {
        requestId: created.requestId,
        requestToken: created.requestToken,
        seed: key.seed,
        email: email.trim().toLowerCase(),
        ...(orgId ? { orgId } : {}),
        requestCode: key.requestCode,
        createdAt: Date.now(),
        expiresAt: created.expiresAt,
      };
      this.storage.setItem(ORG_RECOVERY_KEY, JSON.stringify(pending));
      return pending;
    } finally {
      key.free();
    }
  }

  /** The organization recovery request this device is waiting for, if any. */
  get pendingOrgRecovery(): PendingOrgRecovery | undefined {
    const raw = this.storage.getItem(ORG_RECOVERY_KEY);
    if (!raw) return undefined;
    try {
      const pending = JSON.parse(raw) as PendingOrgRecovery;
      return pending.expiresAt > Date.now() ? pending : undefined;
    } catch {
      return undefined;
    }
  }

  /**
   * Checks the pending request. Once approved, opens the account key on this
   * device (verified against the account's key pairs); then call
   * `finishRecovery`.
   */
  async checkOrgRecovery(): Promise<OrgRecoveryRequestStatus> {
    const pending = this.pendingOrgRecovery;
    if (!pending) return "expired";
    const status = await this.api.recovery.orgStatus({
      requestId: pending.requestId,
      requestToken: pending.requestToken,
      ...(this.device ? { clientKind: this.device.kind } : {}),
    });
    if (status.status !== "approved") {
      if (status.status !== "pending") this.storage.removeItem(ORG_RECOVERY_KEY);
      return status.status;
    }
    if (!status.approved || !status.recovery) return "pending";
    const key = this.core.RecoveryRequestKey.fromSeed(pending.seed);
    try {
      const keyring = key.open(JSON.stringify(status.approved));
      this.verifyRecoveredKeyring(keyring, status.recovery);
      this.recovering?.keyring.free();
      this.recovering = { grant: status.recovery, keyring };
    } finally {
      key.free();
    }
    return "approved";
  }

  /** Withdraws the pending request. */
  async cancelOrgRecovery(): Promise<void> {
    const pending = this.pendingOrgRecovery;
    this.storage.removeItem(ORG_RECOVERY_KEY);
    if (pending) {
      await this.api.recovery
        .orgCancel({ requestId: pending.requestId, requestToken: pending.requestToken })
        .catch(() => undefined);
    }
  }

  // --- Emergency access ------------------------------------------------------------------

  /** People this account trusts (`granted`) and who trust it (`received`). */
  async emergencyContacts(): Promise<{ granted: EmergencyContact[]; received: EmergencyContact[] }> {
    this.requireKeyring();
    return this.api.emergency.list();
  }

  /** Adds a trusted person by email (they get a mail and must accept). */
  async addEmergencyContact(email: string, waitDays: number): Promise<string> {
    this.requireKeyring();
    const { id } = await this.api.emergency.create({ granteeEmail: email.trim().toLowerCase(), waitDays });
    return id;
  }

  /**
   * Seals the chosen personal vaults for an emergency contact who accepted.
   * Looks their key up in the key directory first; returns the fingerprint
   * the grantor can compare with them. Throws `KeyChanged` errors from the
   * core when their key changed (accept it with `acceptKeyChange` first).
   */
  async confirmEmergencyContact(grantId: string, vaultIds: string[]): Promise<string> {
    const keyring = this.requireKeyring();
    const { granted } = await this.api.emergency.list();
    const contact = granted.find((g) => g.id === grantId);
    if (!contact?.granteeId) throw new Error("the emergency contact has not accepted yet");
    await this.lookupKey(contact.granteeId);
    const body = JSON.parse(
      keyring.sealEmergencyAccess(
        grantId,
        contact.granteeId,
        contact.waitDays,
        JSON.stringify(vaultIds),
        contact.version + 1,
        Date.now(),
      ),
    ) as { fingerprint: string };
    await this.api.emergency.confirm(grantId, body);
    return body.fingerprint;
  }

  /**
   * Seals emergency access again where vault keys changed or chosen vaults
   * were deleted. Runs after unlocking (best effort); returns how many
   * grants were updated.
   */
  async resealEmergencyAccess(): Promise<number> {
    const keyring = this.requireKeyring();
    const { granted } = await this.api.emergency.list();
    let updated = 0;
    for (const contact of granted) {
      if (contact.status !== "confirmed" || !contact.grant || !contact.grantSignature || !contact.granteeId) continue;
      const vaultIds = contact.vaultIds.filter((id) => {
        const vault = this.vaults.get(id);
        return vault !== undefined && !vault.orgId;
      });
      if (!keyring.emergencyResealNeeded(contact.grant, contact.grantSignature, JSON.stringify(vaultIds))) continue;
      try {
        await this.lookupKey(contact.granteeId);
        const body = JSON.parse(
          keyring.sealEmergencyAccess(
            contact.id,
            contact.granteeId,
            contact.waitDays,
            JSON.stringify(vaultIds),
            contact.version + 1,
            Date.now(),
          ),
        );
        await this.api.emergency.confirm(contact.id, body);
        updated += 1;
      } catch (error) {
        console.warn("Could not update emergency access", contact.id, error);
      }
    }
    return updated;
  }

  async removeEmergencyContact(grantId: string): Promise<void> {
    this.requireKeyring();
    await this.api.emergency.remove(grantId);
  }

  async acceptEmergencyInvitation(grantId: string): Promise<void> {
    this.requireKeyring();
    await this.api.emergency.accept(grantId);
  }

  /** As the trusted person: starts the waiting period. */
  async requestEmergencyAccess(grantId: string): Promise<void> {
    this.requireKeyring();
    await this.api.emergency.request(grantId);
  }

  /** As the grantor: releases access before the waiting period ends. */
  async approveEmergencyAccess(grantId: string): Promise<void> {
    this.requireKeyring();
    await this.api.emergency.approve(grantId);
  }

  /** As the grantor: declines the request (or ends released access). */
  async denyEmergencyAccess(grantId: string): Promise<void> {
    this.requireKeyring();
    await this.api.emergency.deny(grantId);
  }

  /**
   * As the trusted person, after the release: fetches the grantor's chosen
   * vaults, verifies the grantor's signature (key from the key directory)
   * and decrypts them. Nothing is stored; the keys are wiped afterwards.
   */
  async openEmergencyAccess(grantId: string): Promise<EmergencyVaults> {
    const keyring = this.requireKeyring();
    const { received } = await this.api.emergency.list();
    const contact = received.find((g) => g.id === grantId);
    const data = await this.api.emergency.access(grantId);
    await this.lookupKey(data.grantorId);
    const keys = keyring.openEmergencyAccess(data.grant, data.grantSignature, data.sealedKeys);
    const errors: string[] = [];
    try {
      const vaults = data.vaults.flatMap((v) => {
        try {
          return [{ id: v.id, name: parseVaultMeta(keys.decryptVaultMeta(v.id, v.keyEpoch, v.encryptedMeta)).name }];
        } catch (error) {
          errors.push(`Vault ${v.id}: ${String(error)}`);
          return [];
        }
      });
      const items = data.items.flatMap((item): Item[] => {
        try {
          const json = keys.decryptItem(item.vaultId, item.keyEpoch, item.id, item.revision, item.encryptedData);
          return [
            {
              id: item.id,
              vaultId: item.vaultId,
              revision: item.revision,
              updatedAt: item.updatedAt,
              keyEpoch: item.keyEpoch,
              data: parseItemData(json),
            },
          ];
        } catch (error) {
          errors.push(`Item ${item.id}: ${String(error)}`);
          return [];
        }
      });
      return {
        grantorId: data.grantorId,
        grantorEmail: contact?.grantorEmail ?? "",
        vaults,
        items: items
          .filter((i) => i.data.trashedAt === undefined)
          .sort((a, b) => a.data.title.localeCompare(b.data.title)),
        errors,
      };
    } finally {
      keys.free();
    }
  }

  // --- Adding a device by code -----------------------------------------------------------

  /** On a signed-in device: opens a link and returns the code to show (valid 10 minutes). */
  async startDeviceLink(): Promise<DeviceLinkStart> {
    this.requireKeyring();
    const link = await this.api.deviceLinks.create();
    const offer = new this.core.DeviceLinkOffer(link.shortId);
    this.deviceLinkOffers.get(link.id)?.free();
    this.deviceLinkOffers.set(link.id, offer);
    return { id: link.id, code: offer.code, expiresAt: link.expiresAt };
  }

  /** Whether the new device entered the code, and its name. */
  async deviceLinkStatus(linkId: string): Promise<DeviceLinkState> {
    this.requireKeyring();
    try {
      const info = await this.api.deviceLinks.get(linkId);
      return {
        status: info.status,
        expiresAt: info.expiresAt,
        ...(info.deviceName ? { deviceName: info.deviceName } : {}),
        ...(info.ip ? { ip: info.ip } : {}),
      };
    } catch (error) {
      throw deviceLinkError(error);
    }
  }

  /**
   * Sends the email, account ID and Secret Key to the new device, sealed to
   * its key. Throws `InvalidDeviceCodeError` when the claim did not come from
   * a device that knows the code (for example a swapped key).
   */
  async approveDeviceLink(linkId: string): Promise<void> {
    this.requireKeyring();
    const account = this.deviceAccount;
    const offer = this.deviceLinkOffers.get(linkId);
    if (!account || !offer) throw new InvalidDeviceCodeError();
    try {
      const info = await this.api.deviceLinks.get(linkId);
      if (info.status !== "claimed" || !info.ephemeralKey || !info.mac) throw new InvalidDeviceCodeError();
      const payload: LinkedAccount = {
        email: account.email,
        accountId: account.accountId,
        secretKey: account.secretKey,
      };
      let sealed: string;
      try {
        sealed = offer.seal(info.ephemeralKey, info.mac, JSON.stringify(payload));
      } catch {
        throw new InvalidDeviceCodeError();
      }
      await this.api.deviceLinks.approve(linkId, sealed);
    } catch (error) {
      throw deviceLinkError(error);
    } finally {
      this.deviceLinkOffers.delete(linkId);
      offer.free();
    }
  }

  async cancelDeviceLink(linkId: string): Promise<void> {
    this.deviceLinkOffers.get(linkId)?.free();
    this.deviceLinkOffers.delete(linkId);
    await this.api.deviceLinks.cancel(linkId).catch(() => undefined);
  }

  /** Whether `input` has the shape of a device code. */
  isDeviceCode(input: string): boolean {
    return this.core.isDeviceCode(input);
  }

  /** On the new device: answers the code shown on the signed-in device. */
  async claimDeviceLink(code: string): Promise<void> {
    let request: Core.DeviceLinkRequest;
    try {
      request = new this.core.DeviceLinkRequest(code);
    } catch {
      throw new InvalidDeviceCodeError();
    }
    try {
      const claim = await this.api.deviceLinks.claim({
        shortId: request.shortId,
        ephemeralKey: request.publicKey,
        mac: request.mac,
        ...(this.device ? { deviceName: this.device.name } : {}),
      });
      this.deviceLinkRequest?.request.free();
      this.deviceLinkRequest = { request, claimToken: claim.claimToken };
    } catch (error) {
      request.free();
      throw deviceLinkError(error);
    }
  }

  /**
   * Polls for the approval. Returns the account details once approved (then
   * sign in with them and the master password), `undefined` while waiting.
   */
  async pollDeviceLink(): Promise<LinkedAccount | undefined> {
    const pending = this.deviceLinkRequest;
    if (!pending) throw new InvalidDeviceCodeError();
    let result: { status: string; sealedPayload?: string };
    try {
      result = await this.api.deviceLinks.poll(pending.claimToken);
    } catch (error) {
      throw deviceLinkError(error);
    }
    if (result.status !== "approved" || !result.sealedPayload) return undefined;
    try {
      const payload = JSON.parse(pending.request.open(result.sealedPayload)) as LinkedAccount;
      return { email: payload.email, accountId: payload.accountId, secretKey: payload.secretKey };
    } finally {
      pending.request.free();
      this.deviceLinkRequest = undefined;
    }
  }

  /** Drops a device code this (new) device entered. */
  cancelDeviceLinkClaim(): void {
    this.deviceLinkRequest?.request.free();
    this.deviceLinkRequest = undefined;
  }

  // --- Signing in another device from this browser (pbx login) ------------------------

  private cliLoginApproval(id: string, secret: string): Core.CliLoginApproval {
    try {
      return new this.core.CliLoginApproval(id, secret);
    } catch {
      throw new CliLoginVerificationError();
    }
  }

  /**
   * The sign-in request a link points to (ID and secret from its fragment),
   * after checking that the key and device name are the ones the requesting
   * device registered. Throws `CliLoginExpiredError` or
   * `CliLoginVerificationError`.
   */
  async cliLoginRequest(id: string, secret: string): Promise<CliLoginRequestInfo> {
    this.requireKeyring();
    const approval = this.cliLoginApproval(id, secret);
    try {
      let info: Awaited<ReturnType<typeof this.api.cliLogins.get>>;
      try {
        info = await this.api.cliLogins.get(id);
      } catch (error) {
        throw cliLoginError(error);
      }
      try {
        approval.verify(info.ephemeralKey, info.deviceName, info.mac);
      } catch {
        throw new CliLoginVerificationError();
      }
      return {
        id: info.id,
        deviceName: info.deviceName,
        ip: info.ip,
        createdAt: info.createdAt,
        expiresAt: info.expiresAt,
      };
    } finally {
      approval.free();
    }
  }

  /**
   * Sends the email, account ID and Secret Key to the requesting device,
   * sealed to its key. The master password is never sent: the device asks
   * for it. Nothing is sent if the request does not match the link.
   */
  async approveCliLogin(id: string, secret: string): Promise<void> {
    this.requireKeyring();
    const account = this.deviceAccount;
    if (!account) throw new CliLoginExpiredError();
    const approval = this.cliLoginApproval(id, secret);
    try {
      let sealed: string;
      try {
        const info = await this.api.cliLogins.get(id);
        const payload: LinkedAccount = {
          email: account.email,
          accountId: account.accountId,
          secretKey: account.secretKey,
        };
        try {
          sealed = approval.seal(info.ephemeralKey, info.deviceName, info.mac, JSON.stringify(payload));
        } catch {
          throw new CliLoginVerificationError();
        }
        await this.api.cliLogins.approve(id, sealed);
      } catch (error) {
        throw cliLoginError(error);
      }
    } finally {
      approval.free();
    }
  }

  /** Denies a sign-in request; the requesting device is told. */
  async denyCliLogin(id: string): Promise<void> {
    this.requireKeyring();
    try {
      await this.api.cliLogins.deny(id);
    } catch (error) {
      throw cliLoginError(error);
    }
  }

  // --- Single sign-on and trusted devices -----------------------------------------

  /** SSO configuration, trusted devices and SCIM endpoints (organization settings). */
  get sso(): SsoApi {
    return this.api.sso;
  }

  /** The organization whose identity provider signs in this email's domain, if any. */
  async ssoFor(email: string): Promise<SsoOption | undefined> {
    const { sso } = await this.api.sso.discover(email.trim().toLowerCase());
    return sso ?? undefined;
  }

  /** Starts an SSO sign-in; send the browser to `authorizationUrl` and keep `flowSecret`. */
  startSso(orgId: string, email?: string): Promise<SsoStart> {
    return this.api.sso.start({ orgId, ...(email ? { email: email.trim().toLowerCase() } : {}) });
  }

  /** Turns the ticket from the callback into a proof (`status: "no_account"` without an account). */
  redeemSso(ticket: string, flowSecret: string, deviceId?: string): Promise<SsoRedeemed> {
    return this.api.sso.redeem({ ticket, flowSecret, ...(deviceId ? { deviceId } : {}) });
  }

  /**
   * Unlocks a trusted device with an SSO proof instead of the master password:
   * the server returns the account key sealed to this device, and the core
   * opens it and checks it against the account's own keys.
   */
  async unlockWithSso(proof: string, device: TrustedDeviceSecret): Promise<void> {
    const response = await this.api.sso.unlock({
      proof,
      deviceId: device.deviceId,
      ...(this.device ? { deviceName: this.device.name, clientKind: this.device.kind } : {}),
    });
    await this.adoptSsoSession(response, device.seed);
  }

  private async adoptSsoSession(response: SsoUnlockResponse, seed: string): Promise<void> {
    const key = this.core.TrustedDeviceKey.fromSeed(seed);
    let keyring: Core.Keyring;
    try {
      keyring = key.unlock(JSON.stringify(response.unlock));
    } finally {
      key.free();
    }
    this.cancelTwoFactor();
    this.clearSession();
    this.keyring = keyring;
    this.token = response.session.token;
    this.loginAt = Date.now();
    this.storage.setItem(DEVICE_TOKEN_KEY, response.session.deviceToken);
    this.loadTrust(keyring, response.unlock.accountId);
    const existing = this.deviceAccount;
    if (existing?.accountId !== response.unlock.accountId) {
      // A device approved by another device does not know the Secret Key;
      // it unlocks with SSO, and with the Emergency Kit after signing in again.
      const remote = await this.api.account();
      const account: DeviceAccount = {
        email: remote.email,
        accountId: remote.accountId,
        secretKey: "",
        kdfSalt: remote.kdfSalt,
        kdfParams: remote.kdfParams,
      };
      this.storage.setItem(ACCOUNT_KEY, JSON.stringify(account));
    }
    await this.sync();
  }

  /** Trusted devices of the account and new devices waiting for approval. */
  trustedDevices(): Promise<TrustedDevicesResponse> {
    return this.api.sso.trustedDevices();
  }

  /**
   * Makes this unlocked device a trusted device (needs a recent login; the
   * organization must allow SSO unlock). Store the returned secret in
   * protected storage; without it, the device unlocks with the master password.
   */
  async trustThisDevice(name?: string): Promise<TrustedDeviceSecret> {
    const keyring = this.requireKeyring();
    const key = this.core.TrustedDeviceKey.generate();
    try {
      const deviceId = this.core.newId();
      const upload = JSON.parse(keyring.trustDevice(deviceId, key.publicKey, "", Date.now())) as TrustedDeviceUpload;
      try {
        await this.api.sso.trustDevice({ ...upload, ...(name ? { name } : {}) });
      } catch (error) {
        if (error instanceof ApiError && error.code === "reauthentication_required") {
          throw new ReauthenticationRequiredError();
        }
        throw error;
      }
      return { accountId: keyring.accountId, deviceId, seed: key.seed };
    } finally {
      key.free();
    }
  }

  /** The code to compare with a new device before approving it. */
  approvalCode(publicKey: string): string {
    return this.core.trustedDeviceApprovalCode(publicKey);
  }

  /**
   * Approves a new device after the user compared `approvalCode` with the
   * code it shows: seals the account key to its public key. `ownDeviceId` is
   * this device's trusted device ID, if it has one.
   */
  async approveDevice(request: { id: string; publicKey: string }, ownDeviceId?: string): Promise<void> {
    const keyring = this.requireKeyring();
    const upload = JSON.parse(
      keyring.trustDevice(request.id, request.publicKey, ownDeviceId ?? "", Date.now()),
    ) as TrustedDeviceUpload;
    try {
      await this.api.sso.approveDevice(request.id, upload);
    } catch (error) {
      if (error instanceof ApiError && error.code === "reauthentication_required") {
        throw new ReauthenticationRequiredError();
      }
      throw error;
    }
  }

  denyDevice(requestId: string): Promise<void> {
    return this.api.sso.denyDevice(requestId);
  }

  removeTrustedDevice(id: string): Promise<void> {
    return this.api.sso.removeTrustedDevice(id);
  }

  /** On a new device after SSO: asks a trusted device of the account for approval. */
  async requestDeviceApproval(proof: string): Promise<PendingDeviceApproval> {
    const key = this.core.TrustedDeviceKey.generate();
    try {
      const created = await this.api.sso.requestDevice({
        proof,
        publicKey: key.publicKey,
        ...(this.device ? { deviceName: this.device.name, clientKind: this.device.kind } : {}),
      });
      return {
        requestId: created.requestId,
        requestToken: created.requestToken,
        approvalCode: key.approvalCode,
        expiresAt: created.expiresAt,
        seed: key.seed,
      };
    } finally {
      key.free();
    }
  }

  /**
   * Polls a pending approval. Once approved, unlocks (the device is now
   * trusted: store the returned secret) and returns it.
   */
  async checkDeviceApproval(
    pending: PendingDeviceApproval,
  ): Promise<{ status: "pending" | "denied" } | { status: "approved"; device: TrustedDeviceSecret }> {
    const result = await this.api.sso.deviceRequestStatus(pending.requestToken);
    if (result.status !== "approved" || !result.result) {
      return { status: result.status === "denied" ? "denied" : "pending" };
    }
    await this.adoptSsoSession(result.result, pending.seed);
    return {
      status: "approved",
      device: { accountId: result.result.unlock.accountId, deviceId: pending.requestId, seed: pending.seed },
    };
  }

  // --- Organization administration -------------------------------------------------
  //
  // Policies are signed by an owner or admin and verified in the Rust core
  // during `sync`; this client enforces them where it acts (personal vaults,
  // export, auto-lock, master password strength) and reports item usage
  // when an organization's policy asks for it. See
  // docs/architecture/administration.md.

  /** Policies in force per organization. */
  policies(): OrgPolicy[] {
    return this.viewNow().policies ?? [];
  }

  /** The policy of one organization, if it has one. */
  orgPolicy(orgId: string): OrgPolicy | undefined {
    return this.policies().find((p) => p.orgId === orgId);
  }

  /** Every policy this account is bound by, combined. */
  effectivePolicy(): EffectivePolicy {
    return this.viewNow().effectivePolicy ?? NO_POLICY;
  }

  /**
   * Strength score (0–4) of the master password as entered at the last
   * unlock on this device; `undefined` before that. The password itself is
   * not kept.
   */
  get unlockPasswordScore(): number | undefined {
    return this.passwordScore;
  }

  // --- Hosted service: Business billing ------------------------------------------
  //
  // Only on the hosted service (`meta.extensions.cloud`), for the owner and admins.

  /** The organization's subscription: status, members counted and billed, period. */
  async cloudBilling(orgId: string): Promise<CloudBilling> {
    this.requireKeyring();
    return this.api.cloudBilling(orgId);
  }

  /** Starts a checkout for Business; the app opens the returned URL with a top-level redirect. */
  async cloudCheckout(orgId: string, interval: BillingInterval): Promise<{ url: string }> {
    this.requireKeyring();
    return this.api.cloudCheckout(orgId, interval);
  }

  /** The billing portal (payment method, invoices, plan); the app opens the URL with a top-level redirect. */
  async cloudPortal(orgId: string): Promise<{ url: string }> {
    this.requireKeyring();
    return this.api.cloudPortal(orgId);
  }

  /** Raw API for organization administration (reports, settings, tokens, webhooks). */
  get orgAdmin(): OrgAdminApi {
    this.requireKeyring();
    return this.api.orgAdmin;
  }

  /**
   * Signs and uploads the next version of an organization's policy (owners
   * and admins). Retries once after a sync if another admin changed it
   * meanwhile.
   */
  async setOrgPolicy(orgId: string, rules: PolicyRules): Promise<OrgPolicy> {
    const upload = async () => {
      await this.sync();
      const body = JSON.parse(this.requireKeyring().signOrgPolicy(orgId, JSON.stringify(rules), Date.now())) as {
        version: number;
        policy: string;
        signature: string;
      };
      await this.api.orgAdmin.putPolicy(orgId, body);
    };
    try {
      await upload();
    } catch (error) {
      if (!(error instanceof ApiError && error.code === "conflict")) throw error;
      await upload();
    }
    await this.sync();
    const policy = this.orgPolicy(orgId);
    if (!policy) throw new Error("the new policy could not be verified");
    return policy;
  }

  /** Every version of an organization's policy, newest first, each verified on this device (admins). */
  async policyHistory(orgId: string): Promise<(OrgPolicy | { version: number; problem: string })[]> {
    const keyring = this.requireKeyring();
    const state = await this.api.orgAdmin.policy(orgId);
    return [...state.history].reverse().map((record) => {
      try {
        return JSON.parse(keyring.verifyOrgPolicy(orgId, JSON.stringify(record))) as OrgPolicy;
      } catch (error) {
        return { version: record.version, problem: String(error) };
      }
    });
  }

  /**
   * Downloads the audit log as JSON and checks its hash chain on this
   * device (independently of the server's own check).
   */
  async exportAuditLog(orgId: string, query: AuditQuery = {}): Promise<{ data: AuditExport; check: ChainCheck }> {
    this.requireKeyring();
    const data = await this.api.orgAdmin.exportAudit(orgId, "json", query);
    return { data, check: this.verifyAuditExport(data, query) };
  }

  /** Checks an audit export's hash chain with the core. */
  verifyAuditExport(data: AuditExport, query: AuditQuery = {}): ChainCheck {
    const filtered = Object.values(query).some((v) => v !== undefined && v !== "");
    const first = data.events[0];
    // A filtered export has gaps; only an unfiltered one can be checked end to end.
    if (filtered) {
      return { valid: true, length: data.events.length, problem: "filtered export: entries are checked one by one" };
    }
    const anchor = first && first.seq === data.head.prunedSeq + 1 ? data.head.prunedHash : undefined;
    return JSON.parse(this.core.verifyAuditChain(JSON.stringify(data.events), anchor)) as ChainCheck;
  }

  /**
   * Offboards a member (owners and admins): optionally hands vaults over
   * first (grants `manage` to a successor; this device must hold the vault
   * key), optionally signs the member out everywhere (team organizations),
   * then removes them, which rotates the keys of every vault this account
   * manages. Returns vaults that still wait for a manager to rotate them.
   */
  async offboardMember(
    orgId: string,
    accountId: string,
    options: { handovers?: { vaultId: string; successorId: string }[]; endSessions?: boolean } = {},
  ): Promise<{ pendingRotation: string[] }> {
    await this.sync();
    for (const handover of options.handovers ?? []) {
      await this.shareVault(handover.vaultId, "account", handover.successorId, "manage");
    }
    if (options.endSessions) await this.api.orgAdmin.endSessions(orgId, accountId);
    const signedPolicy = this.orgPolicy(orgId)?.signerId === accountId;
    await this.removeMember(orgId, accountId);
    // A policy signed by the removed admin would stop verifying: sign it again.
    const policy = this.orgPolicy(orgId);
    if (signedPolicy && policy) await this.setOrgPolicy(orgId, policy.rules);
    return {
      pendingRotation: this.viewNow()
        .vaults.filter((v) => v.orgId === orgId && v.rotationPending)
        .map((v) => v.vaultId),
    };
  }

  /**
   * Records that the user viewed, revealed, copied or filled an item, if
   * the item's organization asks for item usage in its policy. Events are
   * signed at once and uploaded in the background; nothing is recorded for
   * personal vaults.
   */
  reportItemUsage(itemId: string, action: ClientAuditAction, field = ""): void {
    const keyring = this.keyring;
    const item = this.items.get(itemId);
    if (!keyring || !item) return;
    const orgId = this.vaults.get(item.vaultId)?.orgId;
    if (!orgId || !this.effectivePolicy().itemUsageOrgs.includes(orgId)) return;
    try {
      const signed = JSON.parse(
        keyring.signClientEvents(
          orgId,
          JSON.stringify([{ action, vaultId: item.vaultId, itemId, field, occurredAt: Date.now() }]),
        ),
      ) as SignedClientEvent[];
      const queue = this.usageQueue(keyring.accountId);
      queue.push(...signed.map((event) => ({ orgId, ...event })));
      this.storage.setItem(`${USAGE_QUEUE_KEY}.${keyring.accountId}`, JSON.stringify(queue.slice(-MAX_USAGE_QUEUE)));
    } catch {
      return;
    }
    if (!this.usageTimer) {
      this.usageTimer = setTimeout(() => {
        this.usageTimer = undefined;
        void this.flushItemUsage().catch(() => undefined);
      }, USAGE_FLUSH_DELAY_MS);
    }
  }

  private usageQueue(accountId: string): ({ orgId: string } & SignedClientEvent)[] {
    try {
      const raw = this.storage.getItem(`${USAGE_QUEUE_KEY}.${accountId}`);
      return raw ? (JSON.parse(raw) as ({ orgId: string } & SignedClientEvent)[]) : [];
    } catch {
      return [];
    }
  }

  /** Uploads queued item usage events (also after the next unlock). */
  async flushItemUsage(): Promise<number> {
    const keyring = this.keyring;
    if (!keyring || !this.token) return 0;
    const queue = this.usageQueue(keyring.accountId);
    if (queue.length === 0) return 0;
    const byOrg = new Map<string, SignedClientEvent[]>();
    for (const { orgId, event, signature } of queue)
      byOrg.set(orgId, [...(byOrg.get(orgId) ?? []), { event, signature }]);
    const failed: ({ orgId: string } & SignedClientEvent)[] = [];
    let sent = 0;
    for (const [orgId, events] of byOrg) {
      try {
        await this.api.orgAdmin.clientEvents(orgId, events.slice(0, 200));
        sent += Math.min(events.length, 200);
        failed.push(...events.slice(200).map((e) => ({ orgId, ...e })));
      } catch (error) {
        // Policy turned off or the account left: drop; network errors: keep.
        if (!(error instanceof ApiError && (error.status === 403 || error.status === 404 || error.status === 400))) {
          failed.push(...events.map((e) => ({ orgId, ...e })));
        }
      }
    }
    this.storage.setItem(`${USAGE_QUEUE_KEY}.${keyring.accountId}`, JSON.stringify(failed));
    return sent;
  }

  /**
   * Reports this account's security aggregate (scores and counts, never
   * items or passwords) to each team organization it is a confirmed
   * member of, at most once a day per organization.
   */
  async reportSecurityAggregates(now = Date.now()): Promise<number> {
    const keyring = this.requireKeyring();
    const policy = this.effectivePolicy();
    const meets =
      this.passwordScore === undefined || policy.minPasswordScore === 0
        ? undefined
        : this.passwordScore >= policy.minPasswordScore;
    const aggregate = securityAggregate(this.health(), meets);
    let report: SecurityReport | undefined;
    let reported = 0;
    for (const org of this.orgs()) {
      if (org.kind !== "team" || org.status !== "confirmed") continue;
      const key = `${SECURITY_REPORT_KEY}.${keyring.accountId}.${org.id}`;
      const last = Number(this.storage.getItem(key) ?? 0);
      if (now - last < SECURITY_REPORT_INTERVAL_MS) continue;
      // Breached websites: counts for the logins in this organization's vaults only.
      report ??= this.securityReport(DEFAULT_REPORT_OPTIONS, now);
      const orgItems = new Set(
        this.snapshot.items.filter((i) => this.vaults.get(i.vaultId)?.orgId === org.id).map((i) => i.id),
      );
      await this.api.orgAdmin.putSecurityReport(org.id, {
        ...aggregate,
        siteBreaches: siteBreachCounts(report, orgItems),
      });
      this.storage.setItem(key, String(now));
      reported++;
    }
    return reported;
  }

  private ensurePersonalVaultsAllowed(): void {
    const policy = this.effectivePolicy();
    if (!policy.allowPersonalVault) {
      throw new PolicyViolationError(
        "personal_vault",
        policy.personalVaultOrgs,
        "your organization does not allow personal vaults; save items in a shared vault",
      );
    }
  }

  // --- Service accounts and agent grants ------------------------------------------

  private vaultEpoch(vaultId: string): number {
    const vault = this.snapshot.vaults.find((v) => v.id === vaultId);
    if (!vault) throw new Error(`vault ${vaultId} not found`);
    return vault.keyEpoch ?? 0;
  }

  /** Service accounts of this account, newest first. */
  async serviceAccounts(): Promise<ServiceAccount[]> {
    const records = await this.api.developer.serviceAccounts();
    return records.map((r) => ({ ...r, state: serviceAccountState(r) }));
  }

  /**
   * Creates a service account with access to `vaults`. `expiresAt` is Unix
   * ms, or 0 for no expiry. The returned token is shown once and is not
   * stored anywhere.
   */
  async createServiceAccount(
    name: string,
    vaults: ServiceAccountVaultChoice[],
    expiresAt: number,
  ): Promise<CreatedServiceAccount> {
    const keyring = this.requireKeyring();
    const created = JSON.parse(keyring.createServiceAccount(Date.now())) as {
      id: string;
      token: string;
      publicKey: string;
      publicKeySignature: string;
      encryptedPrivate: string;
      authHash: string;
    };
    const grants = vaults.map((v) =>
      JSON.parse(
        keyring.grantServiceAccount(
          created.publicKey,
          created.publicKeySignature,
          v.vaultId,
          this.vaultEpoch(v.vaultId),
          v.permission,
          Date.now(),
        ),
      ),
    );
    const record = await this.api.developer.createServiceAccount({
      id: created.id,
      name,
      publicKey: created.publicKey,
      publicKeySignature: created.publicKeySignature,
      encryptedPrivate: created.encryptedPrivate,
      authHash: created.authHash,
      expiresAt,
      grants,
    });
    return { account: { ...record, state: serviceAccountState(record) }, token: created.token };
  }

  /** Gives a service account access to a vault, changes the permission, or renews it after a key rotation. */
  async grantServiceAccount(
    account: Pick<ServiceAccount, "id" | "publicKey" | "publicKeySignature">,
    vaultId: string,
    permission: ServiceAccountPermission,
  ): Promise<ServiceAccount> {
    const grant = JSON.parse(
      this.requireKeyring().grantServiceAccount(
        account.publicKey,
        account.publicKeySignature,
        vaultId,
        this.vaultEpoch(vaultId),
        permission,
        Date.now(),
      ),
    );
    const record = await this.api.developer.putServiceAccountGrants(account.id, [grant]);
    return { ...record, state: serviceAccountState(record) };
  }

  async removeServiceAccountVault(serviceAccountId: string, vaultId: string): Promise<void> {
    await this.api.developer.deleteServiceAccountGrant(serviceAccountId, vaultId);
  }

  async updateServiceAccount(id: string, changes: { name?: string; expiresAt?: number }): Promise<ServiceAccount> {
    const record = await this.api.developer.updateServiceAccount(id, changes);
    return { ...record, state: serviceAccountState(record) };
  }

  /** The token stops working at once; the service account stays listed. */
  async revokeServiceAccount(id: string): Promise<void> {
    await this.api.developer.revokeServiceAccount(id);
  }

  async deleteServiceAccount(id: string): Promise<void> {
    await this.api.developer.deleteServiceAccount(id);
  }

  /** The fair-use limit for AI agents and service accounts (they never count as members). */
  async agentLimit(): Promise<AgentUsage> {
    return this.api.developer.agentLimit();
  }

  async serviceAccountEvents(id: string): Promise<ServiceAccountEventRecord[]> {
    return this.api.developer.serviceAccountEvents(id);
  }

  /**
   * Agent grant requests, parsed from the exact bytes a decision signs
   * (`pending` by default, or the last 30 days). Requests that do not parse
   * or are not for this account are left out.
   */
  async agentRequests(status: "pending" | "all" = "pending"): Promise<AgentRequest[]> {
    const records = await this.api.developer.agentGrants(status);
    const accountId = this.deviceAccount?.accountId;
    const out: AgentRequest[] = [];
    for (const record of records) {
      try {
        const parsed = JSON.parse(this.core.parseAgentRequest(record.request)) as Omit<
          AgentRequest,
          "raw" | "status" | "expiresAt" | "notAfter" | "decidedDevice" | "decidedAt" | "principalName"
        > & { onBehalfOf: string };
        if (parsed.onBehalfOf !== accountId || parsed.id !== record.id) continue;
        const { onBehalfOf: _, ...rest } = parsed;
        out.push({
          ...rest,
          ...(record.principalName ? { principalName: record.principalName } : {}),
          raw: record.request,
          status: record.status,
          expiresAt: record.expiresAt,
          notAfter: record.notAfter,
          decidedDevice: record.decidedDevice,
          decidedAt: record.decidedAt,
        });
      } catch (error) {
        console.warn("Ignoring an agent request that could not be parsed", error);
      }
    }
    return out;
  }

  /**
   * Approves or denies an agent request, signed with this account's key.
   * `maxUses` 0 keeps the request's limit. `allowReveal` is the person's
   * explicit tick "Allow revealing the value to the agent" for a request
   * that asks for `reveal` (`passbox_reveal`); the core refuses it when an
   * organization's policy forbids reveals for one of the items' vaults.
   */
  async decideAgentRequest(request: AgentRequest, approved: boolean, maxUses = 0, allowReveal = false): Promise<void> {
    const signed = JSON.parse(
      this.requireKeyring().decideAgentGrant(request.raw, approved, maxUses, Date.now(), allowReveal),
    ) as {
      decision: string;
      decisionSignature: string;
    };
    await this.api.developer.decideAgentGrant(request.id, signed);
  }

  /** Ends an approved agent grant early. */
  async revokeAgentGrant(id: string): Promise<void> {
    await this.api.developer.revokeAgentGrant(id);
  }

  async agentEvents(limit = 100): Promise<AgentEventRecord[]> {
    return this.api.developer.agentEvents(limit);
  }

  private async handleWriteError(error: unknown): Promise<never> {
    if (error instanceof ApiError && error.code === "conflict") {
      await this.sync();
      throw new ConflictError();
    }
    throw error;
  }

  // --- Archive, moving, attachments, share links, access requests ----------------
  //
  // See docs/architecture/attachments.md and docs/architecture/sharing.md.

  /** Archives an item: hidden from lists, search and autofill, kept in its vault. */
  async archiveItem(id: string): Promise<void> {
    await this.setArchived(id, Date.now());
  }

  /** Takes an item out of the archive. */
  async unarchiveItem(id: string): Promise<void> {
    await this.setArchived(id, undefined);
  }

  private async setArchived(id: string, at: number | undefined) {
    const item = this.items.get(id);
    if (!item) throw new Error("unknown item");
    const { archivedAt: _previous, ...data } = item.data;
    await this.writeItem(item.vaultId, id, item.revision + 1, at === undefined ? data : { ...data, archivedAt: at });
  }

  /**
   * Who gains and who loses access when items move into `targetVaultId`:
   * the people (accounts, through groups too) of the target vault minus
   * those of the current vaults, and the other way round. Personal vaults
   * count as "only you".
   */
  movePreview(ids: readonly string[], targetVaultId: string): MovePreview {
    const me = this.deviceAccount?.accountId ?? "";
    const audience = (vaultId: string): Map<string, MoveAudienceMember> => {
      const out = new Map<string, MoveAudienceMember>();
      const vault = this.vaults.get(vaultId);
      if (!vault?.orgId) {
        out.set(me, { accountId: me, email: this.deviceAccount?.email ?? "", role: "manage" });
        return out;
      }
      const shared = this.sharingView.vaults.find((v) => v.vaultId === vaultId);
      const org = this.sharingView.orgs.find((o) => o.id === vault.orgId);
      for (const member of shared?.members ?? []) {
        const accounts =
          member.principalType === "group"
            ? (org?.groups.find((g) => g.id === member.principalId)?.members ?? [])
            : [member.principalId];
        for (const accountId of accounts) {
          const email = org?.members.find((m) => m.accountId === accountId)?.email ?? "";
          const known = out.get(accountId);
          if (!known || roleRank(member.role) > roleRank(known.role)) {
            out.set(accountId, { accountId, email, role: member.role });
          }
        }
      }
      return out;
    };
    const target = audience(targetVaultId);
    const sources = new Set(
      ids.map((id) => this.items.get(id)?.vaultId).filter((v): v is string => !!v && v !== targetVaultId),
    );
    const before = new Map<string, MoveAudienceMember>();
    for (const vaultId of sources) for (const [id, m] of audience(vaultId)) before.set(id, m);
    return {
      gain: [...target.values()].filter((m) => !before.has(m.accountId)),
      lose: [...before.values()].filter((m) => !target.has(m.accountId)),
      keep: [...target.values()].filter((m) => before.has(m.accountId)),
    };
  }

  /**
   * Moves items into another vault. Each item is re-encrypted here for the
   * target vault and keeps its ID, creation date, attachments and the
   * versions of its history this device can read. Show `movePreview`
   * first. Items already in the target are skipped. Returns the moved IDs.
   */
  async moveItems(ids: readonly string[], targetVaultId: string): Promise<string[]> {
    const target = this.vaults.get(targetVaultId);
    if (!target) throw new Error("unknown vault");
    if (!target.orgId) this.ensurePersonalVaultsAllowed();
    const pending = [...new Set(ids)].filter((id) => {
      const item = this.items.get(id);
      if (!item) throw new Error("unknown item");
      return item.vaultId !== targetVaultId;
    });
    for (let i = 0; i < pending.length; i += 100) {
      const batch = pending.slice(i, i + 100);
      try {
        await this.moveBatch(batch, targetVaultId);
      } catch (error) {
        if (!(error instanceof ApiError && error.code === "conflict")) throw error;
        await this.sync();
        await this.moveBatch(batch, targetVaultId);
      }
    }
    if (pending.length > 0) await this.sync();
    return pending;
  }

  private async moveBatch(ids: string[], targetVaultId: string) {
    const keyring = this.requireKeyring();
    const keyEpoch = this.vaults.get(targetVaultId)?.keyEpoch ?? 0;
    const items: MoveItemUpload[] = [];
    for (const id of ids) {
      const item = this.items.get(id);
      if (!item) throw new Error("unknown item");
      const { versions: history } = await this.api.itemVersions(id);
      const json = serializeItemData(item.data);
      const versions = [
        {
          revision: item.revision,
          encryptedData: keyring.encryptItemAt(targetVaultId, keyEpoch, id, item.revision, json),
        },
      ];
      for (const version of history) {
        if (version.revision >= item.revision) continue;
        let plain: string;
        try {
          plain = keyring.decryptItemAt(item.vaultId, version.keyEpoch, id, version.revision, version.encryptedData);
        } catch {
          continue;
        }
        versions.push({
          revision: version.revision,
          encryptedData: keyring.encryptItemAt(targetVaultId, keyEpoch, id, version.revision, plain),
        });
      }
      items.push({
        id,
        revision: item.revision + 1,
        encryptedData: keyring.encryptItemAt(targetVaultId, keyEpoch, id, item.revision + 1, json),
        versions,
      });
    }
    await this.api.comfort.moveItems({ targetVaultId, keyEpoch, items });
  }

  /**
   * Encrypts a file here and attaches it to an item. `onProgress` reports
   * encrypted bytes (0..1) before the upload. Fails with `ApiError` codes
   * `file_too_large` or `quota_exceeded` when the server's limits do not
   * allow it.
   */
  async addAttachment(
    itemId: string,
    file: { name: string; type: string; data: Uint8Array },
    onProgress?: (fraction: number) => void,
  ): Promise<Attachment> {
    const name = file.name.trim();
    if (!name || name.length > 255) throw new Error("a file name has 1 to 255 characters");
    if (!this.items.get(itemId)) throw new Error("unknown item");
    const id = this.core.newId();
    const key = this.core.generateFileKey();
    const blob = this.encryptFile(key, id, file.data, onProgress);
    await this.api.comfort.uploadAttachment(id, itemId, blob);
    const attachment: Attachment = {
      id,
      name,
      type: file.type || "application/octet-stream",
      size: file.data.length,
      key,
      createdAt: Date.now(),
    };
    try {
      await this.changeAttachments(itemId, (list) => [...list, attachment]);
    } catch (error) {
      await this.api.comfort.deleteAttachment(id).catch(() => undefined);
      throw error;
    }
    return attachment;
  }

  private encryptFile(key: string, id: string, data: Uint8Array, onProgress?: (fraction: number) => void) {
    const encryptor = new this.core.FileEncryptor(key, id);
    try {
      const size = encryptor.chunkSize;
      const out = new Uint8Array(this.core.encryptedFileLength(data.length));
      const header = encryptor.header();
      out.set(header, 0);
      let offset = header.length;
      let position = 0;
      do {
        const end = Math.min(position + size, data.length);
        const last = end >= data.length;
        const chunk = encryptor.encryptChunk(data.subarray(position, end), last);
        out.set(chunk, offset);
        offset += chunk.length;
        position = end;
        onProgress?.(data.length === 0 ? 1 : position / data.length);
      } while (position < data.length);
      return out.subarray(0, offset);
    } finally {
      encryptor.free();
    }
  }

  /** Downloads and decrypts an attachment. */
  async attachmentData(itemId: string, attachmentId: string): Promise<Uint8Array> {
    const attachment = this.items.get(itemId)?.data.attachments?.find((a) => a.id === attachmentId);
    if (!attachment) throw new Error("unknown attachment");
    const blob = await this.api.comfort.downloadAttachment(attachmentId);
    const headerLength = this.core.fileHeaderLength();
    const decryptor = new this.core.FileDecryptor(attachment.key, attachmentId, blob.subarray(0, headerLength));
    try {
      const out = new Uint8Array(attachment.size);
      const step = decryptor.encryptedChunkSize;
      let offset = 0;
      let position = headerLength;
      for (;;) {
        const last = blob.length - position <= step;
        const chunk = decryptor.decryptChunk(blob.subarray(position, Math.min(position + step, blob.length)), last);
        if (offset + chunk.length > out.length) throw new Error("the attachment is larger than expected");
        out.set(chunk, offset);
        offset += chunk.length;
        position += step;
        if (last) break;
      }
      decryptor.finish();
      if (offset !== attachment.size) throw new Error("the attachment does not have the expected size");
      return out;
    } finally {
      decryptor.free();
    }
  }

  /** Removes an attachment from the item and deletes the file on the server. */
  async removeAttachment(itemId: string, attachmentId: string): Promise<void> {
    await this.changeAttachments(itemId, (list) => list.filter((a) => a.id !== attachmentId));
    await this.api.comfort.deleteAttachment(attachmentId).catch((error: unknown) => {
      if (!(error instanceof ApiError && error.status === 404)) throw error;
    });
  }

  private async changeAttachments(itemId: string, change: (list: Attachment[]) => Attachment[]) {
    for (let attempt = 0; ; attempt++) {
      const item = this.items.get(itemId);
      if (!item) throw new Error("unknown item");
      const list = change(item.data.attachments ?? []);
      const { attachments: _old, ...rest } = item.data;
      const data: ItemData = list.length > 0 ? { ...rest, attachments: list } : rest;
      try {
        await this.writeItem(item.vaultId, itemId, item.revision + 1, data);
        return;
      } catch (error) {
        if (!(error instanceof ConflictError) || attempt > 0) throw error;
      }
    }
  }

  /** Storage limits and use for attachments. */
  attachmentUsage(): Promise<AttachmentUsageResponse> {
    return this.api.comfort.attachmentUsage();
  }

  /**
   * Creates a share link for people without an account. The snapshot is
   * encrypted here; the key is only in the link's fragment, which never
   * reaches the server. `vaultId` names where the item comes from so its
   * organization's policy applies. Returns the link.
   */
  async createShareLink(options: {
    snapshot: ShareSnapshot;
    label: string;
    expiresAt: number;
    maxViews: number;
    passphrase?: string;
    vaultId?: string;
    linkBase: string;
  }): Promise<{ id: string; url: string }> {
    const keyring = this.requireKeyring();
    const id = this.core.newId();
    const passphrase = options.passphrase?.length ? options.passphrase : undefined;
    const link = JSON.parse(this.core.shareLinkCreate(id, JSON.stringify(options.snapshot), passphrase)) as {
      key: string;
      blob: string;
      authHash: string;
      salt: string | null;
    };
    await this.api.comfort.createShareLink({
      id,
      encryptedLabel: keyring.encryptLocal(SHARE_LINK_PURPOSE, JSON.stringify({ label: options.label })),
      blob: link.blob,
      authHash: link.authHash,
      salt: link.salt,
      expiresAt: options.expiresAt,
      maxViews: options.maxViews,
      ...(options.vaultId ? { vaultId: options.vaultId } : {}),
    });
    return { id, url: shareLinkUrl(options.linkBase, id, link.key) };
  }

  /** The account's share links that have not expired, with their labels. */
  async shareLinks(): Promise<ShareLink[]> {
    const keyring = this.requireKeyring();
    const { links } = await this.api.comfort.shareLinks();
    return links.map((link) => {
      let label = "";
      try {
        label =
          (JSON.parse(keyring.decryptLocal(SHARE_LINK_PURPOSE, link.encryptedLabel)) as { label?: string }).label ?? "";
      } catch {
        label = "";
      }
      return { ...link, label };
    });
  }

  /** Ends a share link at once. */
  deleteShareLink(id: string): Promise<void> {
    return this.api.comfort.deleteShareLink(id);
  }

  /** Access requests for vaults this account manages, and its own. */
  accessRequests(): Promise<{ incoming: AccessRequestRecord[]; outgoing: AccessRequestRecord[] }> {
    return this.api.comfort.accessRequests();
  }

  /** Whether this account can open a vault it has a link to, and its request. */
  vaultAccessRequest(vaultId: string) {
    return this.api.comfort.vaultAccessRequest(vaultId);
  }

  /** Asks the vault's managers for access. */
  requestVaultAccess(vaultId: string, role: VaultRole): Promise<AccessRequestRecord> {
    return this.api.comfort.requestVaultAccess(vaultId, role);
  }

  /**
   * Approves a request: shares the vault with the requester (a signed
   * manifest version, after checking their key) and marks it approved.
   */
  async approveAccessRequest(request: AccessRequestRecord, role: VaultRole = request.role): Promise<void> {
    await this.shareVault(request.vaultId, "account", request.accountId, role);
    await this.api.comfort.approveAccessRequest(request.id);
  }

  denyAccessRequest(id: string): Promise<void> {
    return this.api.comfort.denyAccessRequest(id);
  }

  cancelAccessRequest(id: string): Promise<void> {
    return this.api.comfort.cancelAccessRequest(id);
  }
}
