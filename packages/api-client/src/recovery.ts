/**
 * Account recovery, emergency access and adding devices by code.
 * Request bodies with keys are built by `@passbox/core-wasm`; see
 * docs/architecture/recovery.md and docs/api/openapi.yaml.
 */
import type { AccountKeys, ClientKind, KdfParams, LoginFinishResponse } from "./index";

export interface RecoveryStatus {
  /** `null` without a recovery code. */
  recoveryCode: { createdAt: number } | null;
  /** Organizations this account escrowed its key with. */
  orgEscrows: { orgId: string; keyVersion: number; createdAt: number }[];
}

/** A proven recovery: the token for `completeStart`/`completeFinish` (15 minutes, single use). */
export interface RecoveryGrant {
  recoveryToken: string;
  accountId: string;
  email: string;
  expiresAt: number;
  method: "code" | "org";
  /** Set while a recovery by code still needs the account's second factor. */
  twoFactorMethods?: ("totp" | "recovery")[];
  /** The account key wrapped with the recovery code. */
  wrappedAccountKey?: string;
  /** The account's key pairs; the recovered account key must open them. */
  accountKeys?: AccountKeys;
}

export interface OrgRecoveryKeyRecord {
  keyVersion: number;
  bundle: string;
  bundleSignature: string;
  grants: { accountId: string; keyVersion: number; grant: string; grantSignature: string; sealedKey?: string }[];
}

export interface OrgRecoveryState {
  key: OrgRecoveryKeyRecord | null;
  escrow: { keyVersion: number; createdAt: number } | null;
  /** Admins only: members who opted in. */
  enrolled?: string[];
  /** Admins who hold the key: open requests. */
  pendingRequests?: number;
}

export interface OrgRecoveryRequest {
  id: string;
  orgId: string;
  accountId: string;
  email: string;
  deviceName: string;
  ip: string;
  createdAt: number;
  expiresAt: number;
  ephemeralKey: string;
  keyVersion: number;
  escrow: string;
  escrowSignature: string;
  sealedKey: string;
}

export interface OrgRecoveryRequestCreated {
  requestId: string;
  requestToken: string;
  expiresAt: number;
}

export interface OrgRecoveryStatus {
  status: "pending" | "approved" | "denied" | "completed" | "cancelled" | "expired";
  expiresAt: number;
  approved?: {
    requestId: string;
    accountId: string;
    approval: string;
    approvalSignature: string;
    sealedKey: string;
    approverBundle: string;
    approverBundleSignature: string;
  };
  recovery?: RecoveryGrant;
}

export interface EmergencyGrantInfo {
  id: string;
  grantorId: string;
  grantorEmail: string;
  granteeId: string | null;
  granteeEmail: string;
  scope: "vaults";
  waitDays: number;
  /** `invited` (by email), `accepted` (waiting for the grantor to confirm) or `confirmed`. */
  status: "invited" | "accepted" | "confirmed";
  vaultIds: string[];
  version: number;
  grant?: string;
  grantSignature?: string;
  requestedAt: number;
  approvedAt: number;
  deniedAt: number;
  accessedAt: number;
  /** When access is (or was) released for the current request; 0 without one. */
  releaseAt: number;
  released: boolean;
  createdAt: number;
}

export interface EmergencyAccessData {
  grantorId: string;
  grant: string;
  grantSignature: string;
  sealedKeys: string;
  vaults: { id: string; encryptedMeta: string; revision: number; keyEpoch: number }[];
  items: {
    id: string;
    vaultId: string;
    revision: number;
    encryptedData: string;
    updatedAt: number;
    keyEpoch: number;
  }[];
}

export interface DeviceLinkInfo {
  status: "open" | "claimed" | "approved";
  expiresAt: number;
  ephemeralKey?: string;
  mac?: string;
  deviceName?: string;
  ip?: string;
  claimedAt: number;
}

/** A pending sign-in request of another device (`pbx login`), for the approver. */
export interface CliLoginInfo {
  id: string;
  deviceName: string;
  ip: string;
  createdAt: number;
  expiresAt: number;
  ephemeralKey: string;
  mac: string;
}

export interface RecoveryApi {
  status(): Promise<RecoveryStatus>;
  /** Needs a login in the last 10 minutes. */
  codeStart(req: { registrationRequest: string }): Promise<{ registrationResponse: string }>;
  codeFinish(req: { registrationUpload: string; wrappedAccountKey: string }): Promise<void>;
  codeDelete(): Promise<void>;
  loginStart(req: { email: string; credentialRequest: string }): Promise<{
    loginId: string;
    credentialResponse: string;
  }>;
  loginFinish(req: {
    loginId: string;
    credentialFinalization: string;
    deviceName?: string;
    clientKind?: ClientKind;
  }): Promise<RecoveryGrant>;
  twoFactor(req: { recoveryToken: string; method: "totp" | "recovery"; code: string }): Promise<RecoveryGrant>;
  completeStart(req: {
    recoveryToken: string;
    registrationRequest: string;
    recoveryRegistrationRequest?: string;
  }): Promise<{ registrationResponse: string; recoveryRegistrationResponse?: string }>;
  completeFinish(req: {
    recoveryToken: string;
    registrationUpload: string;
    kdfSalt: string;
    kdfParams: KdfParams;
    encryptedAccountKey: string;
    recoveryCode?: { registrationUpload: string; wrappedAccountKey: string };
  }): Promise<LoginFinishResponse>;
  orgRequest(req: {
    email: string;
    orgId?: string;
    ephemeralKey: string;
    deviceName?: string;
  }): Promise<OrgRecoveryRequestCreated>;
  orgStatus(req: { requestId: string; requestToken: string; clientKind?: ClientKind }): Promise<OrgRecoveryStatus>;
  orgCancel(req: { requestId: string; requestToken: string }): Promise<void>;
  orgState(orgId: string): Promise<OrgRecoveryState>;
  createOrgKey(orgId: string, body: unknown): Promise<void>;
  addOrgGrant(orgId: string, body: unknown): Promise<void>;
  putEscrow(orgId: string, body: unknown): Promise<void>;
  deleteEscrow(orgId: string): Promise<void>;
  /** Turns recovery off for the whole organization (admins). */
  turnOff(orgId: string): Promise<void>;
  orgRequests(orgId: string): Promise<OrgRecoveryRequest[]>;
  approveRequest(orgId: string, requestId: string, body: unknown): Promise<void>;
  denyRequest(orgId: string, requestId: string): Promise<void>;
}

export interface EmergencyApi {
  list(): Promise<{ granted: EmergencyGrantInfo[]; received: EmergencyGrantInfo[] }>;
  create(req: { granteeEmail: string; waitDays: number; scope?: "vaults" }): Promise<{ id: string }>;
  remove(id: string): Promise<void>;
  accept(id: string): Promise<void>;
  confirm(id: string, body: unknown): Promise<void>;
  request(id: string): Promise<void>;
  approve(id: string): Promise<void>;
  deny(id: string): Promise<void>;
  access(id: string): Promise<EmergencyAccessData>;
}

export interface DeviceLinkApi {
  create(): Promise<{ id: string; shortId: string; expiresAt: number }>;
  get(id: string): Promise<DeviceLinkInfo>;
  approve(id: string, sealedPayload: string): Promise<void>;
  cancel(id: string): Promise<void>;
  claim(req: {
    shortId: string;
    ephemeralKey: string;
    mac: string;
    deviceName?: string;
  }): Promise<{ claimToken: string; expiresAt: number }>;
  poll(claimToken: string): Promise<{ status: "claimed" | "approved"; sealedPayload?: string }>;
}

/** Signing in a device without a session (`pbx login`) from a signed-in browser. */
export interface CliLoginApi {
  /** Approver (signed in): the pending request. */
  get(id: string): Promise<CliLoginInfo>;
  approve(id: string, sealedPayload: string): Promise<void>;
  deny(id: string): Promise<void>;
  /** Requesting device (no session). */
  create(req: {
    id: string;
    ephemeralKey: string;
    mac: string;
    deviceName: string;
  }): Promise<{ pollToken: string; expiresAt: number }>;
  poll(pollToken: string): Promise<{
    status: "pending" | "approved" | "denied" | "expired";
    sealedPayload?: string;
    approvedBy?: string;
  }>;
  cancel(pollToken: string): Promise<void>;
}

type Call = <T>(method: string, path: string, body?: unknown) => Promise<T>;

export function recoveryApi(call: Call): RecoveryApi {
  const e = encodeURIComponent;
  const org = (id: string) => `/api/v1/orgs/${e(id)}/recovery`;
  return {
    status: () => call("GET", "/api/v1/account/recovery"),
    codeStart: (req) => call("POST", "/api/v1/account/recovery-code/start", req),
    codeFinish: (req) => call("POST", "/api/v1/account/recovery-code", req),
    codeDelete: () => call("DELETE", "/api/v1/account/recovery-code"),
    loginStart: (req) => call("POST", "/api/v1/recovery/code/start", req),
    loginFinish: (req) => call("POST", "/api/v1/recovery/code/finish", req),
    twoFactor: (req) => call("POST", "/api/v1/recovery/two-factor", req),
    completeStart: (req) => call("POST", "/api/v1/recovery/complete/start", req),
    completeFinish: (req) => call("POST", "/api/v1/recovery/complete/finish", req),
    orgRequest: (req) => call("POST", "/api/v1/recovery/org/request", req),
    orgStatus: (req) => call("POST", "/api/v1/recovery/org/status", req),
    orgCancel: (req) => call("POST", "/api/v1/recovery/org/cancel", req),
    orgState: (orgId) => call("GET", org(orgId)),
    createOrgKey: (orgId, body) => call("POST", `${org(orgId)}/keys`, body),
    addOrgGrant: (orgId, body) => call("POST", `${org(orgId)}/grants`, body),
    putEscrow: (orgId, body) => call("PUT", `${org(orgId)}/escrow`, body),
    deleteEscrow: (orgId) => call("DELETE", `${org(orgId)}/escrow`),
    turnOff: (orgId) => call("DELETE", org(orgId)),
    orgRequests: (orgId) => call("GET", `${org(orgId)}/requests`),
    approveRequest: (orgId, requestId, body) => call("POST", `${org(orgId)}/requests/${e(requestId)}/approve`, body),
    denyRequest: (orgId, requestId) => call("POST", `${org(orgId)}/requests/${e(requestId)}/deny`, {}),
  };
}

export function emergencyApi(call: Call): EmergencyApi {
  const grant = (id: string) => `/api/v1/emergency/grants/${encodeURIComponent(id)}`;
  return {
    list: () => call("GET", "/api/v1/emergency"),
    create: (req) => call("POST", "/api/v1/emergency/grants", req),
    remove: (id) => call("DELETE", grant(id)),
    accept: (id) => call("POST", `${grant(id)}/accept`, {}),
    confirm: (id, body) => call("POST", `${grant(id)}/confirm`, body),
    request: (id) => call("POST", `${grant(id)}/request`, {}),
    approve: (id) => call("POST", `${grant(id)}/approve`, {}),
    deny: (id) => call("POST", `${grant(id)}/deny`, {}),
    access: (id) => call("GET", `${grant(id)}/access`),
  };
}

export function deviceLinkApi(call: Call): DeviceLinkApi {
  const link = (id: string) => `/api/v1/device-links/${encodeURIComponent(id)}`;
  return {
    create: () => call("POST", "/api/v1/device-links", {}),
    get: (id) => call("GET", link(id)),
    approve: (id, sealedPayload) => call("POST", `${link(id)}/approve`, { sealedPayload }),
    cancel: (id) => call("DELETE", link(id)),
    claim: (req) => call("POST", "/api/v1/device-links/claim", req),
    poll: (claimToken) => call("POST", "/api/v1/device-links/poll", { claimToken }),
  };
}

export function cliLoginApi(call: Call): CliLoginApi {
  const request = (id: string) => `/api/v1/cli-logins/${encodeURIComponent(id)}`;
  return {
    get: (id) => call("GET", request(id)),
    approve: (id, sealedPayload) => call("POST", `${request(id)}/approve`, { sealedPayload }),
    deny: (id) => call("POST", `${request(id)}/deny`, {}),
    create: (req) => call("POST", "/api/v1/cli-logins", req),
    poll: (pollToken) => call("POST", "/api/v1/cli-logins/poll", { pollToken }),
    cancel: (pollToken) => call("POST", "/api/v1/cli-logins/cancel", { pollToken }),
  };
}
