/**
 * Types and errors of account recovery, emergency access and adding a
 * device by code. The operations are methods of `PassboxClient`;
 * the cryptography is in the Rust core. See docs/architecture/recovery.md.
 */
import type { EmergencyGrantInfo, OrgRecoveryRequest } from "@passbox/api-client";
import type { Item } from "./client";

/**
 * What this device knows about the account's recovery options, so the
 * "Forgot master password?" dialog can offer them while locked. Public
 * data, refreshed after every unlock.
 */
export interface RecoveryOptions {
  accountId: string;
  /** The account has a personal recovery code. */
  recoveryCode: boolean;
  /** Organizations that can recover the account (the member opted in). */
  orgs: { orgId: string; name?: string | undefined }[];
  /** People this account is an emergency contact for, or who trust it. */
  emergencyContacts: number;
  updatedAt: number;
}

/** The first step of a recovery by code. */
export interface CodeRecoveryStart {
  accountId: string;
  email: string;
  /** Set when the account uses two-factor sign-in: call `completeRecoveryTwoFactor`. */
  twoFactorMethods?: ("totp" | "recovery")[];
}

/** New credentials after a recovery, for the new Emergency Kit. */
export interface RecoveryResult {
  accountId: string;
  email: string;
  /** The new Secret Key; the old one no longer works. */
  secretKey: string;
  /** The new recovery code; an old one no longer works. */
  recoveryCode: string;
}

/** An organization recovery request this device sent, kept across reloads. */
export interface PendingOrgRecovery {
  requestId: string;
  requestToken: string;
  /** The ephemeral private key's seed (Base64url). Useless once the request expired. */
  seed: string;
  email: string;
  orgId?: string;
  /** Read it to the admin who approves; they compare it with theirs. */
  requestCode: string;
  createdAt: number;
  expiresAt: number;
}

export type OrgRecoveryRequestStatus = "pending" | "approved" | "denied" | "completed" | "cancelled" | "expired";

/** An organization's recovery setup as this account sees it (verified by the core). */
export interface OrgRecoveryInfo {
  orgId: string;
  /** An admin set up recovery and the key verified against the organization's roster. */
  available: boolean;
  /** Why `available` is false although the server has a key (verification failed). */
  problem?: string;
  keyVersion?: number;
  /** Fingerprint of the recovery key (8 groups of five digits). */
  fingerprint?: string;
  /** Verified admins who can approve requests. */
  admins: string[];
  /** This account holds the recovery key. */
  canApprove: boolean;
  /** This account opted in. */
  enrolled: boolean;
  enrolledAt?: number;
  /** For admins: members who opted in. */
  enrolledMembers?: string[];
  /** For admins who hold the key: open requests. */
  pendingRequests?: number;
}

/** A pending request with the code to compare with the member. */
export interface RecoveryRequest extends OrgRecoveryRequest {
  requestCode: string;
}

export type EmergencyContact = EmergencyGrantInfo;

/** The grantor's vaults, opened through released emergency access. Read only. */
export interface EmergencyVaults {
  grantorId: string;
  grantorEmail: string;
  vaults: { id: string; name: string }[];
  items: Item[];
  /** Items that could not be decrypted. */
  errors: string[];
}

/** A link opened on this (signed-in) device. */
export interface DeviceLinkStart {
  id: string;
  /** `XXXX-XXXX-XXXX-XXXX`; show it and put it into the QR code. */
  code: string;
  expiresAt: number;
}

export interface DeviceLinkState {
  status: "open" | "claimed" | "approved";
  expiresAt: number;
  /** The new device's name, once it entered the code. */
  deviceName?: string;
  ip?: string;
}

/** What a new device receives from the signed-in one. Never the master password. */
export interface LinkedAccount {
  email: string;
  accountId: string;
  secretKey: string;
}

/** A sign-in request of another device (`pbx login`) as the approving browser sees it. */
export interface CliLoginRequestInfo {
  id: string;
  /** Covered by the request's MAC: the name the requesting device registered. */
  deviceName: string;
  /** Where the request came from, as the server saw it. */
  ip: string;
  createdAt: number;
  expiresAt: number;
}

/** The ID and secret of a sign-in link (`#/cli-login/{id}#{secret}`). */
export interface CliLoginLink {
  id: string;
  secret: string;
}

/**
 * Reads a sign-in link from a location hash (`#/cli-login/{id}#{secret}`).
 * Only checks the shape; the secret is checked by the core.
 */
export function parseCliLoginLink(hash: string): CliLoginLink | undefined {
  const match = /^#?\/?cli-login\/([0-9a-z]{26})\/?#([A-Za-z0-9_-]{43})$/.exec(hash);
  if (!match?.[1] || !match[2]) return undefined;
  return { id: match[1], secret: match[2] };
}

/** The sign-in request expired, was cancelled or was already answered. */
export class CliLoginExpiredError extends Error {
  constructor() {
    super("This sign-in request expired or was already answered. Start it again on the other device.");
    this.name = "CliLoginExpiredError";
  }
}

/**
 * The request the server returned does not match the link: a different key or
 * device name. Nothing was sent. Either the link is wrong or the server is not
 * trustworthy.
 */
export class CliLoginVerificationError extends Error {
  constructor() {
    super("This sign-in request does not match the link. Nothing was sent.");
    this.name = "CliLoginVerificationError";
  }
}

/** The recovery code is incomplete or has a typo (checked on the device). */
export class InvalidRecoveryCodeError extends Error {
  constructor() {
    super("This is not a complete recovery code. Check it for typos.");
    this.name = "InvalidRecoveryCodeError";
  }
}

/** The recovery took too long or was already used; start again. */
export class RecoveryExpiredError extends Error {
  constructor() {
    super("The recovery expired. Start again.");
    this.name = "RecoveryExpiredError";
  }
}

/** The device code is malformed, expired or was used by another device. */
export class InvalidDeviceCodeError extends Error {
  constructor() {
    super("This code is not valid. Show a new code on your other device.");
    this.name = "InvalidDeviceCodeError";
  }
}

/** The recovered account key does not open the account's keys: the server sent something else. */
export class RecoveryVerificationError extends Error {
  constructor() {
    super("The recovered key could not be verified. Nothing was changed.");
    this.name = "RecoveryVerificationError";
  }
}

export const RECOVERY_OPTIONS_KEY = "passbox.recoveryOptions";
export const ORG_RECOVERY_KEY = "passbox.orgRecovery";
