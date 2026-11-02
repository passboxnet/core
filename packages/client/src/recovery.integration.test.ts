/**
 * Recovery code, organization recovery, emergency access and adding a
 * device by code against a real server. Start one and set
 * PASSBOX_TEST_SERVER_URL (see client.integration.test.ts).
 */
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { ApiError, createClient } from "@passbox/api-client";
import * as core from "@passbox/core-wasm";
import { beforeAll, describe, expect, it } from "vitest";
import { InvalidCredentialsError, PassboxClient } from "./client";
import { FIELD, fieldValue, newItemData } from "./items";
import {
  CliLoginExpiredError,
  CliLoginVerificationError,
  InvalidDeviceCodeError,
  InvalidRecoveryCodeError,
  parseCliLoginLink,
} from "./recovery";
import { memoryStorage } from "./storage";

const serverUrl = process.env.PASSBOX_TEST_SERVER_URL;
const PASSWORD = "correct horse battery staple";
const NEW_PASSWORD = "violet ocean lantern 42 maple";

function newClient() {
  const storage = memoryStorage();
  let client: PassboxClient | undefined;
  const api = createClient({ baseUrl: serverUrl ?? "", getToken: () => client?.token });
  client = new PassboxClient({ core, api, storage, device: { name: "Test device", kind: "web" } });
  return client;
}

async function person(name: string) {
  const client = newClient();
  const email = `${name}-${core.newId()}@example.com`;
  const { accountId, secretKey } = await client.signUp(email, PASSWORD);
  return { client, email, id: accountId, secretKey };
}

function secret(title: string, password: string) {
  const data = newItemData("login", title);
  data.fields = data.fields.map((f) => (f.id === FIELD.password ? { ...f, value: password } : f));
  return data;
}

function personalVault(client: PassboxClient): string {
  return client.getSnapshot().vaults.find((v) => !v.orgId)?.id ?? "";
}

describe("recovery codes on the device", () => {
  beforeAll(async () => {
    const require = createRequire(import.meta.url);
    const wasmPath = require.resolve("@passbox/core-wasm").replace(/\.js$/, "_bg.wasm");
    await core.default({ module_or_path: await readFile(wasmPath) });
  });

  it("have a checksum and the R1 prefix", () => {
    const code = core.generateRecoveryCode();
    expect(code).toMatch(/^R1(-[0-9A-Z]{5}){11}$/);
    expect(core.isRecoveryCode(code.toLowerCase().replaceAll("-", " "))).toBe(true);
    const typo = `${code.slice(0, 10)}${code[10] === "A" ? "B" : "A"}${code.slice(11)}`;
    expect(core.isRecoveryCode(typo)).toBe(false);
    expect(core.isDeviceCode("ABCD-EFGH-JKMN-PQRS")).toBe(true);
    expect(core.isDeviceCode("ABCD-EFGH")).toBe(false);
  });
});

describe.skipIf(!serverUrl)("recovery against a server", () => {
  beforeAll(async () => {
    const require = createRequire(import.meta.url);
    const wasmPath = require.resolve("@passbox/core-wasm").replace(/\.js$/, "_bg.wasm");
    await core.default({ module_or_path: await readFile(wasmPath) });
  });

  it("recovers an account with the recovery code", { timeout: 120_000 }, async () => {
    const ada = await person("ada");
    const itemId = await ada.client.createItem(personalVault(ada.client), secret("Bank", "s3cret"));
    const code = await ada.client.createRecoveryCode();
    expect(core.isRecoveryCode(code)).toBe(true);
    expect((await ada.client.recoveryStatus()).recoveryCode).not.toBeNull();
    expect(ada.client.recoveryOptions?.recoveryCode).toBe(true);

    // A new device, without the master password or Secret Key.
    const device = newClient();
    await expect(device.startCodeRecovery(ada.email, "R1-ABC")).rejects.toBeInstanceOf(InvalidRecoveryCodeError);
    await expect(device.startCodeRecovery(ada.email, core.generateRecoveryCode())).rejects.toBeInstanceOf(
      InvalidCredentialsError,
    );
    const start = await device.startCodeRecovery(ada.email, code);
    expect(start).toEqual({ accountId: ada.id, email: ada.email });
    expect(device.recoveryReady).toBe(true);
    const result = await device.finishRecovery(NEW_PASSWORD);
    expect(result.secretKey).not.toBe(ada.secretKey);
    expect(result.recoveryCode).not.toBe(code);
    expect(device.getSnapshot().status).toBe("unlocked");
    const item = device.getSnapshot().items.find((i) => i.id === itemId);
    expect(item && fieldValue(item.data, FIELD.password)).toBe("s3cret");

    // The old device is signed out; the old Secret Key and code stop working.
    await expect(ada.client.sync()).rejects.toBeInstanceOf(ApiError);
    await expect(newClient().signIn(ada.email, PASSWORD, ada.secretKey)).rejects.toBeInstanceOf(
      InvalidCredentialsError,
    );
    await expect(newClient().startCodeRecovery(ada.email, code)).rejects.toBeInstanceOf(InvalidCredentialsError);
    const third = newClient();
    await third.signIn(ada.email, NEW_PASSWORD, result.secretKey);
    expect(third.getSnapshot().items.map((i) => i.id)).toContain(itemId);
    const kinds = (await third.activity()).map((e) => e.kind);
    expect(kinds).toContain("account_recovered_code");
  });

  it("recovers a member through the organization", { timeout: 180_000 }, async () => {
    const alice = await person("alice");
    const bob = await person("bob");
    const orgId = await alice.client.createTeam("Acme");
    const vaultId = await alice.client.createSharedVault(orgId, "Team");
    const invitation = await alice.client.invite(orgId, bob.email, "member");
    await bob.client.acceptInvitation(invitation.link);
    await alice.client.confirmMember(orgId, bob.id);
    await alice.client.shareVault(vaultId, "account", bob.id, "edit");
    await bob.client.sync();
    const shared = await alice.client.createItem(vaultId, secret("Shared", "team-secret"));

    // On by default: the organization has recovery and requires it; Bob's
    // client enrolls automatically once he is confirmed.
    const info = await bob.client.orgRecovery(orgId);
    expect(info).toMatchObject({ available: true, enrolled: false, canApprove: false, admins: [alice.id] });
    expect((await alice.client.orgRecovery(orgId)).canApprove).toBe(true);
    expect((await alice.client.orgRecovery(orgId)).enrolled).toBe(true);
    expect(await bob.client.enrollRequiredOrgRecovery()).toEqual([orgId]);
    expect((await bob.client.orgRecovery(orgId)).enrolled).toBe(true);
    expect(await bob.client.enrollRequiredOrgRecovery()).toEqual([]);
    expect(bob.client.recoveryOptions?.orgs.map((o) => o.orgId)).toEqual([orgId]);

    // Bob's new device asks; Alice compares the code and approves.
    const device = newClient();
    const pending = await device.requestOrgRecovery(bob.email, orgId);
    expect(pending.requestCode.split(" ")).toHaveLength(4);
    expect(device.pendingOrgRecovery?.requestId).toBe(pending.requestId);
    expect(await device.checkOrgRecovery()).toBe("pending");
    const [request] = await alice.client.recoveryRequests(orgId);
    expect(request?.requestCode).toBe(pending.requestCode);
    expect(request?.email).toBe(bob.email);
    await expect(bob.client.recoveryRequests(orgId)).rejects.toBeInstanceOf(ApiError);
    if (!request) throw new Error("no request");
    await alice.client.approveRecoveryRequest(orgId, request);
    expect(await device.checkOrgRecovery()).toBe("approved");
    const result = await device.finishRecovery(NEW_PASSWORD);
    expect(result.email).toBe(bob.email);
    expect(device.pendingOrgRecovery).toBeUndefined();
    await device.sync();
    const item = device.getSnapshot().items.find((i) => i.id === shared);
    expect(item && fieldValue(item.data, FIELD.password)).toBe("team-secret");
    await expect(bob.client.sync()).rejects.toBeInstanceOf(ApiError);

    // A declined request gives nothing.
    const other = newClient();
    await other.requestOrgRecovery(bob.email, orgId);
    const [second] = await alice.client.recoveryRequests(orgId);
    await alice.client.denyRecoveryRequest(orgId, second?.id ?? "");
    expect(await other.checkOrgRecovery()).toBe("denied");
    expect(other.recoveryReady).toBe(false);
  });

  it("gives an emergency contact read access after approval", { timeout: 120_000 }, async () => {
    const grantor = await person("grantor");
    const grantee = await person("grantee");
    const vaultId = personalVault(grantor.client);
    await grantor.client.createItem(vaultId, secret("Insurance", "policy-123"));
    const grantId = await grantor.client.addEmergencyContact(grantee.email, 3);
    const { received } = await grantee.client.emergencyContacts();
    expect(received[0]).toMatchObject({ id: grantId, status: "invited", waitDays: 3 });
    await grantee.client.acceptEmergencyInvitation(grantId);
    const fingerprint = await grantor.client.confirmEmergencyContact(grantId, [vaultId]);
    expect(fingerprint).toBe(grantee.client.ownFingerprint());
    expect(await grantor.client.resealEmergencyAccess()).toBe(0);

    await expect(grantee.client.openEmergencyAccess(grantId)).rejects.toBeInstanceOf(ApiError);
    await grantee.client.requestEmergencyAccess(grantId);
    const waiting = (await grantee.client.emergencyContacts()).received[0];
    expect(waiting?.released).toBe(false);
    expect((waiting?.releaseAt ?? 0) - (waiting?.requestedAt ?? 0)).toBe(3 * 24 * 60 * 60 * 1000);
    await expect(grantee.client.openEmergencyAccess(grantId)).rejects.toBeInstanceOf(ApiError);
    await grantor.client.approveEmergencyAccess(grantId);
    const opened = await grantee.client.openEmergencyAccess(grantId);
    expect(opened.vaults).toEqual([{ id: vaultId, name: "Private" }]);
    expect(opened.items.map((i) => fieldValue(i.data, FIELD.password))).toEqual(["policy-123"]);
    expect(opened.grantorEmail).toBe(grantor.email);

    await grantor.client.denyEmergencyAccess(grantId);
    await expect(grantee.client.openEmergencyAccess(grantId)).rejects.toBeInstanceOf(ApiError);
    await grantor.client.removeEmergencyContact(grantId);
    expect((await grantee.client.emergencyContacts()).received).toEqual([]);
  });

  it("adds a device with a code", { timeout: 120_000 }, async () => {
    const ada = await person("linker");
    const link = await ada.client.startDeviceLink();
    expect(link.code).toMatch(/^[0-9A-Z]{4}(-[0-9A-Z]{4}){3}$/);
    const device = newClient();
    await expect(device.claimDeviceLink("ABCD")).rejects.toBeInstanceOf(InvalidDeviceCodeError);
    await device.claimDeviceLink(link.code.toLowerCase());
    expect(await device.pollDeviceLink()).toBeUndefined();
    const state = await ada.client.deviceLinkStatus(link.id);
    expect(state).toMatchObject({ status: "claimed", deviceName: "Test device" });
    await ada.client.approveDeviceLink(link.id);
    const linked = await device.pollDeviceLink();
    expect(linked).toEqual({ email: ada.email, accountId: ada.id, secretKey: ada.secretKey });
    if (!linked) throw new Error("not linked");
    await device.signIn(linked.email, PASSWORD, linked.secretKey);
    expect(device.getSnapshot().status).toBe("unlocked");
    // The code works once.
    await expect(newClient().claimDeviceLink(link.code)).rejects.toBeInstanceOf(InvalidDeviceCodeError);
  });

  it("signs in pbx from the browser", { timeout: 120_000 }, async () => {
    const ada = await person("cli");
    const api = createClient({ baseUrl: serverUrl ?? "" });
    // The requesting device (what pbx login does, without a session).
    const request = new core.CliLoginRequest("pbx build-box");
    const { pollToken } = await api.cliLogins.create({
      id: request.id,
      ephemeralKey: request.publicKey,
      mac: request.mac,
      deviceName: request.deviceName,
    });
    expect((await api.cliLogins.poll(pollToken)).status).toBe("pending");
    const link = parseCliLoginLink(request.linkFragment);
    if (!link) throw new Error("no link");
    expect(link.id).toBe(request.id);

    // The browser checks the request against the link before showing it.
    const info = await ada.client.cliLoginRequest(link.id, link.secret);
    expect(info).toMatchObject({ id: request.id, deviceName: "pbx build-box" });
    const other = parseCliLoginLink(new core.CliLoginRequest("x").linkFragment);
    if (!other) throw new Error("no link");
    await expect(ada.client.cliLoginRequest(link.id, other.secret)).rejects.toBeInstanceOf(CliLoginVerificationError);
    await expect(ada.client.approveCliLogin(link.id, other.secret)).rejects.toBeInstanceOf(CliLoginVerificationError);
    await ada.client.approveCliLogin(link.id, link.secret);

    const answer = await api.cliLogins.poll(pollToken);
    expect(answer.status).toBe("approved");
    expect(JSON.parse(request.open(answer.sealedPayload ?? ""))).toEqual({
      email: ada.email,
      accountId: ada.id,
      secretKey: ada.secretKey,
    });
    expect((await api.cliLogins.poll(pollToken)).status).toBe("expired");
    await expect(ada.client.cliLoginRequest(link.id, link.secret)).rejects.toBeInstanceOf(CliLoginExpiredError);

    // Denied requests are answered once too.
    const denied = new core.CliLoginRequest("pbx");
    const created = await api.cliLogins.create({
      id: denied.id,
      ephemeralKey: denied.publicKey,
      mac: denied.mac,
      deviceName: denied.deviceName,
    });
    await ada.client.denyCliLogin(denied.id);
    expect((await api.cliLogins.poll(created.pollToken)).status).toBe("denied");
    expect((await api.cliLogins.poll(created.pollToken)).status).toBe("expired");
    await expect(ada.client.denyCliLogin(denied.id)).rejects.toBeInstanceOf(CliLoginExpiredError);
  });
});
