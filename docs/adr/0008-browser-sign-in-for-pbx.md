# ADR 0008: Signing in pbx through the browser

- Status: Accepted

## Context

`pbx signin` needed the server URL, the email, the Secret Key (typed from the Emergency Kit) and the master password. Developer tools such as npm, GitHub CLI or Vercel sign in by opening a browser where the user is already signed in. Passbox already had a way to hand the email and Secret Key to a new device without typing them: the device code ("Adding a device with a code", [recovery.md](../architecture/recovery.md#adding-a-device-with-a-code)). There the signed-in device starts and shows a code. A terminal is better served the other way round: it starts and prints a link.

## Decision

- **The device without a session starts.** `pbx login` registers a request (ID, ephemeral X-Wing public key, device name, MAC) without a session and prints `<web vault>/#/cli-login/{id}#{secret}`. The signed-in web vault approves or denies; `pbx` receives the sealed email, account ID and Secret Key once and asks for the master password, which is never transferred.
- **The same cryptography as device codes, with its own labels.** `device_link::CliLoginRequest` and `CliLoginApproval` reuse the HKDF/HMAC construction, the X-Wing seal and the payload of device codes. The MAC key (`passbox/v1/cli-login`), the MAC input (`passbox/v1/cli-login-request`, which also covers the device name) and the seal context (`passbox/v1/seal-context/cli-login`) are new, so nothing verifies across the two directions. The secret is 256 bits because it is never typed.
- **The secret lives only in the URL fragment**, which browsers do not send. The web vault removes it from the address bar on load.
- **The approval page is built against phishing**: device name, IP and time are prominent, the page says that a new device gets full access with the master password, and Approve needs an explicit confirmation. Requests expire after 10 minutes and are answered once.
- **Headless stays explicit.** Without a terminal or with `CI` set, `pbx` never prompts or opens a browser and points to service accounts.

## Consequences

- A new unauthenticated endpoint family (`/api/v1/cli-logins`) with its own table and rate limits in passboxnet/server.
- The web vault gets a route that works signed out (sign in first, then return).
- Someone who tricks a user into approving their link receives the user's Secret Key (not the master password). The approval page, the confirmation and the activity log are the mitigations; the threat analysis is in [recovery.md](../architecture/recovery.md#threat-analysis).
- The mobile and desktop apps cannot approve yet; the Rust client has the approving side for when they do.
