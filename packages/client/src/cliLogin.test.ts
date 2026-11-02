import { describe, expect, it } from "vitest";
import { parseCliLoginLink } from "./recovery";

const ID = "0123456789abcdefghjkmnpqrs";
const SECRET = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-abcde";

describe("parseCliLoginLink", () => {
  it("reads the ID and the secret of a pbx sign-in link", () => {
    expect(parseCliLoginLink(`#/cli-login/${ID}#${SECRET}`)).toEqual({ id: ID, secret: SECRET });
    expect(parseCliLoginLink(`cli-login/${ID}#${SECRET}`)).toEqual({ id: ID, secret: SECRET });
  });

  it("rejects incomplete and malformed links", () => {
    for (const hash of [
      `#/cli-login/${ID}`,
      `#/cli-login/${ID}#`,
      `#/cli-login/${ID}#${SECRET}x`,
      `#/cli-login/${ID.toUpperCase()}#${SECRET}`,
      `#/items#${SECRET}`,
      "",
    ]) {
      expect(parseCliLoginLink(hash)).toBeUndefined();
    }
  });
});
