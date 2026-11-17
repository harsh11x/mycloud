import { describe, it, expect } from "vitest";
import { hashPassword, verifyPassword, validatePasswordPolicy } from "./password";
import { hashToken, newToken } from "./session";

describe("password hashing", () => {
  it("hashes with Argon2id and verifies the correct password only", async () => {
    const hash = await hashPassword("correct horse battery");
    expect(hash.startsWith("$argon2id$")).toBe(true);
    expect(await verifyPassword(hash, "correct horse battery")).toBe(true);
    expect(await verifyPassword(hash, "wrong password here")).toBe(false);
  });

  it("returns false for a malformed hash instead of throwing", async () => {
    expect(await verifyPassword("not-a-hash", "anything at all")).toBe(false);
  });

  it("enforces a 12 character minimum", () => {
    expect(validatePasswordPolicy("short")).not.toBeNull();
    expect(validatePasswordPolicy("long enough password")).toBeNull();
  });
});

describe("session tokens", () => {
  it("generates unique high-entropy tokens and stores only their hash", () => {
    const a = newToken();
    const b = newToken();
    expect(a).not.toBe(b);
    expect(a.length).toBeGreaterThanOrEqual(43);
    expect(hashToken(a)).toMatch(/^[0-9a-f]{64}$/);
    expect(hashToken(a)).not.toContain(a);
  });
});
