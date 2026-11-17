import { describe, expect, it } from "vitest";
import { generateTotpSecret, totpCode, verifyTotp } from "./totp";

// RFC 6238 Appendix B SHA-1 reference secret "12345678901234567890" in base32.
const RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

describe("TOTP", () => {
  it("matches the RFC 6238 SHA-1 reference codes", () => {
    expect(totpCode(RFC_SECRET, 59 / 30 | 0)).toBe("287082");
    expect(totpCode(RFC_SECRET, 1111111109 / 30 | 0)).toBe("081804");
    expect(totpCode(RFC_SECRET, 1234567890 / 30 | 0)).toBe("005924");
  });

  it("accepts the current step and one step of drift, rejects two steps away", () => {
    const now = 1234567890 * 1000;
    const c = Math.floor(now / 1000 / 30);
    expect(verifyTotp(RFC_SECRET, totpCode(RFC_SECRET, c), now)).toBe(c);
    expect(verifyTotp(RFC_SECRET, totpCode(RFC_SECRET, c - 1), now)).toBe(c - 1);
    expect(verifyTotp(RFC_SECRET, totpCode(RFC_SECRET, c - 2), now)).toBeNull();
  });

  it("refuses a code whose counter was already accepted (replay)", () => {
    const now = 1234567890 * 1000;
    const c = Math.floor(now / 1000 / 30);
    expect(verifyTotp(RFC_SECRET, totpCode(RFC_SECRET, c), now, c)).toBeNull();
  });

  it("rejects malformed codes", () => {
    expect(verifyTotp(RFC_SECRET, "12345", Date.now())).toBeNull();
    expect(verifyTotp(RFC_SECRET, "abcdef", Date.now())).toBeNull();
  });

  it("generates base32 secrets of usable length", () => {
    const s = generateTotpSecret();
    expect(s).toMatch(/^[A-Z2-7]+$/);
    expect(s.length).toBe(32);
  });
});
