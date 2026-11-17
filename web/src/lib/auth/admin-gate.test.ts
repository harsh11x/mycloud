import { describe, expect, it } from "vitest";
import { assertAdmin, isRecentlyReauthenticated, REAUTH_WINDOW_MS, SESSION_MFA_MAX_AGE_MS } from "./admin-gate";

const now = new Date("2026-11-16T12:00:00Z");

function resolved(over: Partial<{ role: "user" | "admin"; totpEnabled: boolean; mfa: Date | null }>) {
  return {
    sessionId: "s1",
    mfaVerifiedAt: over.mfa === undefined ? now : over.mfa,
    reauthAt: null,
    user: {
      id: "u1",
      email: "a@example.com",
      role: over.role ?? "admin",
      status: "active" as const,
      totpEnabled: over.totpEnabled ?? true,
    },
  };
}

describe("assertAdmin", () => {
  it("grants access to an admin with TOTP enabled and a fresh MFA step", () => {
    expect(assertAdmin(resolved({}), now)?.userId).toBe("u1");
  });

  it("denies a password-only admin session (no MFA step in this session)", () => {
    expect(assertAdmin(resolved({ mfa: null }), now)).toBeNull();
  });

  it("denies a non-admin even with MFA", () => {
    expect(assertAdmin(resolved({ role: "user" }), now)).toBeNull();
  });

  it("denies an admin whose account has TOTP disabled", () => {
    expect(assertAdmin(resolved({ totpEnabled: false }), now)).toBeNull();
  });

  it("denies when the MFA step is older than the session elevation window", () => {
    const old = new Date(now.getTime() - SESSION_MFA_MAX_AGE_MS - 1000);
    expect(assertAdmin(resolved({ mfa: old }), now)).toBeNull();
  });

  it("denies when there is no session", () => {
    expect(assertAdmin(null, now)).toBeNull();
  });
});

describe("isRecentlyReauthenticated", () => {
  it("accepts re-auth inside the window and rejects it after", () => {
    expect(isRecentlyReauthenticated(new Date(now.getTime() - 1000), now)).toBe(true);
    expect(isRecentlyReauthenticated(new Date(now.getTime() - REAUTH_WINDOW_MS - 1), now)).toBe(false);
    expect(isRecentlyReauthenticated(null, now)).toBe(false);
  });
});
