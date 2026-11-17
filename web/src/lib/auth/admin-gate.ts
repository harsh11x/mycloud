import { resolveSession, SESSION_COOKIE } from "./session";

/** Re-authentication within this window is required for dangerous admin actions. */
export const REAUTH_WINDOW_MS = 5 * 60 * 1000;

export type AdminContext = {
  sessionId: string;
  userId: string;
  email: string;
  mfaVerifiedAt: Date;
};

/**
 * Admin access requires: a usable session, role admin, TOTP enabled on the account,
 * and a TOTP step completed in this session. A password-only session is never admin.
 */
export function assertAdmin(
  resolved: Awaited<ReturnType<typeof resolveSession>>,
  now: Date = new Date(),
): AdminContext | null {
  if (!resolved) return null;
  const { user } = resolved;
  if (user.role !== "admin" || !user.totpEnabled) return null;
  const verified = resolved.mfaVerifiedAt;
  if (!verified) return null;
  if (now.getTime() - verified.getTime() > SESSION_MFA_MAX_AGE_MS) return null;
  return {
    sessionId: resolved.sessionId,
    userId: user.id,
    email: user.email,
    mfaVerifiedAt: verified,
  };
}

/** How long a TOTP verification keeps an admin session elevated. */
export const SESSION_MFA_MAX_AGE_MS = 12 * 60 * 60 * 1000;

/** True when the session re-entered credentials within the re-auth window. */
export function isRecentlyReauthenticated(reauthAt: Date | null | undefined, now: Date = new Date()): boolean {
  return !!reauthAt && now.getTime() - reauthAt.getTime() <= REAUTH_WINDOW_MS;
}

export { SESSION_COOKIE };
