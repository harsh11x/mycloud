import { and, eq, isNull } from "drizzle-orm";
import { getDb, type Db } from "@/db/client";
import { sessions, users } from "@/db/schema";
import { generateTotpSecret, totpUri, verifyTotp } from "./totp";
import { consumeRateLimit } from "../security/rate-limit";

export const MFA_RATE_WINDOW_MS = 15 * 60 * 1000;
export const MFA_MAX_ATTEMPTS = 5;

/** Creates a pending TOTP secret. It is not active until confirmed with a valid code. */
export async function beginTotpEnrolment(userId: string, email: string, db: Db = getDb()) {
  const secret = generateTotpSecret();
  await db
    .update(users)
    .set({ totpSecret: secret, totpEnabled: false, totpLastCounter: -1, updatedAt: new Date() })
    .where(eq(users.id, userId));
  return { secret, uri: totpUri(secret, email) };
}

/**
 * Activates TOTP once the user proves they hold the secret. Returns false on a
 * bad code. Rate limited per user so the 6-digit space cannot be brute forced.
 */
export async function confirmTotpEnrolment(userId: string, code: string, db: Db = getDb()): Promise<boolean> {
  if (!(await consumeRateLimit(`mfa:${userId}`, MFA_MAX_ATTEMPTS, MFA_RATE_WINDOW_MS, db))) return false;
  const [user] = await db.select().from(users).where(eq(users.id, userId)).limit(1);
  if (!user?.totpSecret) return false;
  const counter = verifyTotp(user.totpSecret, code, Date.now(), user.totpLastCounter);
  if (counter === null) return false;
  await db
    .update(users)
    .set({ totpEnabled: true, totpLastCounter: counter, updatedAt: new Date() })
    .where(eq(users.id, userId));
  return true;
}

/**
 * Verifies a TOTP code at login or step-up. On success, stamps the session with the
 * time of MFA verification and records the counter so the same code cannot be reused.
 */
export async function verifySessionMfa(
  userId: string,
  sessionId: string,
  code: string,
  db: Db = getDb(),
): Promise<boolean> {
  if (!(await consumeRateLimit(`mfa:${userId}`, MFA_MAX_ATTEMPTS, MFA_RATE_WINDOW_MS, db))) return false;
  const [user] = await db.select().from(users).where(eq(users.id, userId)).limit(1);
  if (!user?.totpEnabled || !user.totpSecret) return false;
  const counter = verifyTotp(user.totpSecret, code, Date.now(), user.totpLastCounter);
  if (counter === null) return false;
  await db
    .update(users)
    .set({ totpLastCounter: counter, updatedAt: new Date() })
    .where(eq(users.id, userId));
  await db
    .update(sessions)
    .set({ mfaVerifiedAt: new Date() })
    .where(and(eq(sessions.id, sessionId), isNull(sessions.revokedAt)));
  return true;
}

/** Stamps a session with a fresh re-authentication time for dangerous actions. */
export async function markReauth(sessionId: string, db: Db = getDb()) {
  await db.update(sessions).set({ reauthAt: new Date() }).where(eq(sessions.id, sessionId));
}
