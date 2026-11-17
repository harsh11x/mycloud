import { eq } from "drizzle-orm";
import { getDb, type Db } from "@/db/client";
import { users } from "@/db/schema";
import { consumeRateLimit } from "../security/rate-limit";
import { hashPassword, verifyPassword } from "./password";
import { revokeAllUserSessions } from "./session";

export type ChangePasswordResult =
  | { ok: true }
  | { ok: false; reason: "rate_limited" | "invalid_current" | "not_found" };

/**
 * Changes a signed-in user's password after verifying the current one.
 * Revokes every session for the account, including the caller's, so the
 * caller must sign in again. Rate-limited per user.
 */
export async function changePassword(
  userId: string,
  currentPassword: string,
  newPassword: string,
  db: Db = getDb(),
): Promise<ChangePasswordResult> {
  const allowed = await consumeRateLimit(`password-change:${userId}`, 5, 15 * 60 * 1000, db);
  if (!allowed) return { ok: false, reason: "rate_limited" };

  const [user] = await db.select().from(users).where(eq(users.id, userId)).limit(1);
  if (!user) return { ok: false, reason: "not_found" };

  const valid = await verifyPassword(user.passwordHash, currentPassword);
  if (!valid) return { ok: false, reason: "invalid_current" };

  const passwordHash = await hashPassword(newPassword);
  await db
    .update(users)
    .set({ passwordHash, failedLogins: 0, lockedUntil: null, updatedAt: new Date() })
    .where(eq(users.id, userId));

  await revokeAllUserSessions(userId, db);
  return { ok: true };
}
