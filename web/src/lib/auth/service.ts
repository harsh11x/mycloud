import { eq } from "drizzle-orm";
import { getDb, type Db } from "@/db/client";
import { users } from "@/db/schema";
import { hashPassword, verifyPassword } from "./password";
import { createSession } from "./session";
import { consumeRateLimit } from "../security/rate-limit";

export const MAX_FAILED_LOGINS = 5;
export const LOCKOUT_MS = 15 * 60 * 1000;

// A valid Argon2id hash of a random value, verified against when the email is
// unknown so response timing does not reveal which accounts exist.
let dummyHash: string | undefined;
async function getDummyHash() {
  dummyHash ??= await hashPassword(crypto.randomUUID() + crypto.randomUUID());
  return dummyHash;
}

export type LoginResult =
  | { ok: true; token: string; expiresAt: Date; userId: string }
  | { ok: false; reason: "invalid" | "locked" | "rate_limited" | "blocked" };

/** Checks credentials with per-account lockout and a per-IP+email rate limit. */
export async function login(
  email: string,
  password: string,
  meta: { ip: string; userAgent?: string },
  db: Db = getDb(),
): Promise<LoginResult> {
  const allowed = await consumeRateLimit(`login:${meta.ip}:${email}`, 10, 15 * 60 * 1000, db);
  if (!allowed) return { ok: false, reason: "rate_limited" };

  const [user] = await db.select().from(users).where(eq(users.email, email)).limit(1);

  if (!user) {
    await verifyPassword(await getDummyHash(), password);
    return { ok: false, reason: "invalid" };
  }

  if (user.lockedUntil && user.lockedUntil.getTime() > Date.now()) {
    await verifyPassword(await getDummyHash(), password);
    return { ok: false, reason: "locked" };
  }

  const valid = await verifyPassword(user.passwordHash, password);
  if (!valid) {
    const failed = user.failedLogins + 1;
    await db
      .update(users)
      .set({
        failedLogins: failed,
        lockedUntil: failed >= MAX_FAILED_LOGINS ? new Date(Date.now() + LOCKOUT_MS) : null,
        updatedAt: new Date(),
      })
      .where(eq(users.id, user.id));
    return { ok: false, reason: "invalid" };
  }

  if (user.status !== "active") return { ok: false, reason: "blocked" };

  await db
    .update(users)
    .set({ failedLogins: 0, lockedUntil: null, updatedAt: new Date() })
    .where(eq(users.id, user.id));

  const { token, expiresAt } = await createSession(user.id, meta, db);
  return { ok: true, token, expiresAt, userId: user.id };
}
