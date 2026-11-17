import { createHash, randomBytes } from "node:crypto";
import { and, eq, isNull, gt } from "drizzle-orm";
import { getDb, type Db } from "@/db/client";
import { sessions, users } from "@/db/schema";

export const SESSION_COOKIE = "mc_session";
export const SESSION_IDLE_MS = 30 * 60 * 1000; // 30 minutes idle
export const SESSION_ABSOLUTE_MS = 12 * 60 * 60 * 1000; // 12 hours absolute

export function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

export function newToken(): string {
  return randomBytes(32).toString("base64url");
}

/** Creates a server-side session and returns the raw token (only sent to the browser). */
export async function createSession(
  userId: string,
  meta: { ip?: string; userAgent?: string },
  db: Db = getDb(),
): Promise<{ token: string; expiresAt: Date }> {
  const token = newToken();
  const expiresAt = new Date(Date.now() + SESSION_ABSOLUTE_MS);
  await db.insert(sessions).values({
    userId,
    tokenHash: hashToken(token),
    ip: meta.ip ?? null,
    userAgent: meta.userAgent?.slice(0, 300) ?? null,
    expiresAt,
  });
  return { token, expiresAt };
}

/**
 * Resolves a raw session token to its user. Enforces idle and absolute expiry,
 * revocation, and account status. Returns null when the session is not usable.
 */
export async function resolveSession(token: string | undefined, db?: Db) {
  // No cookie means no session to look up, so don't open a connection just to answer that.
  if (!token) return null;
  const conn = db ?? getDb();
  const tokenHash = hashToken(token);
  const now = new Date();
  const rows = await conn
    .select({
      sessionId: sessions.id,
      lastSeenAt: sessions.lastSeenAt,
      userId: users.id,
      email: users.email,
      role: users.role,
      status: users.status,
      totpEnabled: users.totpEnabled,
      mfaVerifiedAt: sessions.mfaVerifiedAt,
      reauthAt: sessions.reauthAt,
    })
    .from(sessions)
    .innerJoin(users, eq(users.id, sessions.userId))
    .where(
      and(
        eq(sessions.tokenHash, tokenHash),
        isNull(sessions.revokedAt),
        gt(sessions.expiresAt, now),
      ),
    )
    .limit(1);
  const row = rows[0];
  if (!row) return null;
  if (now.getTime() - row.lastSeenAt.getTime() > SESSION_IDLE_MS) {
    await revokeSessionById(row.sessionId, conn);
    return null;
  }
  if (row.status !== "active") {
    await revokeSessionById(row.sessionId, conn);
    return null;
  }
  await conn.update(sessions).set({ lastSeenAt: now }).where(eq(sessions.id, row.sessionId));
  return {
    sessionId: row.sessionId,
    mfaVerifiedAt: row.mfaVerifiedAt,
    reauthAt: row.reauthAt,
    user: {
      id: row.userId,
      email: row.email,
      role: row.role,
      status: row.status,
      totpEnabled: row.totpEnabled,
    },
  };
}

export async function revokeSessionById(sessionId: string, db: Db = getDb()) {
  await db.update(sessions).set({ revokedAt: new Date() }).where(eq(sessions.id, sessionId));
}

export async function revokeSessionByToken(token: string, db: Db = getDb()) {
  await db
    .update(sessions)
    .set({ revokedAt: new Date() })
    .where(eq(sessions.tokenHash, hashToken(token)));
}

export async function revokeAllUserSessions(userId: string, db: Db = getDb()) {
  await db
    .update(sessions)
    .set({ revokedAt: new Date() })
    .where(and(eq(sessions.userId, userId), isNull(sessions.revokedAt)));
}

export function sessionCookieOptions(expiresAt: Date) {
  return {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax" as const,
    path: "/",
    expires: expiresAt,
  };
}
