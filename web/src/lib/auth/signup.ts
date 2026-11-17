import { eq } from "drizzle-orm";
import { getDb, type Db } from "@/db/client";
import { settings, users } from "@/db/schema";
import { hashPassword } from "./password";
import { consumeRateLimit } from "../security/rate-limit";

export type SignupMode = "closed" | "open";

/** Reads the signup mode. Defaults to "closed" so nothing is open until an admin enables it. */
export async function getSignupMode(db: Db = getDb()): Promise<SignupMode> {
  const [row] = await db.select().from(settings).where(eq(settings.key, "signup_mode")).limit(1);
  return row?.value === "open" ? "open" : "closed";
}

export type SignupResult =
  | { ok: true }
  | { ok: false; reason: "closed" | "rate_limited" | "invalid" };

/**
 * Creates a user. Returns { ok: true } for new and existing emails alike, so the
 * response does not reveal whether an account exists. The existing-account case
 * is handled by the caller sending the same response.
 */
export async function signup(
  email: string,
  password: string,
  meta: { ip: string },
  db: Db = getDb(),
): Promise<SignupResult> {
  const allowed = await consumeRateLimit(`signup:${meta.ip}`, 5, 60 * 60 * 1000, db);
  if (!allowed) return { ok: false, reason: "rate_limited" };
  if ((await getSignupMode(db)) !== "open") return { ok: false, reason: "closed" };

  const passwordHash = await hashPassword(password);
  const [existing] = await db.select({ id: users.id }).from(users).where(eq(users.email, email)).limit(1);
  if (existing) return { ok: true };

  try {
    await db.insert(users).values({ email, passwordHash });
  } catch (err) {
    // Lost a race with a concurrent signup for the same email: treat as success.
    if ((err as { code?: string }).code === "23505") return { ok: true };
    throw err;
  }
  return { ok: true };
}
