import { eq, sql } from "drizzle-orm";
import { getDb, type Db } from "@/db/client";
import { rateLimits } from "@/db/schema";

/**
 * Fixed-window rate limiter backed by Postgres so it works across serverless instances.
 * Returns true when the request is allowed.
 */
export async function consumeRateLimit(
  key: string,
  limit: number,
  windowMs: number,
  db: Db = getDb(),
): Promise<boolean> {
  const now = new Date();
  const windowStart = new Date(now.getTime() - windowMs);
  const rows = await db
    .insert(rateLimits)
    .values({ key, count: 1, windowStart: now })
    .onConflictDoUpdate({
      target: rateLimits.key,
              set: {
        count: sql`CASE WHEN ${rateLimits.windowStart} < ${sql.param(windowStart, rateLimits.windowStart)} THEN 1 ELSE ${rateLimits.count} + 1 END`,
        windowStart: sql`CASE WHEN ${rateLimits.windowStart} < ${sql.param(windowStart, rateLimits.windowStart)} THEN ${sql.param(now, rateLimits.windowStart)} ELSE ${rateLimits.windowStart} END`,
      },
    })
    .returning({ count: rateLimits.count });
  return (rows[0]?.count ?? 0) <= limit;
}

export async function resetRateLimit(key: string, db: Db = getDb()) {
  await db.delete(rateLimits).where(eq(rateLimits.key, key));
}
