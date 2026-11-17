import { drizzle as drizzlePg } from "drizzle-orm/postgres-js";
import postgres from "postgres";
import * as schema from "./schema";

export type Db = ReturnType<typeof drizzlePg<typeof schema>>;

let cached: Db | undefined;

/**
 * Returns a shared Drizzle client for the Postgres database in DATABASE_URL.
 * Only parameterized queries are used through Drizzle.
 */
export function getDb(): Db {
  if (cached) return cached;
  const url = process.env.DATABASE_URL;
  if (!url) throw new Error("DATABASE_URL is not set");
  const client = postgres(url, { max: 10, prepare: true });
  cached = drizzlePg(client, { schema });
  return cached;
}
