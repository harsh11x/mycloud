import { PGlite } from "@electric-sql/pglite";
import { drizzle } from "drizzle-orm/pglite";
import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import * as schema from "@/db/schema";

export type TestDb = Awaited<ReturnType<typeof createTestDb>>;

/** In-memory Postgres (PGlite) with every migration in drizzle/ applied. Tests only. */
export async function createTestDb() {
  const client = new PGlite();
  const dir = path.resolve(process.cwd(), "drizzle");
  for (const f of readdirSync(dir).filter((x) => x.endsWith(".sql")).sort()) {
    const sql = readFileSync(path.join(dir, f), "utf8").split("--> statement-breakpoint").join("\n");
    await client.exec(sql);
  }
  const db = drizzle(client, { schema });
  return {
    db: db as unknown as import("@/db/client").Db,
    close: () => client.close(),
  };
}
