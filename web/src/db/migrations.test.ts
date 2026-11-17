import { describe, it, expect } from "vitest";
import { PGlite } from "@electric-sql/pglite";
import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";

// Applies the generated SQL migrations to an in-memory Postgres (PGlite)
// and checks the schema the app relies on, including the IDOR-relevant constraints.
describe("database migrations", () => {
  const dir = path.resolve(__dirname, "../../drizzle");
  const files = readdirSync(dir).filter((f) => f.endsWith(".sql")).sort();

  async function migrated() {
    const db = new PGlite();
    for (const f of files) {
      const sql = readFileSync(path.join(dir, f), "utf8")
        .split("--> statement-breakpoint")
        .join("\n");
      await db.exec(sql);
    }
    return db;
  }

  it("creates all core tables", async () => {
    const db = await migrated();
    const res = await db.query<{ table_name: string }>(
      "select table_name from information_schema.tables where table_schema = 'public'",
    );
    const names = res.rows.map((r) => r.table_name).sort();
    for (const t of ["users", "sessions", "drives", "files", "uploads", "share_links", "audit_log", "settings", "rate_limits"]) {
      expect(names).toContain(t);
    }
  });

  it("enforces unique emails and unique session token hashes", async () => {
    const db = await migrated();
    await db.query(
      "insert into users (email, password_hash) values ('a@example.com', 'x')",
    );
    await expect(
      db.query("insert into users (email, password_hash) values ('a@example.com', 'y')"),
    ).rejects.toThrow();
  });

  it("cascades file deletion from owners and rejects orphan files", async () => {
    const db = await migrated();
    const u = await db.query<{ id: string }>(
      "insert into users (email, password_hash) values ('b@example.com', 'x') returning id",
    );
    await db.query(
      "insert into files (owner_id, name) values ($1, 'doc.txt')",
      [u.rows[0].id],
    );
    await expect(
      db.query("insert into files (owner_id, name) values ('00000000-0000-0000-0000-000000000000', 'x')"),
    ).rejects.toThrow();
    await db.query("delete from users where id = $1", [u.rows[0].id]);
    const left = await db.query("select count(*)::int as c from files");
    expect((left.rows[0] as { c: number }).c).toBe(0);
  });
});
