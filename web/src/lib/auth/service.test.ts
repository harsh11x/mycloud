import { describe, it, expect, beforeEach } from "vitest";
import { PGlite } from "@electric-sql/pglite";
import { drizzle } from "drizzle-orm/pglite";
import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import * as schema from "@/db/schema";
import { hashPassword } from "./password";
import { login, MAX_FAILED_LOGINS } from "./service";

const PASSWORD = "correct horse battery";

async function makeDb() {
  const client = new PGlite();
  const dir = path.resolve(__dirname, "../../../drizzle");
  for (const f of readdirSync(dir).filter((x) => x.endsWith(".sql")).sort()) {
    const sql = readFileSync(path.join(dir, f), "utf8").split("--> statement-breakpoint").join("\n");
    await client.exec(sql);
  }
  return drizzle(client, { schema });
}

describe("login service", () => {
  let db: Awaited<ReturnType<typeof makeDb>>;
  const meta = { ip: "203.0.113.5" };

  beforeEach(async () => {
    db = await makeDb();
    await db.insert(schema.users).values({
      email: "alice@example.com",
      passwordHash: await hashPassword(PASSWORD),
    });
  });

  it("accepts the correct password and issues a session", async () => {
    const r = await login("alice@example.com", PASSWORD, meta, db as never);
    expect(r.ok).toBe(true);
  });

  it("returns the same generic reason for unknown emails and wrong passwords", async () => {
    const a = await login("nobody@example.com", "whatever password", meta, db as never);
    const b = await login("alice@example.com", "wrong password here", meta, db as never);
    expect(a).toMatchObject({ ok: false, reason: "invalid" });
    expect(b).toMatchObject({ ok: false, reason: "invalid" });
  });

  it("locks the account after repeated failures, even with the right password", async () => {
    for (let i = 0; i < MAX_FAILED_LOGINS; i++) {
      await login("alice@example.com", "wrong password here", { ip: `198.51.100.${i}` }, db as never);
    }
    const r = await login("alice@example.com", PASSWORD, { ip: "198.51.100.99" }, db as never);
    expect(r).toMatchObject({ ok: false, reason: "locked" });
  });

  it("refuses suspended or blocked accounts", async () => {
    await db.update(schema.users).set({ status: "blocked" });
    const r = await login("alice@example.com", PASSWORD, meta, db as never);
    expect(r).toMatchObject({ ok: false, reason: "blocked" });
  });
});
