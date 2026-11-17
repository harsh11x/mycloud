import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createTestDb, type TestDb } from "../test-db";
import { users, sessions } from "@/db/schema";
import { eq } from "drizzle-orm";
import { beginTotpEnrolment, confirmTotpEnrolment, verifySessionMfa } from "./mfa";
import { totpCode } from "./totp";
import { hashPassword } from "./password";
import { createSession } from "./session";

let t: TestDb;
let userId: string;
let sessionId: string;

beforeEach(async () => {
  t = await createTestDb();
  const [u] = await t.db
    .insert(users)
    .values({ email: "admin@example.com", passwordHash: await hashPassword("correct horse battery"), role: "admin" })
    .returning({ id: users.id });
  userId = u.id;
  const { token } = await createSession(userId, { ip: "1.2.3.4" }, t.db);
  const [s] = await t.db.select({ id: sessions.id }).from(sessions).limit(1);
  sessionId = s.id;
  void token;
});

afterEach(async () => {
  await t.close();
});

describe("TOTP enrolment and session step-up", () => {
  it("does not enable TOTP until a valid code is confirmed", async () => {
    const { secret } = await beginTotpEnrolment(userId, "admin@example.com", t.db);
    expect(await confirmTotpEnrolment(userId, "000000", t.db)).toBe(false);
    const code = totpCode(secret, Math.floor(Date.now() / 1000 / 30));
    expect(await confirmTotpEnrolment(userId, code, t.db)).toBe(true);
    const [u] = await t.db.select().from(users).where(eq(users.id, userId));
    expect(u.totpEnabled).toBe(true);
  });

  it("stamps the session on a valid code and refuses the same code twice", async () => {
    const { secret } = await beginTotpEnrolment(userId, "admin@example.com", t.db);
    const c = Math.floor(Date.now() / 1000 / 30);
    await confirmTotpEnrolment(userId, totpCode(secret, c), t.db);

    // A replay of the same code is rejected even within the valid window.
    expect(await verifySessionMfa(userId, sessionId, totpCode(secret, c), t.db)).toBe(false);

    const [s] = await t.db.select().from(sessions).where(eq(sessions.id, sessionId));
    expect(s.mfaVerifiedAt).toBeNull();
  });

  it("accepts the next step's code and then sets mfaVerifiedAt", async () => {
    const { secret } = await beginTotpEnrolment(userId, "admin@example.com", t.db);
    const c = Math.floor(Date.now() / 1000 / 30);
    await confirmTotpEnrolment(userId, totpCode(secret, c), t.db);
    expect(await verifySessionMfa(userId, sessionId, totpCode(secret, c + 1), t.db)).toBe(true);
    const [s] = await t.db.select().from(sessions).where(eq(sessions.id, sessionId));
    expect(s.mfaVerifiedAt).not.toBeNull();
  });
});
