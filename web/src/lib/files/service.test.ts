import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createTestDb, type TestDb } from "@/lib/test-db";
import { users, files } from "@/db/schema";
import { getOwnedFile, listOwnedFiles, trashOwnedFile, restoreOwnedFile } from "./service";

describe("file ownership (IDOR)", () => {
  let t: TestDb;
  let alice: string;
  let bob: string;
  let aliceFile: string;

  beforeAll(async () => {
    t = await createTestDb();
    const [a] = await t.db.insert(users).values({ email: "alice@example.com", passwordHash: "x" }).returning({ id: users.id });
    const [b] = await t.db.insert(users).values({ email: "bob@example.com", passwordHash: "x" }).returning({ id: users.id });
    alice = a.id;
    bob = b.id;
    const [f] = await t.db
      .insert(files)
      .values({ ownerId: alice, name: "secret.txt", status: "ready", sizeBytes: 5 })
      .returning({ id: files.id });
    aliceFile = f.id;
  });

  afterAll(async () => {
    await t.close();
  });

  it("lets the owner read their own file", async () => {
    expect((await getOwnedFile(alice, aliceFile, t.db))?.name).toBe("secret.txt");
  });

  it("hides another user's file as if it did not exist", async () => {
    expect(await getOwnedFile(bob, aliceFile, t.db)).toBeNull();
  });

  it("does not list another user's files", async () => {
    expect(await listOwnedFiles(bob, t.db)).toHaveLength(0);
    expect(await listOwnedFiles(alice, t.db)).toHaveLength(1);
  });

  it("refuses to trash or restore another user's file", async () => {
    expect(await trashOwnedFile(bob, aliceFile, t.db)).toBe(false);
    expect(await trashOwnedFile(alice, aliceFile, t.db)).toBe(true);
    expect(await restoreOwnedFile(bob, aliceFile, t.db)).toBe(false);
    expect(await restoreOwnedFile(alice, aliceFile, t.db)).toBe(true);
  });
});
