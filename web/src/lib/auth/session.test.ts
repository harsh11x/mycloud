// @vitest-environment node
import { describe, it, expect, afterEach } from "vitest";
import { resolveSession } from "./session";
import type { Db } from "../../db/client";

const original = process.env.DATABASE_URL;

afterEach(() => {
  if (original === undefined) delete process.env.DATABASE_URL;
  else process.env.DATABASE_URL = original;
});

describe("resolveSession", () => {
  it("returns null without a token and never opens a connection", async () => {
    // getDb() throws when DATABASE_URL is unset, so resolving here proves no connection was made.
    delete process.env.DATABASE_URL;

    await expect(resolveSession(undefined)).resolves.toBeNull();
  });

  it("propagates query errors when a token is present", async () => {
    const db = {
      select: () => {
        throw new Error("connection refused");
      },
    } as unknown as Db;

    await expect(resolveSession("token", db)).rejects.toThrow("connection refused");
  });
});
