import { and, desc, eq, ne } from "drizzle-orm";
import { getDb, type Db } from "@/db/client";
import { files } from "@/db/schema";

export type FileRow = typeof files.$inferSelect;

/**
 * Every lookup takes the authenticated user's id and scopes by owner. A file owned by
 * another user is indistinguishable from a missing file (returns null), so IDs cannot
 * be probed across accounts (IDOR defence).
 */
export async function getOwnedFile(ownerId: string, fileId: string, db: Db = getDb()): Promise<FileRow | null> {
  const [row] = await db
    .select()
    .from(files)
    .where(and(eq(files.id, fileId), eq(files.ownerId, ownerId), ne(files.status, "deleted")))
    .limit(1);
  return row ?? null;
}

export async function listOwnedFiles(ownerId: string, db: Db = getDb()): Promise<FileRow[]> {
  return db
    .select()
    .from(files)
    .where(and(eq(files.ownerId, ownerId), eq(files.status, "ready")))
    .orderBy(desc(files.createdAt))
    .limit(500);
}

export async function listOwnedTrash(ownerId: string, db: Db = getDb()): Promise<FileRow[]> {
  return db
    .select()
    .from(files)
    .where(and(eq(files.ownerId, ownerId), eq(files.status, "trashed")))
    .orderBy(desc(files.trashedAt))
    .limit(500);
}

/** Moves a file to trash. Returns false when the file is not owned by the user. */
export async function trashOwnedFile(ownerId: string, fileId: string, db: Db = getDb()): Promise<boolean> {
  const rows = await db
    .update(files)
    .set({ status: "trashed", trashedAt: new Date(), updatedAt: new Date() })
    .where(and(eq(files.id, fileId), eq(files.ownerId, ownerId), eq(files.status, "ready")))
    .returning({ id: files.id });
  return rows.length === 1;
}

export async function restoreOwnedFile(ownerId: string, fileId: string, db: Db = getDb()): Promise<boolean> {
  const rows = await db
    .update(files)
    .set({ status: "ready", trashedAt: null, updatedAt: new Date() })
    .where(and(eq(files.id, fileId), eq(files.ownerId, ownerId), eq(files.status, "trashed")))
    .returning({ id: files.id });
  return rows.length === 1;
}
