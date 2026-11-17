import { randomBytes, createHash } from "node:crypto";
import { and, desc, eq, gt, isNull, or } from "drizzle-orm";
import { getDb } from "@/db/client";
import { files, shareLinks } from "@/db/schema";
import { getOwnedFile } from "@/lib/files/service";

export const DEFAULT_SHARE_HOURS = 24;
export const MAX_SHARE_HOURS = 24 * 30;

function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

export type ShareLinkRow = {
  id: string;
  fileId: string;
  expiresAt: Date | null;
  revokedAt: Date | null;
  createdAt: Date;
};

/**
 * Creates a share link for a file the owner controls. The raw token is returned once and
 * only its hash is stored. Returns null when the file is not owned or not ready.
 */
export async function createShareLink(
  ownerId: string,
  fileId: string,
  expiresInHours: number = DEFAULT_SHARE_HOURS,
  db = getDb(),
): Promise<{ token: string; link: ShareLinkRow } | null> {
  const file = await getOwnedFile(ownerId, fileId, db);
  if (!file || file.status !== "ready") return null;

  const token = randomBytes(32).toString("base64url");
  const expiresAt = new Date(Date.now() + expiresInHours * 60 * 60 * 1000);
  const [row] = await db
    .insert(shareLinks)
    .values({ fileId: file.id, ownerId, tokenHash: hashToken(token), expiresAt })
    .returning({
      id: shareLinks.id,
      fileId: shareLinks.fileId,
      expiresAt: shareLinks.expiresAt,
      revokedAt: shareLinks.revokedAt,
      createdAt: shareLinks.createdAt,
    });
  return { token, link: row };
}

/** Lists the owner's share links for one file. Tokens are never returned. */
export async function listShareLinks(ownerId: string, fileId: string, db = getDb()): Promise<ShareLinkRow[]> {
  return db
    .select({
      id: shareLinks.id,
      fileId: shareLinks.fileId,
      expiresAt: shareLinks.expiresAt,
      revokedAt: shareLinks.revokedAt,
      createdAt: shareLinks.createdAt,
    })
    .from(shareLinks)
    .where(and(eq(shareLinks.ownerId, ownerId), eq(shareLinks.fileId, fileId)))
    .orderBy(desc(shareLinks.createdAt))
    .limit(100);
}

/** Revokes one of the owner's links. Returns false when no such active link exists. */
export async function revokeShareLink(ownerId: string, fileId: string, linkId: string, db = getDb()): Promise<boolean> {
  const rows = await db
    .update(shareLinks)
    .set({ revokedAt: new Date() })
    .where(
      and(
        eq(shareLinks.id, linkId),
        eq(shareLinks.ownerId, ownerId),
        eq(shareLinks.fileId, fileId),
        isNull(shareLinks.revokedAt),
      ),
    )
    .returning({ id: shareLinks.id });
  return rows.length > 0;
}

/**
 * Resolves a public token to a ready file. Returns null for unknown, expired, revoked
 * or deleted links, so callers can answer every failure the same way.
 */
export async function resolveShareToken(
  token: string,
  db = getDb(),
): Promise<{ fileId: string; ownerId: string; name: string } | null> {
  if (token.length < 20 || token.length > 128) return null;
  const [row] = await db
    .select({
      fileId: files.id,
      ownerId: shareLinks.ownerId,
      name: files.name,
      status: files.status,
    })
    .from(shareLinks)
    .innerJoin(files, eq(files.id, shareLinks.fileId))
    .where(
      and(
        eq(shareLinks.tokenHash, hashToken(token)),
        isNull(shareLinks.revokedAt),
        or(isNull(shareLinks.expiresAt), gt(shareLinks.expiresAt, new Date())),
      ),
    )
    .limit(1);
  if (!row || row.status !== "ready") return null;
  return { fileId: row.fileId, ownerId: row.ownerId, name: row.name };
}
