import { cookies } from "next/headers";
import { NextResponse } from "next/server";
import { z } from "zod";
import { getDb } from "@/db/client";
import { files, uploads } from "@/db/schema";
import { resolveSession, SESSION_COOKIE } from "@/lib/auth/session";
import { fileNameSchema } from "@/lib/validation";
import { isSameOrigin } from "@/lib/security/request";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/** Largest single file accepted. Chunking keeps each request small; this caps the total. */
const MAX_FILE_BYTES = 5 * 1024 * 1024 * 1024; // 5 GiB
const MAX_CHUNK_BYTES = 64 * 1024 * 1024;
const UPLOAD_TTL_MS = 24 * 60 * 60 * 1000;

const initSchema = z.object({
  name: fileNameSchema,
  size: z.number().int().positive().max(MAX_FILE_BYTES),
  mimeType: z.string().trim().min(1).max(127).regex(/^[\w.+-]+\/[\w.+-]+$/).default("application/octet-stream"),
  chunkSize: z.number().int().min(64 * 1024).max(MAX_CHUNK_BYTES).default(8 * 1024 * 1024),
});

/**
 * Starts a resumable upload. Creates the file row in "uploading" state and an upload
 * record. Bytes are never sent here: they go to the Storage Agent via a grant issued
 * per chunk (see /api/files/uploads/[id]/grant).
 */
export async function POST(req: Request) {
  if (!isSameOrigin(req)) return NextResponse.json({ error: "Forbidden" }, { status: 403 });

  const resolved = await resolveSession((await cookies()).get(SESSION_COOKIE)?.value);
  if (!resolved) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const parsed = initSchema.safeParse(await req.json().catch(() => null));
  if (!parsed.success) return NextResponse.json({ error: "Invalid upload request." }, { status: 400 });
  const { name, size, mimeType, chunkSize } = parsed.data;

  const db = getDb();
  const [file] = await db
    .insert(files)
    .values({ ownerId: resolved.user.id, name, mimeType, sizeBytes: size, status: "uploading" })
    .returning({ id: files.id });
  const [upload] = await db
    .insert(uploads)
    .values({
      fileId: file.id,
      ownerId: resolved.user.id,
      expectedSize: size,
      chunkSize,
      expiresAt: new Date(Date.now() + UPLOAD_TTL_MS),
    })
    .returning({ id: uploads.id, chunkSize: uploads.chunkSize });

  return NextResponse.json(
    { uploadId: upload.id, fileId: file.id, chunkSize: upload.chunkSize },
    { status: 201, headers: { "Cache-Control": "no-store" } },
  );
}
