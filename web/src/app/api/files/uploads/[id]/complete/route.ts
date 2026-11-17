import { cookies } from "next/headers";
import { NextResponse } from "next/server";
import { and, eq } from "drizzle-orm";
import { z } from "zod";
import { getDb } from "@/db/client";
import { files, uploads } from "@/db/schema";
import { resolveSession, SESSION_COOKIE } from "@/lib/auth/session";
import { grantConfig, grantQuery, issueGrant } from "@/lib/grants/grant";
import { isSameOrigin } from "@/lib/security/request";
import { uuidSchema } from "@/lib/validation";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const bodySchema = z.object({ sha256: z.string().regex(/^[a-f0-9]{64}$/i) });

/**
 * Finalises an upload. Asks the Agent to re-hash the whole file and compare it with the
 * client-declared SHA-256. The file is only marked "ready" when the Agent confirms the
 * hash and the stored size matches the expected size. Otherwise it stays "uploading".
 */
export async function POST(req: Request, { params }: { params: Promise<{ id: string }> }) {
  if (!isSameOrigin(req)) return NextResponse.json({ error: "Forbidden" }, { status: 403 });

  const resolved = await resolveSession((await cookies()).get(SESSION_COOKIE)?.value);
  if (!resolved) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const { id } = await params;
  if (!uuidSchema.safeParse(id).success) return NextResponse.json({ error: "Not found" }, { status: 404 });
  const parsed = bodySchema.safeParse(await req.json().catch(() => null));
  if (!parsed.success) return NextResponse.json({ error: "Invalid request" }, { status: 400 });
  const sha256 = parsed.data.sha256.toLowerCase();

  const db = getDb();
  const [upload] = await db
    .select()
    .from(uploads)
    .where(and(eq(uploads.id, id), eq(uploads.ownerId, resolved.user.id)))
    .limit(1);
  if (!upload) return NextResponse.json({ error: "Not found" }, { status: 404 });

  const { privateKeyPem, agentUrl } = grantConfig();
  const { grant, sig } = issueGrant("finalize", upload.fileId, resolved.user.id, privateKeyPem);
  const res = await fetch(
    `${agentUrl.replace(/\/$/, "")}/v1/files/${upload.fileId}/finalize?${grantQuery(grant, sig)}`,
    { method: "POST", headers: { "X-Content-SHA256": sha256 }, cache: "no-store" },
  );
  if (!res.ok) {
    return NextResponse.json({ error: "Verification failed" }, { status: res.status === 422 ? 422 : 409 });
  }
  const stored = (await res.json().catch(() => null)) as { bytes?: number; sha256?: string } | null;
  if (!stored || stored.bytes !== upload.expectedSize || stored.sha256 !== sha256) {
    return NextResponse.json({ error: "Verification failed" }, { status: 409 });
  }

  await db
    .update(files)
    .set({ status: "ready", sha256, sizeBytes: upload.expectedSize, updatedAt: new Date() })
    .where(eq(files.id, upload.fileId));
  await db.delete(uploads).where(eq(uploads.id, id));

  return NextResponse.json({ ok: true, fileId: upload.fileId, sizeBytes: upload.expectedSize });
}
