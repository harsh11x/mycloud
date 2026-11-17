import { cookies } from "next/headers";
import { NextResponse } from "next/server";
import { and, eq } from "drizzle-orm";
import { getDb } from "@/db/client";
import { uploads } from "@/db/schema";
import { resolveSession, SESSION_COOKIE } from "@/lib/auth/session";
import { grantConfig, grantQuery, issueGrant } from "@/lib/grants/grant";
import { isSameOrigin } from "@/lib/security/request";
import { uuidSchema } from "@/lib/validation";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * Issues one upload grant for a specific chunk. The upload must belong to the caller and
 * be unexpired. The client sends the offset it wants; the Agent enforces that the offset
 * equals the bytes already stored, so retries are idempotent.
 */
export async function POST(req: Request, { params }: { params: Promise<{ id: string }> }) {
  if (!isSameOrigin(req)) return NextResponse.json({ error: "Forbidden" }, { status: 403 });

  const resolved = await resolveSession((await cookies()).get(SESSION_COOKIE)?.value);
  if (!resolved) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const { id } = await params;
  if (!uuidSchema.safeParse(id).success) return NextResponse.json({ error: "Not found" }, { status: 404 });

  const [upload] = await getDb()
    .select()
    .from(uploads)
    .where(and(eq(uploads.id, id), eq(uploads.ownerId, resolved.user.id)))
    .limit(1);
  if (!upload) return NextResponse.json({ error: "Not found" }, { status: 404 });
  if (upload.expiresAt.getTime() < Date.now()) {
    return NextResponse.json({ error: "Upload expired" }, { status: 410 });
  }

  const { privateKeyPem, agentUrl } = grantConfig();
  const { grant, sig } = issueGrant("upload", upload.fileId, resolved.user.id, privateKeyPem);
  return NextResponse.json(
    {
      agentUrl: `${agentUrl.replace(/\/$/, "")}/v1/files/${upload.fileId}`,
      grant: grantQuery(grant, sig),
      fileId: upload.fileId,
      receivedBytes: upload.receivedBytes,
    },
    { headers: { "Cache-Control": "no-store" } },
  );
}
