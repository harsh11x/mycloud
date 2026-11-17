import { cookies } from "next/headers";
import { NextResponse } from "next/server";
import { eq } from "drizzle-orm";
import { getDb } from "@/db/client";
import { files } from "@/db/schema";
import { resolveSession, SESSION_COOKIE } from "@/lib/auth/session";
import { getOwnedFile } from "@/lib/files/service";
import { grantConfig, grantQuery, issueGrant } from "@/lib/grants/grant";
import { isSameOrigin } from "@/lib/security/request";
import { uuidSchema } from "@/lib/validation";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * Permanently deletes a file. The Agent removes the bytes first; the database row is
 * marked "deleted" only after the Agent confirms, so a failed call never hides live data.
 */
export async function DELETE(req: Request, { params }: { params: Promise<{ id: string }> }) {
  if (!isSameOrigin(req)) return NextResponse.json({ error: "Forbidden" }, { status: 403 });

  const resolved = await resolveSession((await cookies()).get(SESSION_COOKIE)?.value);
  if (!resolved) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const { id } = await params;
  if (!uuidSchema.safeParse(id).success) return NextResponse.json({ error: "Not found" }, { status: 404 });

  const file = await getOwnedFile(resolved.user.id, id);
  if (!file) return NextResponse.json({ error: "Not found" }, { status: 404 });

  const { privateKeyPem, agentUrl } = grantConfig();
  const { grant, sig } = issueGrant("delete", file.id, resolved.user.id, privateKeyPem);
  const res = await fetch(`${agentUrl.replace(/\/$/, "")}/v1/files/${file.id}?${grantQuery(grant, sig)}`, {
    method: "DELETE",
    cache: "no-store",
  });
  // 404 means the bytes are already gone; the record can still be cleared.
  if (!res.ok && res.status !== 404) {
    return NextResponse.json({ error: "Storage delete failed" }, { status: 502 });
  }

  await getDb()
    .update(files)
    .set({ status: "deleted", updatedAt: new Date() })
    .where(eq(files.id, file.id));
  return NextResponse.json({ ok: true });
}
