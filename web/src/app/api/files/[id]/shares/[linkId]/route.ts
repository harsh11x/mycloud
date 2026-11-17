import { cookies } from "next/headers";
import { NextResponse } from "next/server";
import { resolveSession, SESSION_COOKIE } from "@/lib/auth/session";
import { revokeShareLink } from "@/lib/share/service";
import { isSameOrigin } from "@/lib/security/request";
import { uuidSchema } from "@/lib/validation";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/** Revokes a share link immediately. Only the file's owner can revoke it. */
export async function DELETE(req: Request, { params }: { params: Promise<{ id: string; linkId: string }> }) {
  if (!isSameOrigin(req)) return NextResponse.json({ error: "Forbidden" }, { status: 403 });

  const resolved = await resolveSession((await cookies()).get(SESSION_COOKIE)?.value);
  if (!resolved) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const { id, linkId } = await params;
  if (!uuidSchema.safeParse(id).success || !uuidSchema.safeParse(linkId).success) {
    return NextResponse.json({ error: "Not found" }, { status: 404 });
  }

  const revoked = await revokeShareLink(resolved.user.id, id, linkId);
  if (!revoked) return NextResponse.json({ error: "Not found" }, { status: 404 });
  return NextResponse.json({ ok: true });
}
