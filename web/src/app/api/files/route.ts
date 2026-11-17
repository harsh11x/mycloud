import { cookies } from "next/headers";
import { NextResponse } from "next/server";
import { resolveSession, SESSION_COOKIE } from "@/lib/auth/session";
import { listOwnedFiles } from "@/lib/files/service";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/** Lists the caller's ready files. Only rows owned by the caller are returned. */
export async function GET() {
  const resolved = await resolveSession((await cookies()).get(SESSION_COOKIE)?.value);
  if (!resolved) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const rows = await listOwnedFiles(resolved.user.id);
  return NextResponse.json(
    {
      files: rows.map((f) => ({
        id: f.id,
        name: f.name,
        mimeType: f.mimeType,
        sizeBytes: f.sizeBytes,
        sha256: f.sha256,
        createdAt: f.createdAt,
      })),
    },
    { headers: { "Cache-Control": "private, no-store" } },
  );
}
