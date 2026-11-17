import { cookies } from "next/headers";
import { NextResponse } from "next/server";
import { resolveSession, SESSION_COOKIE } from "@/lib/auth/session";
import { getOwnedFile } from "@/lib/files/service";
import { grantConfig, grantQuery, issueGrant } from "@/lib/grants/grant";
import { uuidSchema } from "@/lib/validation";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * Returns a single-use download URL for the Agent. The owner check happens here before
 * any grant is issued. The Agent checks the grant again and only serves its owner.
 */
export async function GET(_req: Request, { params }: { params: Promise<{ id: string }> }) {
  const resolved = await resolveSession((await cookies()).get(SESSION_COOKIE)?.value);
  if (!resolved) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const { id } = await params;
  if (!uuidSchema.safeParse(id).success) return NextResponse.json({ error: "Not found" }, { status: 404 });

  const file = await getOwnedFile(resolved.user.id, id);
  if (!file || file.status !== "ready") return NextResponse.json({ error: "Not found" }, { status: 404 });

  const { privateKeyPem, agentUrl } = grantConfig();
  const { grant, sig } = issueGrant("download", file.id, resolved.user.id, privateKeyPem);
  return NextResponse.json(
    {
      url: `${agentUrl.replace(/\/$/, "")}/v1/files/${file.id}?${grantQuery(grant, sig)}`,
      name: file.name,
    },
    { headers: { "Cache-Control": "no-store" } },
  );
}
