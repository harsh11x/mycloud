import { NextResponse } from "next/server";
import { grantConfig, grantQuery, issueGrant } from "@/lib/grants/grant";
import { resolveShareToken } from "@/lib/share/service";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * Public share download. The token is the only credential. The server re-checks expiry,
 * revocation and file status on every visit, then issues a fresh short-lived download
 * grant and redirects the browser to the Agent. The signing key stays on the server.
 */
export async function GET(_req: Request, { params }: { params: Promise<{ token: string }> }) {
  const { token } = await params;
  const shared = await resolveShareToken(token);
  if (!shared) {
    return new NextResponse("Not found", { status: 404, headers: { "Cache-Control": "no-store" } });
  }

  const { privateKeyPem, agentUrl } = grantConfig();
  const { grant, sig } = issueGrant("download", shared.fileId, shared.ownerId, privateKeyPem);
  const res = NextResponse.redirect(
    `${agentUrl.replace(/\/$/, "")}/v1/files/${shared.fileId}?${grantQuery(grant, sig)}`,
    302,
  );
  res.headers.set("Cache-Control", "no-store");
  res.headers.set("Referrer-Policy", "no-referrer");
  return res;
}
