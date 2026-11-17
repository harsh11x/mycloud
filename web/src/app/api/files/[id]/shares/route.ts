import { cookies } from "next/headers";
import { NextResponse } from "next/server";
import { z } from "zod";
import { resolveSession, SESSION_COOKIE } from "@/lib/auth/session";
import { createShareLink, DEFAULT_SHARE_HOURS, listShareLinks, MAX_SHARE_HOURS } from "@/lib/share/service";
import { isSameOrigin } from "@/lib/security/request";
import { uuidSchema } from "@/lib/validation";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const createBodySchema = z.object({
  expiresInHours: z.number().int().min(1).max(MAX_SHARE_HOURS).optional(),
});

/** Lists the owner's share links for a file. Tokens are never returned after creation. */
export async function GET(_req: Request, { params }: { params: Promise<{ id: string }> }) {
  const resolved = await resolveSession((await cookies()).get(SESSION_COOKIE)?.value);
  if (!resolved) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const { id } = await params;
  if (!uuidSchema.safeParse(id).success) return NextResponse.json({ error: "Not found" }, { status: 404 });

  const links = await listShareLinks(resolved.user.id, id);
  return NextResponse.json({ links }, { headers: { "Cache-Control": "no-store" } });
}

/**
 * Creates a share link. The response contains the only copy of the token; the public URL
 * is built from the app origin, and the Agent signing key never leaves the server.
 */
export async function POST(req: Request, { params }: { params: Promise<{ id: string }> }) {
  if (!isSameOrigin(req)) return NextResponse.json({ error: "Forbidden" }, { status: 403 });

  const resolved = await resolveSession((await cookies()).get(SESSION_COOKIE)?.value);
  if (!resolved) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const { id } = await params;
  if (!uuidSchema.safeParse(id).success) return NextResponse.json({ error: "Not found" }, { status: 404 });

  let body: unknown = {};
  try {
    const text = await req.text();
    body = text ? JSON.parse(text) : {};
  } catch {
    return NextResponse.json({ error: "Invalid body" }, { status: 400 });
  }
  const parsed = createBodySchema.safeParse(body);
  if (!parsed.success) return NextResponse.json({ error: "Invalid expiry" }, { status: 400 });

  const created = await createShareLink(resolved.user.id, id, parsed.data.expiresInHours ?? DEFAULT_SHARE_HOURS);
  if (!created) return NextResponse.json({ error: "Not found" }, { status: 404 });

  const origin = (process.env.APP_ORIGIN ?? "").replace(/\/$/, "");
  return NextResponse.json(
    {
      link: created.link,
      url: `${origin}/api/share/${created.token}`,
    },
    { status: 201, headers: { "Cache-Control": "no-store" } },
  );
}
