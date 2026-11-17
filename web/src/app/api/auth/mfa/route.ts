import { cookies } from "next/headers";
import { NextResponse } from "next/server";
import { z } from "zod";
import { beginTotpEnrolment, confirmTotpEnrolment, verifySessionMfa } from "@/lib/auth/mfa";
import { resolveSession, SESSION_COOKIE } from "@/lib/auth/session";
import { isSameOrigin } from "@/lib/security/request";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const codeSchema = z.object({ action: z.enum(["enrol", "confirm", "verify"]), code: z.string().regex(/^\d{6}$/).optional() });

/** TOTP enrolment (enrol → confirm) and step-up verification (verify). Session-bound and origin-checked. */
export async function POST(req: Request) {
  if (!isSameOrigin(req)) return NextResponse.json({ error: "Forbidden" }, { status: 403 });

  const resolved = await resolveSession((await cookies()).get(SESSION_COOKIE)?.value);
  if (!resolved) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const parsed = codeSchema.safeParse(await req.json().catch(() => null));
  if (!parsed.success) return NextResponse.json({ error: "Invalid request" }, { status: 400 });
  const { action, code } = parsed.data;
  const { user, sessionId } = resolved;

  if (action === "enrol") {
    const { uri } = await beginTotpEnrolment(user.id, user.email);
    return NextResponse.json({ otpauthUri: uri }, { headers: { "Cache-Control": "no-store" } });
  }

  if (!code) return NextResponse.json({ error: "Invalid code" }, { status: 400 });

  const ok =
    action === "confirm"
      ? await confirmTotpEnrolment(user.id, code)
      : await verifySessionMfa(user.id, sessionId, code);

  if (!ok) return NextResponse.json({ error: "Invalid code" }, { status: 401 });
  return NextResponse.json({ ok: true });
}
