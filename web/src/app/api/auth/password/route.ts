import { cookies } from "next/headers";
import { NextResponse } from "next/server";
import { z } from "zod";
import { changePassword } from "@/lib/auth/change-password";
import { resolveSession, SESSION_COOKIE } from "@/lib/auth/session";
import { validatePasswordPolicy } from "@/lib/auth/password";
import { isSameOrigin } from "@/lib/security/request";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const bodySchema = z.object({
  currentPassword: z.string().min(1).max(256),
  newPassword: z.string().min(12).max(256),
});

/** Changes the signed-in user's password. Requires the current password and revokes all sessions. */
export async function POST(req: Request) {
  if (!isSameOrigin(req)) return NextResponse.json({ error: "Forbidden" }, { status: 403 });

  const resolved = await resolveSession((await cookies()).get(SESSION_COOKIE)?.value);
  if (!resolved) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const parsed = bodySchema.safeParse(await req.json().catch(() => null));
  if (!parsed.success) {
    return NextResponse.json({ error: "Invalid request" }, { status: 400 });
  }

  const policyError = validatePasswordPolicy(parsed.data.newPassword);
  if (policyError) return NextResponse.json({ error: policyError }, { status: 400 });

  if (parsed.data.currentPassword === parsed.data.newPassword) {
    return NextResponse.json({ error: "New password must differ from the current password." }, { status: 400 });
  }

  const result = await changePassword(
    resolved.user.id,
    parsed.data.currentPassword,
    parsed.data.newPassword,
  );

  if (!result.ok) {
    if (result.reason === "rate_limited") {
      return NextResponse.json(
        { error: "Too many attempts. Try again later." },
        { status: 429, headers: { "Retry-After": "900" } },
      );
    }
    if (result.reason === "invalid_current") {
      return NextResponse.json({ error: "Current password is incorrect." }, { status: 401 });
    }
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const res = NextResponse.json({ ok: true });
  res.cookies.set(SESSION_COOKIE, "", { path: "/", maxAge: 0, httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production" });
  res.headers.set("Cache-Control", "no-store");
  return res;
}
