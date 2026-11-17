import { cookies } from "next/headers";
import { NextResponse } from "next/server";
import { revokeSessionByToken, SESSION_COOKIE } from "@/lib/auth/session";
import { isSameOrigin } from "@/lib/security/request";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(req: Request) {
  if (!isSameOrigin(req)) {
    return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  }
  const token = (await cookies()).get(SESSION_COOKIE)?.value;
  if (token) await revokeSessionByToken(token);

  const res = NextResponse.json({ ok: true });
  res.cookies.set(SESSION_COOKIE, "", { path: "/", maxAge: 0, httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production" });
  res.headers.set("Cache-Control", "no-store");
  return res;
}
