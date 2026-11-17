import { NextResponse } from "next/server";
import { login } from "@/lib/auth/service";
import { SESSION_COOKIE, sessionCookieOptions } from "@/lib/auth/session";
import { credentialsSchema } from "@/lib/validation";
import { clientIp, isSameOrigin } from "@/lib/security/request";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const GENERIC_FAILURE = { error: "Invalid email or password." };

export async function POST(req: Request) {
  if (!isSameOrigin(req)) {
    return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  }

  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json(GENERIC_FAILURE, { status: 400 });
  }

  const parsed = credentialsSchema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json(GENERIC_FAILURE, { status: 400 });
  }

  const result = await login(parsed.data.email, parsed.data.password, {
    ip: clientIp(req),
    userAgent: req.headers.get("user-agent") ?? undefined,
  });

  if (!result.ok) {
    if (result.reason === "rate_limited") {
      return NextResponse.json(
        { error: "Too many attempts. Try again later." },
        { status: 429, headers: { "Retry-After": "900" } },
      );
    }
    // invalid, locked and blocked all return the same body so accounts cannot be enumerated.
    return NextResponse.json(GENERIC_FAILURE, { status: 401 });
  }

  const res = NextResponse.json({ ok: true });
  res.cookies.set(SESSION_COOKIE, result.token, sessionCookieOptions(result.expiresAt));
  res.headers.set("Cache-Control", "no-store");
  return res;
}
