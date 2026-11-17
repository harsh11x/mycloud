import { NextResponse } from "next/server";
import { signup } from "@/lib/auth/signup";
import { signupSchema } from "@/lib/validation";
import { clientIp, isSameOrigin } from "@/lib/security/request";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(req: Request) {
  if (!isSameOrigin(req)) {
    return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  }

  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid request." }, { status: 400 });
  }

  const parsed = signupSchema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json(
      { error: "Enter a valid email and a password of at least 12 characters." },
      { status: 400 },
    );
  }

  const result = await signup(parsed.data.email, parsed.data.password, { ip: clientIp(req) });

  if (!result.ok) {
    if (result.reason === "rate_limited") {
      return NextResponse.json({ error: "Too many attempts. Try again later." }, { status: 429 });
    }
    return NextResponse.json({ error: "Sign-up is not available." }, { status: 403 });
  }

  // Same response whether or not the email was already registered.
  return NextResponse.json({ ok: true, message: "If the address can be registered, check your inbox to continue." }, {
    headers: { "Cache-Control": "no-store" },
  });
}
