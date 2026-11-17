import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { resolveSession, SESSION_COOKIE } from "@/lib/auth/session";
import ChangePasswordForm from "./change-password-form";

export const dynamic = "force-dynamic";

export default async function ChangePasswordPage() {
  const token = (await cookies()).get(SESSION_COOKIE)?.value;
  const session = await resolveSession(token);
  if (!session) redirect("/login");

  return <ChangePasswordForm />;
}
