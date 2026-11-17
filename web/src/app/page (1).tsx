import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { resolveSession, SESSION_COOKIE } from "@/lib/auth/session";

export const dynamic = "force-dynamic";

export default async function Home() {
  const token = (await cookies()).get(SESSION_COOKIE)?.value;
  const session = await resolveSession(token);
  if (!session) redirect("/login");

  return (
    <main style={{ maxWidth: 720, margin: "10vh auto", padding: 24 }}>
      <h1>MyCloud</h1>
      <p>Signed in as {session.user.email}. The file manager is not built yet.</p>
    </main>
  );
}
