"use client";

import { useState, type FormEvent } from "react";

export default function LoginPage() {
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function onSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    const form = new FormData(e.currentTarget);
    try {
      const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "same-origin",
        body: JSON.stringify({ email: form.get("email"), password: form.get("password") }),
      });
      if (res.ok) {
        window.location.assign("/");
        return;
      }
      const data = (await res.json().catch(() => ({}))) as { error?: string };
      setError(data.error ?? "Sign-in failed.");
    } catch {
      setError("Network error. Try again.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main style={{ maxWidth: 360, margin: "10vh auto", padding: 24 }}>
      <h1>Sign in to MyCloud</h1>
      <form onSubmit={onSubmit} noValidate>
        <label htmlFor="email">Email</label>
        <input id="email" name="email" type="email" autoComplete="email" required maxLength={254} style={{ width: "100%", marginBottom: 12 }} />
        <label htmlFor="password">Password</label>
        <input id="password" name="password" type="password" autoComplete="current-password" required maxLength={256} style={{ width: "100%", marginBottom: 12 }} />
        <button type="submit" disabled={busy} style={{ width: "100%", padding: 10 }}>
          {busy ? "Signing in…" : "Sign in"}
        </button>
      </form>
      {error && <p role="alert" style={{ color: "#ff8a8a" }}>{error}</p>}
    </main>
  );
}
