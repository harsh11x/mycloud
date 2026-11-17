"use client";

import { useState, type FormEvent } from "react";

export default function ChangePasswordForm() {
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function onSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    const form = new FormData(e.currentTarget);
    const currentPassword = String(form.get("currentPassword") ?? "");
    const newPassword = String(form.get("newPassword") ?? "");
    const confirmPassword = String(form.get("confirmPassword") ?? "");

    if (newPassword !== confirmPassword) {
      setError("New passwords do not match.");
      return;
    }

    setBusy(true);
    try {
      const res = await fetch("/api/auth/password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "same-origin",
        body: JSON.stringify({ currentPassword, newPassword }),
      });
      if (res.ok) {
        // All sessions were revoked, including this one. Sign in again with the new password.
        window.location.assign("/login");
        return;
      }
      const data = (await res.json().catch(() => ({}))) as { error?: string };
      setError(data.error ?? "Could not change password.");
    } catch {
      setError("Network error. Try again.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main style={{ maxWidth: 360, margin: "10vh auto", padding: 24 }}>
      <h1>Change password</h1>
      <p>Changing your password signs you out on every device.</p>
      <form onSubmit={onSubmit} noValidate>
        <label htmlFor="currentPassword">Current password</label>
        <input id="currentPassword" name="currentPassword" type="password" autoComplete="current-password" required maxLength={256} style={{ width: "100%", marginBottom: 12 }} />
        <label htmlFor="newPassword">New password (at least 12 characters)</label>
        <input id="newPassword" name="newPassword" type="password" autoComplete="new-password" required minLength={12} maxLength={256} style={{ width: "100%", marginBottom: 12 }} />
        <label htmlFor="confirmPassword">Confirm new password</label>
        <input id="confirmPassword" name="confirmPassword" type="password" autoComplete="new-password" required minLength={12} maxLength={256} style={{ width: "100%", marginBottom: 12 }} />
        <button type="submit" disabled={busy} style={{ width: "100%", padding: 10 }}>
          {busy ? "Changing…" : "Change password"}
        </button>
      </form>
      {error && <p role="alert" style={{ color: "#ff8a8a" }}>{error}</p>}
    </main>
  );
}
