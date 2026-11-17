"use client";

import { useCallback, useEffect, useState, type ChangeEvent } from "react";
import { uploadFile } from "@/lib/upload/client";

type FileRow = {
  id: string;
  name: string;
  mimeType: string;
  sizeBytes: number;
  sha256: string;
  createdAt: string;
};

export default function FilesPanel() {
  const [files, setFiles] = useState<FileRow[]>([]);
  const [status, setStatus] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    const res = await fetch("/api/files", { credentials: "same-origin", cache: "no-store" });
    if (!res.ok) {
      setStatus(`Could not load files (${res.status}).`);
      return;
    }
    const data = (await res.json()) as { files: FileRow[] };
    setFiles(data.files);
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function onUpload(e: ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    e.target.value = "";
    if (!file) return;
    setBusy(true);
    setStatus(`Uploading ${file.name}…`);
    try {
      await uploadFile(file, (sent, total) =>
        setStatus(`Uploading ${file.name}… ${Math.floor((sent / total) * 100)}%`),
      );
      setStatus(`Uploaded ${file.name}.`);
      await load();
    } catch (err) {
      setStatus(err instanceof Error ? `Upload failed: ${err.message}` : "Upload failed.");
    } finally {
      setBusy(false);
    }
  }

  async function onDownload(f: FileRow) {
    setStatus(null);
    const res = await fetch(`/api/files/${f.id}/download`, { credentials: "same-origin", cache: "no-store" });
    if (!res.ok) {
      setStatus(`Download failed (${res.status}).`);
      return;
    }
    const { url } = (await res.json()) as { url: string };
    // The grant URL is single-use and short-lived; the browser fetches the bytes straight from the Agent.
    window.location.assign(url);
  }

  async function onDelete(f: FileRow) {
    if (!window.confirm(`Delete ${f.name} permanently?`)) return;
    setBusy(true);
    setStatus(null);
    try {
      const res = await fetch(`/api/files/${f.id}`, { method: "DELETE", credentials: "same-origin" });
      if (!res.ok) {
        setStatus(`Delete failed (${res.status}).`);
        return;
      }
      await load();
    } finally {
      setBusy(false);
    }
  }

  return (
    <section>
      <label style={{ display: "inline-block", marginBottom: 16 }}>
        <input type="file" onChange={onUpload} disabled={busy} />
      </label>
      {status && <p role="status">{status}</p>}
      {files.length === 0 ? (
        <p>No files yet.</p>
      ) : (
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr>
              <th style={{ textAlign: "left" }}>Name</th>
              <th style={{ textAlign: "right" }}>Size</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {files.map((f) => (
              <tr key={f.id}>
                <td>{f.name}</td>
                <td style={{ textAlign: "right" }}>{f.sizeBytes.toLocaleString()} B</td>
                <td style={{ textAlign: "right" }}>
                  <button type="button" onClick={() => onDownload(f)} disabled={busy}>
                    Download
                  </button>{" "}
                  <button type="button" onClick={() => onDelete(f)} disabled={busy}>
                    Delete
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
