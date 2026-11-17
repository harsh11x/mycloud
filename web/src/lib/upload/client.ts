/**
 * Browser upload client. Splits a file into chunks, sends each chunk straight to the
 * Storage Agent with a fresh single-use grant, then asks the web app to finalise.
 * Bytes never pass through Vercel. The client resumes from the offset the Agent reports.
 */

type InitResponse = { uploadId: string; fileId: string; chunkSize: number };
type GrantResponse = { agentUrl: string; grant: string; fileId: string };

const MAX_RETRIES = 5;

async function sha256Hex(blob: Blob): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", await blob.arrayBuffer());
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}

async function postJson<T>(url: string, body: unknown): Promise<T> {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    credentials: "same-origin",
  });
  if (!res.ok) throw new Error(`Request failed (${res.status})`);
  return (await res.json()) as T;
}

async function sleep(ms: number) {
  return new Promise((r) => setTimeout(r, ms));
}

/** The Agent holds bytes up to `size`; the upload must resume from there. */
class ResumeError extends Error {
  constructor(readonly size: number) {
    super("Upload conflict");
  }
}

/**
 * Sends one chunk with a fresh grant. The chunk is sliced and hashed here, from
 * `offset`, so a resumed offset always carries its own bytes and hash.
 */
async function sendChunk(
  file: File,
  uploadId: string,
  offset: number,
  chunkSize: number,
): Promise<number> {
  const end = Math.min(offset + chunkSize, file.size);
  const chunk = file.slice(offset, end);
  const chunkHash = await sha256Hex(chunk);
  const g = await postJson<GrantResponse>(`/api/files/uploads/${uploadId}/grant`, {});
  const res = await fetch(`${g.agentUrl}?${g.grant}&offset=${offset}`, {
    method: "PATCH",
    headers: { "X-Content-SHA256": chunkHash },
    body: chunk,
  });
  if (res.status === 409) {
    // The Agent already holds bytes up to its reported size.
    const body = (await res.json().catch(() => null)) as { size?: number } | null;
    if (typeof body?.size !== "number") throw new Error("Upload conflict");
    throw new ResumeError(body.size);
  }
  if (!res.ok) throw new Error(`Chunk upload failed (${res.status})`);
  return end;
}

export async function uploadFile(
  file: File,
  onProgress?: (sentBytes: number, totalBytes: number) => void,
): Promise<{ fileId: string }> {
  const init = await postJson<InitResponse>("/api/files/uploads", {
    name: file.name,
    mimeType: file.type || "application/octet-stream",
    size: file.size,
  });
  const sha256 = await sha256Hex(file);

  // One attempt counter covers chunk failures and 409 resumes alike, so the loop always ends.
  let offset = 0;
  let attempt = 0;
  while (offset < file.size) {
    try {
      offset = await sendChunk(file, init.uploadId, offset, init.chunkSize);
      attempt = 0;
      onProgress?.(offset, file.size);
    } catch (err) {
      attempt++;
      if (attempt > MAX_RETRIES) throw err;
      if (err instanceof ResumeError) {
        offset = err.size;
      } else {
        await sleep(Math.min(8000, 500 * 2 ** attempt));
      }
    }
  }

  await postJson(`/api/files/uploads/${init.uploadId}/complete`, { sha256 });
  return { fileId: init.fileId };
}
