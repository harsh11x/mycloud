// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, fireEvent, waitFor, cleanup } from "@testing-library/react";
import FilesPanel from "./files-panel";

type Json = Record<string, unknown>;

function jsonResponse(body: Json, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

const sampleFile = {
  id: "f1",
  name: "report.pdf",
  mimeType: "application/pdf",
  sizeBytes: 2048,
  sha256: "ab".repeat(32),
  createdAt: "2026-01-01T00:00:00.000Z",
};

let fetchMock: ReturnType<typeof vi.fn>;
let assignMock: ReturnType<typeof vi.fn>;

beforeEach(() => {
  fetchMock = vi.fn();
  vi.stubGlobal("fetch", fetchMock);
  assignMock = vi.fn();
  // jsdom's location is not configurable; swap the whole object for the test.
  vi.stubGlobal("location", { ...window.location, assign: assignMock });
  Object.defineProperty(window, "location", {
    configurable: true,
    value: { assign: assignMock },
  });
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

/** Routes fetch calls by URL and method so each test only describes what it needs. */
function route(handlers: Record<string, (init?: RequestInit) => Response | Promise<Response>>) {
  fetchMock.mockImplementation(async (url: string, init?: RequestInit) => {
    const method = init?.method ?? "GET";
    const key = `${method} ${url}`;
    const handler = handlers[key];
    if (!handler) throw new Error(`Unexpected fetch: ${key}`);
    return handler(init);
  });
}

describe("FilesPanel", () => {
  it("lists the user's files on load", async () => {
    route({ "GET /api/files": () => jsonResponse({ files: [sampleFile] }) });

    render(<FilesPanel />);

    expect(await screen.findByText("report.pdf")).toBeTruthy();
    expect(screen.getByText("2,048 B")).toBeTruthy();
  });

  it("shows an empty state when there are no files", async () => {
    route({ "GET /api/files": () => jsonResponse({ files: [] }) });

    render(<FilesPanel />);

    expect(await screen.findByText("No files yet.")).toBeTruthy();
  });

  it("reports a load failure", async () => {
    route({ "GET /api/files": () => new Response("nope", { status: 500 }) });

    render(<FilesPanel />);

    expect(await screen.findByText("Could not load files (500).")).toBeTruthy();
  });

  it("uploads a picked file through init, grant, chunk PATCH and complete, then refreshes the list", async () => {
    let listCalls = 0;
    const agentUrl = "http://agent.test/v1/upload/u1";
    route({
      "GET /api/files": () => {
        listCalls++;
        return jsonResponse({ files: listCalls > 1 ? [sampleFile] : [] });
      },
      "POST /api/files/uploads": () =>
        jsonResponse({ uploadId: "u1", fileId: "f1", chunkSize: 1024 * 1024 }),
      "POST /api/files/uploads/u1/grant": () =>
        jsonResponse({ agentUrl, grant: "g=abc", fileId: "f1" }),
      [`PATCH ${agentUrl}?g=abc&offset=0`]: () => new Response(null, { status: 200 }),
      "POST /api/files/uploads/u1/complete": () => jsonResponse({ ok: true }),
    });

    const { container } = render(<FilesPanel />);
    await screen.findByText("No files yet.");

    const input = container.querySelector('input[type="file"]') as HTMLInputElement;
    const file = new File(["hello world"], "report.pdf", { type: "application/pdf" });
    fireEvent.change(input, { target: { files: [file] } });

    expect(await screen.findByText("Uploaded report.pdf.")).toBeTruthy();
    expect(await screen.findByText("report.pdf")).toBeTruthy();

    const calls = fetchMock.mock.calls.map(([url, init]) => `${init?.method ?? "GET"} ${url}`);
    expect(calls).toEqual([
      "GET /api/files",
      "POST /api/files/uploads",
      "POST /api/files/uploads/u1/grant",
      `PATCH ${agentUrl}?g=abc&offset=0`,
      "POST /api/files/uploads/u1/complete",
      "GET /api/files",
    ]);

    // The chunk is sent with a SHA-256 header, and completion carries the whole-file hash.
    const patch = fetchMock.mock.calls[3][1] as RequestInit;
    expect((patch.headers as Record<string, string>)["X-Content-SHA256"]).toMatch(/^[0-9a-f]{64}$/);
    const complete = JSON.parse(fetchMock.mock.calls[4][1].body as string) as { sha256: string };
    expect(complete.sha256).toMatch(/^[0-9a-f]{64}$/);
  });

  it("reports an upload failure when the init request is rejected", async () => {
    route({
      "GET /api/files": () => jsonResponse({ files: [] }),
      "POST /api/files/uploads": () => new Response("too big", { status: 413 }),
    });

    const { container } = render(<FilesPanel />);
    await screen.findByText("No files yet.");

    const input = container.querySelector('input[type="file"]') as HTMLInputElement;
    fireEvent.change(input, {
      target: { files: [new File(["x"], "big.bin")] },
    });

    expect(await screen.findByText("Upload failed: Request failed (413)")).toBeTruthy();
  });

  it("downloads by requesting a grant URL and navigating to it", async () => {
    const grantUrl = "http://agent.test/v1/download/f1?g=dl1";
    route({
      "GET /api/files": () => jsonResponse({ files: [sampleFile] }),
      "GET /api/files/f1/download": () => jsonResponse({ url: grantUrl, name: "report.pdf" }),
    });

    render(<FilesPanel />);
    fireEvent.click(await screen.findByRole("button", { name: "Download" }));

    await waitFor(() => expect(assignMock).toHaveBeenCalledWith(grantUrl));
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/files/f1/download",
      expect.objectContaining({ credentials: "same-origin", cache: "no-store" }),
    );
  });

  it("reports a download failure without navigating", async () => {
    route({
      "GET /api/files": () => jsonResponse({ files: [sampleFile] }),
      "GET /api/files/f1/download": () => new Response("gone", { status: 404 }),
    });

    render(<FilesPanel />);
    fireEvent.click(await screen.findByRole("button", { name: "Download" }));

    expect(await screen.findByText("Download failed (404).")).toBeTruthy();
    expect(assignMock).not.toHaveBeenCalled();
  });

  it("deletes after confirmation and refreshes the list", async () => {
    let listCalls = 0;
    route({
      "GET /api/files": () => {
        listCalls++;
        return jsonResponse({ files: listCalls === 1 ? [sampleFile] : [] });
      },
      "DELETE /api/files/f1": () => jsonResponse({ ok: true }),
    });
    const confirmMock = vi.spyOn(window, "confirm").mockReturnValue(true);

    render(<FilesPanel />);
    fireEvent.click(await screen.findByRole("button", { name: "Delete" }));

    expect(confirmMock).toHaveBeenCalledWith("Delete report.pdf permanently?");
    expect(await screen.findByText("No files yet.")).toBeTruthy();
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/files/f1",
      expect.objectContaining({ method: "DELETE", credentials: "same-origin" }),
    );
  });

  it("does nothing when the delete confirmation is cancelled", async () => {
    route({ "GET /api/files": () => jsonResponse({ files: [sampleFile] }) });
    vi.spyOn(window, "confirm").mockReturnValue(false);

    render(<FilesPanel />);
    fireEvent.click(await screen.findByRole("button", { name: "Delete" }));

    expect(screen.getByText("report.pdf")).toBeTruthy();
    const deleteCalls = fetchMock.mock.calls.filter(([, init]) => init?.method === "DELETE");
    expect(deleteCalls).toHaveLength(0);
  });

  it("reports a delete failure and keeps the row", async () => {
    route({
      "GET /api/files": () => jsonResponse({ files: [sampleFile] }),
      "DELETE /api/files/f1": () => new Response("err", { status: 500 }),
    });
    vi.spyOn(window, "confirm").mockReturnValue(true);

    render(<FilesPanel />);
    fireEvent.click(await screen.findByRole("button", { name: "Delete" }));

    expect(await screen.findByText("Delete failed (500).")).toBeTruthy();
    expect(screen.getByText("report.pdf")).toBeTruthy();
  });
});
