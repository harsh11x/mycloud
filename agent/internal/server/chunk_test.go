package server

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

func sizeOf(t *testing.T, res *http.Response) int64 {
	t.Helper()
	var body struct {
		Size int64 `json:"size"`
	}
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("decode size: %v", err)
	}
	return body.Size
}

func TestChunkedAppendAssemblesAndFinalizes(t *testing.T) {
	f := newFixture(t)
	exp := time.Now().Add(time.Minute)
	parts := []string{"hello ", "chunked ", "world"}
	full := strings.Join(parts, "")

	var off int64
	for i, p := range parts {
		qs := f.grant(t, "upload", fileID, userID, "n-chunk-"+strconv.Itoa(i), exp)
		res := f.do(t, http.MethodPatch, "/v1/files/"+fileID+"?offset="+strconv.FormatInt(off, 10)+"&"+qs,
			strings.NewReader(p), map[string]string{"X-Content-SHA256": sum([]byte(p))})
		if res.StatusCode != http.StatusOK {
			t.Fatalf("chunk %d: status %d", i, res.StatusCode)
		}
		off = sizeOf(t, res)
	}
	if off != int64(len(full)) {
		t.Fatalf("size after chunks: want %d got %d", len(full), off)
	}

	fin := f.do(t, http.MethodPost, "/v1/files/"+fileID+"/finalize?"+f.grant(t, "finalize", fileID, userID, "n-fin-ok", exp),
		nil, map[string]string{"X-Content-SHA256": sum([]byte(full))})
	if fin.StatusCode != http.StatusOK {
		t.Fatalf("finalize: status %d", fin.StatusCode)
	}
}

func TestChunkOffsetConflictReturns409WithCurrentSize(t *testing.T) {
	f := newFixture(t)
	exp := time.Now().Add(time.Minute)
	first := "abcdef"
	res := f.do(t, http.MethodPatch, "/v1/files/"+fileID+"?offset=0&"+f.grant(t, "upload", fileID, userID, "n-c0", exp),
		strings.NewReader(first), map[string]string{"X-Content-SHA256": sum([]byte(first))})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("first chunk: %d", res.StatusCode)
	}
	// Client wrongly assumes offset 0 again; server must refuse and report size 6.
	res = f.do(t, http.MethodPatch, "/v1/files/"+fileID+"?offset=0&"+f.grant(t, "upload", fileID, userID, "n-c1", exp),
		strings.NewReader("zz"), map[string]string{"X-Content-SHA256": sum([]byte("zz"))})
	if res.StatusCode != http.StatusConflict {
		t.Fatalf("offset conflict: want 409, got %d", res.StatusCode)
	}
	if got := sizeOf(t, res); got != int64(len(first)) {
		t.Fatalf("409 size: want %d got %d", len(first), got)
	}
}

func TestRetriedChunkAfterSuccessIsRejectedWithoutCorruption(t *testing.T) {
	f := newFixture(t)
	exp := time.Now().Add(time.Minute)
	c := "part"
	res := f.do(t, http.MethodPatch, "/v1/files/"+fileID+"?offset=0&"+f.grant(t, "upload", fileID, userID, "n-r0", exp),
		strings.NewReader(c), map[string]string{"X-Content-SHA256": sum([]byte(c))})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("chunk: %d", res.StatusCode)
	}
	// Network retry of the same chunk with a fresh grant: must not duplicate bytes.
	res = f.do(t, http.MethodPatch, "/v1/files/"+fileID+"?offset=0&"+f.grant(t, "upload", fileID, userID, "n-r1", exp),
		strings.NewReader(c), map[string]string{"X-Content-SHA256": sum([]byte(c))})
	if res.StatusCode != http.StatusConflict {
		t.Fatalf("retry: want 409, got %d", res.StatusCode)
	}
	fin := f.do(t, http.MethodPost, "/v1/files/"+fileID+"/finalize?"+f.grant(t, "finalize", fileID, userID, "n-r-fin", exp),
		nil, map[string]string{"X-Content-SHA256": sum([]byte(c))})
	if fin.StatusCode != http.StatusOK {
		t.Fatalf("finalize after retry: %d", fin.StatusCode)
	}
}

func TestChunkChecksumMismatchRejected(t *testing.T) {
	f := newFixture(t)
	exp := time.Now().Add(time.Minute)
	res := f.do(t, http.MethodPatch, "/v1/files/"+fileID+"?offset=0&"+f.grant(t, "upload", fileID, userID, "n-cm", exp),
		strings.NewReader("data"), map[string]string{"X-Content-SHA256": sum([]byte("other"))})
	if res.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("chunk checksum: want 422, got %d", res.StatusCode)
	}
}

func TestFinalizeChecksumMismatchDeletesFile(t *testing.T) {
	f := newFixture(t)
	exp := time.Now().Add(time.Minute)
	data := "complete"
	res := f.do(t, http.MethodPatch, "/v1/files/"+fileID+"?offset=0&"+f.grant(t, "upload", fileID, userID, "n-fm0", exp),
		strings.NewReader(data), map[string]string{"X-Content-SHA256": sum([]byte(data))})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("chunk: %d", res.StatusCode)
	}
	fin := f.do(t, http.MethodPost, "/v1/files/"+fileID+"/finalize?"+f.grant(t, "finalize", fileID, userID, "n-fm1", exp),
		nil, map[string]string{"X-Content-SHA256": sum([]byte("wrong"))})
	if fin.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("finalize mismatch: want 422, got %d", fin.StatusCode)
	}
	var left int
	_ = walk(f.root, func(string) { left++ })
	if left != 0 {
		t.Fatalf("file should be deleted after checksum mismatch, found %d", left)
	}
}

func TestDownloadRangeReturnsPartialContent(t *testing.T) {
	f := newFixture(t)
	exp := time.Now().Add(time.Minute)
	data := "0123456789"
	up := f.do(t, http.MethodPut, "/v1/files/"+fileID+"?"+f.grant(t, "upload", fileID, userID, "n-rg-up", exp),
		strings.NewReader(data), map[string]string{"X-Content-SHA256": sum([]byte(data))})
	if up.StatusCode != http.StatusOK {
		t.Fatalf("upload: %d", up.StatusCode)
	}
	res := f.do(t, http.MethodGet, "/v1/files/"+fileID+"?"+f.grant(t, "download", fileID, userID, "n-rg-dl", exp),
		nil, map[string]string{"Range": "bytes=2-5"})
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusPartialContent {
		t.Fatalf("range: want 206, got %d", res.StatusCode)
	}
	if string(body) != "2345" {
		t.Fatalf("range body: want 2345 got %q", body)
	}
	if cr := res.Header.Get("Content-Range"); cr != "bytes 2-5/10" {
		t.Fatalf("Content-Range: %q", cr)
	}
}
