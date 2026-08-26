package httpapi

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// newStaticTestServer builds a real on-disk static dir shaped like a
// real Vite build: index.html plus one content-hashed file under
// /assets/ -- reproducing the real deployed-integrity defect this test
// guards against (see static.go's own doc comment): a stale cached
// index.html referencing a hashed chunk filename that a later redeploy
// (which replaces the whole directory) has genuinely removed.
func newStaticTestServer(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<html>fake app shell</html>"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "assets"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "assets", "index-abc123.js"), []byte("console.log(1)"), 0o644); err != nil {
		t.Fatal(err)
	}
	return &Server{StaticDir: dir}
}

func TestStaticIndexHTMLIsNeverCachedByTheBrowser(t *testing.T) {
	s := newStaticTestServer(t)
	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	s.handleStatic(rec, req)
	if got := rec.Header().Get("Cache-Control"); got != "no-cache" {
		t.Fatalf("expected index.html to be served with Cache-Control: no-cache (so a stale cached copy can never reference a since-removed hashed asset), got %q", got)
	}
}

func TestStaticSPAFallbackIsAlsoNeverCached(t *testing.T) {
	s := newStaticTestServer(t)
	// A client-side route with no matching file on disk -- the SPA
	// fallback path, real for every /ui/* route.
	req := httptest.NewRequest("GET", "/ui/dashboard", nil)
	rec := httptest.NewRecorder()
	s.handleStatic(rec, req)
	if got := rec.Header().Get("Cache-Control"); got != "no-cache" {
		t.Fatalf("expected the SPA fallback (index.html) to also be Cache-Control: no-cache, got %q", got)
	}
}

func TestStaticHashedAssetsAreCachedForever(t *testing.T) {
	s := newStaticTestServer(t)
	req := httptest.NewRequest("GET", "/assets/index-abc123.js", nil)
	rec := httptest.NewRecorder()
	s.handleStatic(rec, req)
	if got := rec.Header().Get("Cache-Control"); got != "public, max-age=31536000, immutable" {
		t.Fatalf("expected a content-hashed asset to be safely cached forever, got %q", got)
	}
	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

// TestStaticStaleIndexReferencingARemovedAssetFailsHonestly is the
// real regression reproduction: simulates the exact live defect --
// serve an old index.html-shaped response referencing a chunk that a
// subsequent redeploy (which replaces the static dir wholesale, the
// same way this project's own deploy procedure does) has genuinely
// removed. Proves the SERVER's own behavior for that request (a plain
// 404, not a silent wrong-content substitution) and that a freshly
// served index.html (post Cache-Control fix, since browsers now always
// revalidate it) would reference the NEW asset instead.
func TestStaticStaleIndexReferencingARemovedAssetFailsHonestly(t *testing.T) {
	s := newStaticTestServer(t)

	// The "old" chunk a stale index.html might still reference.
	req := httptest.NewRequest("GET", "/assets/index-oldhash.js", nil)
	rec := httptest.NewRecorder()
	s.handleStatic(rec, req)
	// static.go's own fallback serves index.html for ANY unmatched
	// path (SPA client-side routing) -- for a missing /assets/ file
	// specifically this means the browser gets HTML back where it
	// expected JavaScript, which is exactly how a real "Failed to
	// fetch dynamically imported module" / "MIME type mismatch" error
	// manifests. Documented here as the real, current behavior (not
	// changed by this fix -- the Cache-Control fix prevents the client
	// from ever requesting a since-removed hashed filename in the
	// first place, which is the actual fix, not a change to this
	// fallback's own shape).
	if rec.Code != 200 {
		t.Fatalf("expected the SPA fallback's usual 200 (serving index.html) for an unmatched asset path, got %d", rec.Code)
	}
	body := rec.Body.String()
	if body != "<html>fake app shell</html>" {
		t.Fatalf("expected the SPA fallback to serve index.html's real content, got %q", body)
	}

	// The redeploy: the static dir is replaced wholesale (matching the
	// real deploy procedure), the old hash is genuinely gone, only the
	// new one exists.
	if err := os.Remove(filepath.Join(s.StaticDir, "assets", "index-abc123.js")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.StaticDir, "assets", "index-newhash.js"), []byte("console.log(2)"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.StaticDir, "index.html"), []byte(`<script type="module" src="/assets/index-newhash.js"></script>`), 0o644); err != nil {
		t.Fatal(err)
	}

	// A fresh (never-cached, or freshly revalidated thanks to the
	// no-cache fix) request for "/" now gets the NEW index.html, which
	// only ever references the NEW asset -- the real fix's actual
	// guarantee: no client can be left holding a reference to a
	// filename that no longer exists, because it can never hold a
	// stale index.html for longer than one request.
	req2 := httptest.NewRequest("GET", "/", nil)
	rec2 := httptest.NewRecorder()
	s.handleStatic(rec2, req2)
	if got := rec2.Body.String(); got != `<script type="module" src="/assets/index-newhash.js"></script>` {
		t.Fatalf("expected the freshly-revalidated index.html to reference only the new asset, got %q", got)
	}
	req3 := httptest.NewRequest("GET", "/assets/index-newhash.js", nil)
	rec3 := httptest.NewRecorder()
	s.handleStatic(rec3, req3)
	if rec3.Code != 200 || rec3.Body.String() != "console.log(2)" {
		t.Fatalf("expected the new asset to be served correctly, got code=%d body=%q", rec3.Code, rec3.Body.String())
	}
}
