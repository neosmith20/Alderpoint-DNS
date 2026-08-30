package softwareupdates

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"

	"alderpointdns/go-controlplane/internal/dbmigrate"
)

func newTestService(t *testing.T) *Service {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := dbmigrate.Up(context.Background(), db, "../../schema/migrations"); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return &Service{DB: db}
}

func TestGetReturnsSeedDefaults(t *testing.T) {
	s := newTestService(t)
	cs, err := s.Get(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if cs.RepoOwner != "neosmith20" || cs.RepoName != "Alderpoint-DNS" {
		t.Fatalf("expected the real seeded repo coordinates, got %+v", cs)
	}
	if cs.HasToken {
		t.Fatal("expected no token by default")
	}
}

func TestSetChannelUpdatesCoordinatesAndPreservesTokenWhenNotGiven(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	if err := s.SetChannel(ctx, "someone", "somerepo", "secret-token", false); err != nil {
		t.Fatal(err)
	}
	cs, _ := s.Get(ctx)
	if cs.RepoOwner != "someone" || cs.RepoName != "somerepo" || !cs.HasToken {
		t.Fatalf("unexpected state after set: %+v", cs)
	}
	// Re-saving owner/repo alone (empty token) must not wipe the
	// previously-set token.
	if err := s.SetChannel(ctx, "someone", "somerepo-renamed", "", false); err != nil {
		t.Fatal(err)
	}
	cs, _ = s.Get(ctx)
	if cs.RepoName != "somerepo-renamed" || !cs.HasToken {
		t.Fatalf("expected token preserved across a token-less re-save, got %+v", cs)
	}
	if err := s.SetChannel(ctx, "someone", "somerepo-renamed", "", true); err != nil {
		t.Fatal(err)
	}
	cs, _ = s.Get(ctx)
	if cs.HasToken {
		t.Fatal("expected clear_token=true to actually clear the token")
	}
}

func TestSetChannelRejectsEmptyCoordinates(t *testing.T) {
	s := newTestService(t)
	if err := s.SetChannel(context.Background(), "", "repo", "", false); err == nil {
		t.Fatal("expected a validation error for an empty repo_owner")
	}
}

func TestCheckNowParsesRealGitHubReleaseShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/testowner/testrepo/releases/latest" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		fmt.Fprint(w, `{
			"tag_name": "v2.3.1",
			"prerelease": false,
			"draft": false,
			"assets": [
				{"name": "alderpointdns_2.3.1-1_all.deb", "browser_download_url": "https://example.invalid/deb"},
				{"name": "alderpointdns_latest_all.deb", "browser_download_url": "https://example.invalid/deb-latest-alias"},
				{"name": "SHA256SUMS", "browser_download_url": "https://example.invalid/sums"}
			]
		}`)
	}))
	defer srv.Close()

	s := newTestService(t)
	s.SetChannel(context.Background(), "testowner", "testrepo", "", false)
	s.githubAPIBase = srv.URL
	cs, err := s.CheckNow(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if cs.LatestVersion != "2.3.1" {
		t.Fatalf("expected version 2.3.1 (v-prefix stripped), got %q", cs.LatestVersion)
	}
	if cs.LatestDebURL != "https://example.invalid/deb" {
		t.Fatalf("expected the real versioned asset, not the _latest_ alias, got %q", cs.LatestDebURL)
	}
	if cs.LatestDebAssetName != "alderpointdns_2.3.1-1_all.deb" {
		t.Fatalf("unexpected asset name %q", cs.LatestDebAssetName)
	}
	if cs.LatestSHA256SumsURL != "https://example.invalid/sums" {
		t.Fatalf("expected SHA256SUMS url captured, got %q", cs.LatestSHA256SumsURL)
	}
	if cs.LastCheckStatus != "ok" {
		t.Fatalf("expected status ok, got %q (%s)", cs.LastCheckStatus, cs.LastCheckError)
	}
	if cs.LastCheckedAt == "" {
		t.Fatal("expected a real last_checked_at timestamp")
	}
}

func TestCheckNowRecordsARealErrorHonestlyRatherThanSilentlyDropping(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"message":"Not Found"}`)
	}))
	defer srv.Close()

	s := newTestService(t)
	s.SetChannel(context.Background(), "testowner", "testrepo", "", false)
	s.githubAPIBase = srv.URL
	cs, err := s.CheckNow(context.Background())
	if err == nil {
		t.Fatal("expected a real error for a 404 response")
	}
	if cs.LastCheckStatus != "error" || cs.LastCheckError == "" {
		t.Fatalf("expected the error persisted with status=error, got %+v", cs)
	}
}

func TestCheckNowRejectsDraftRelease(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"tag_name":"v9.9.9","draft":true,"assets":[]}`)
	}))
	defer srv.Close()
	s := newTestService(t)
	s.SetChannel(context.Background(), "testowner", "testrepo", "", false)
	s.githubAPIBase = srv.URL
	_, err := s.CheckNow(context.Background())
	if err == nil {
		t.Fatal("expected an error for a draft release")
	}
}

func TestFetchLatestDebVerifiesChecksumAndRejectsMismatch(t *testing.T) {
	debBytes := []byte("fake deb contents for testing")
	sum := sha256.Sum256(debBytes)
	goodHex := hex.EncodeToString(sum[:])

	mux := http.NewServeMux()
	mux.HandleFunc("/deb", func(w http.ResponseWriter, r *http.Request) { w.Write(debBytes) })
	mux.HandleFunc("/sums-good", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s  alderpointdns_1.0.0-1_all.deb\n", goodHex)
	})
	mux.HandleFunc("/sums-bad", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s  alderpointdns_1.0.0-1_all.deb\n", "0000000000000000000000000000000000000000000000000000000000000000"[:64])
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	s := newTestService(t)
	ctx := context.Background()
	s.DB.ExecContext(ctx, `UPDATE update_channel_settings SET latest_version=?, latest_deb_url=?, latest_sha256sums_url=?, latest_deb_asset_name=? WHERE id=1`,
		"1.0.0", srv.URL+"/deb", srv.URL+"/sums-good", "alderpointdns_1.0.0-1_all.deb")
	data, version, gotHex, err := s.FetchLatestDeb(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != string(debBytes) || version != "1.0.0" || gotHex != goodHex {
		t.Fatalf("unexpected fetch result: version=%q hex=%q", version, gotHex)
	}

	s.DB.ExecContext(ctx, `UPDATE update_channel_settings SET latest_sha256sums_url=? WHERE id=1`, srv.URL+"/sums-bad")
	if _, _, _, err := s.FetchLatestDeb(ctx); err == nil {
		t.Fatal("expected a checksum-mismatch error to be refused")
	}
}

func TestFetchLatestDebRequiresAPriorCheck(t *testing.T) {
	s := newTestService(t)
	if _, _, _, err := s.FetchLatestDeb(context.Background()); err == nil {
		t.Fatal("expected an error when no latest_deb_url is known yet")
	}
}

func TestParseSHA256SumsFindsExactFilename(t *testing.T) {
	text := "abc123  other-file.deb\ndef456  alderpointdns_1.0.0-1_all.deb\n"
	got, ok := parseSHA256Sums(text, "alderpointdns_1.0.0-1_all.deb")
	if !ok || got != "def456" {
		t.Fatalf("expected def456, got %q ok=%v", got, ok)
	}
	if _, ok := parseSHA256Sums(text, "nonexistent.deb"); ok {
		t.Fatal("expected not-found for a filename not in the sums file")
	}
}
