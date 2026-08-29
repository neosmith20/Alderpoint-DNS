package httpapi

// HTTP-layer proof for GET/POST /api/blocklists/categories,
// POST /api/blocklists/categories/{id}/rename, and
// DELETE /api/blocklists/categories/{id}.

import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"path/filepath"
	"strconv"
	"testing"

	"alderpointdns/go-controlplane/internal/blocklists"
	"alderpointdns/go-controlplane/internal/dbmigrate"
)

func newBlocklistCategoryTestServer(t *testing.T) *Server {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "control.db")
	db, err := sql.Open("sqlite", dbPath+"?_pragma=busy_timeout(3000)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := dbmigrate.Up(context.Background(), db, "../../schema/migrations"); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return &Server{Blocklists: &blocklists.Service{DB: db}, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

func TestBlocklistCategoryLifecycleHTTP(t *testing.T) {
	s := newBlocklistCategoryTestServer(t)

	// The migration seeds standard/privacy/aggressive, so list should
	// already report at least those three.
	code, body := doHandler(t, s.handleListBlocklistCategories, "GET", "", nil)
	if code != 200 {
		t.Fatalf("list: code=%d body=%+v", code, body)
	}
	seeded, _ := body["categories"].([]any)
	if len(seeded) < 3 {
		t.Fatalf("expected the three seeded categories, got %+v", seeded)
	}

	code, body = doHandler(t, s.handleCreateBlocklistCategory, "POST", `{"name":"Kids Safe"}`, nil)
	if code != 201 {
		t.Fatalf("create: code=%d body=%+v", code, body)
	}
	id := int64(body["id"].(float64))
	if body["name"] != "Kids Safe" {
		t.Fatalf("unexpected created category: %+v", body)
	}

	code, _ = doHandler(t, s.handleRenameBlocklistCategory, "POST", `{"name":"Kids Safe Plus"}`,
		map[string]string{"id": strconv.FormatInt(id, 10)})
	if code != 200 {
		t.Fatalf("rename: code=%d", code)
	}
	_, body = doHandler(t, s.handleListBlocklistCategories, "GET", "", nil)
	list, _ := body["categories"].([]any)
	found := false
	for _, c := range list {
		m := c.(map[string]any)
		if m["id"] == float64(id) {
			found = true
			if m["name"] != "Kids Safe Plus" {
				t.Fatalf("rename did not persist: %+v", m)
			}
		}
	}
	if !found {
		t.Fatalf("renamed category missing from list: %+v", list)
	}

	code, _ = doHandler(t, s.handleDeleteBlocklistCategory, "DELETE", "", map[string]string{"id": strconv.FormatInt(id, 10)})
	if code != 200 {
		t.Fatalf("delete: code=%d", code)
	}
	_, body = doHandler(t, s.handleListBlocklistCategories, "GET", "", nil)
	list, _ = body["categories"].([]any)
	for _, c := range list {
		if c.(map[string]any)["id"] == float64(id) {
			t.Fatalf("expected category to be gone after delete, still present: %+v", list)
		}
	}
}

func TestBlocklistCategoryDeleteInUseReturnsConflict(t *testing.T) {
	s := newBlocklistCategoryTestServer(t)
	if _, err := s.Blocklists.DB.ExecContext(context.Background(),
		`INSERT INTO blocklist_subscriptions (subscription_id, name, url, category, created_at) VALUES ('sub1', 'Sub 1', 'https://example.com/list.txt', 'standard', '2024-01-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	cats, err := s.Blocklists.ListCategories(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var standardID int64
	for _, c := range cats {
		if c.Name == "standard" {
			standardID = c.ID
		}
	}
	if standardID == 0 {
		t.Fatalf("expected a seeded 'standard' category, got %+v", cats)
	}
	code, body := doHandler(t, s.handleDeleteBlocklistCategory, "DELETE", "", map[string]string{"id": strconv.FormatInt(standardID, 10)})
	if code != 409 {
		t.Fatalf("expected 409 Conflict, got code=%d body=%+v", code, body)
	}
}

func TestBlocklistCategoryCreateRejectsEmptyName(t *testing.T) {
	s := newBlocklistCategoryTestServer(t)
	code, _ := doHandler(t, s.handleCreateBlocklistCategory, "POST", `{"name":"  "}`, nil)
	if code != 400 {
		t.Fatalf("expected 400, got %d", code)
	}
}

func TestBlocklistCategoryRenameNotFound(t *testing.T) {
	s := newBlocklistCategoryTestServer(t)
	code, _ := doHandler(t, s.handleRenameBlocklistCategory, "POST", `{"name":"whatever"}`, map[string]string{"id": "999999"})
	if code != 404 {
		t.Fatalf("expected 404, got %d", code)
	}
}
