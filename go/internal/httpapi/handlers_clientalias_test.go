package httpapi

// HTTP-layer proof for GET/POST/PATCH/DELETE /api/local-dns/aliases.

import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"path/filepath"
	"strconv"
	"testing"

	"alderpointdns/go-controlplane/internal/clientalias"
	"alderpointdns/go-controlplane/internal/dbmigrate"
)

func newClientAliasTestServer(t *testing.T) *Server {
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
	return &Server{ClientAliases: &clientalias.Service{DB: db}, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

func TestClientAliasLifecycleHTTP(t *testing.T) {
	s := newClientAliasTestServer(t)

	code, body := doHandler(t, s.handleCreateClientAlias, "POST", `{"cidr":"10.0.0.0/8","display_name":"Corp","description":"main office"}`, nil)
	if code != 201 {
		t.Fatalf("create: code=%d body=%+v", code, body)
	}
	alias, _ := body["alias"].(map[string]any)
	if alias["cidr"] != "10.0.0.0/8" || alias["display_name"] != "Corp" {
		t.Fatalf("unexpected created alias: %+v", alias)
	}
	id := int64(alias["id"].(float64))

	code, body = doHandler(t, s.handleListClientAliases, "GET", "", nil)
	if code != 200 {
		t.Fatalf("list: code=%d", code)
	}
	list, _ := body["aliases"].([]any)
	if len(list) != 1 {
		t.Fatalf("list = %+v, want 1", list)
	}

	code, _ = doHandler(t, s.handleUpdateClientAlias, "PATCH", `{"display_name":"Corp Renamed","description":"updated"}`,
		map[string]string{"id": strconv.FormatInt(id, 10)})
	if code != 200 {
		t.Fatalf("update: code=%d", code)
	}
	_, body = doHandler(t, s.handleListClientAliases, "GET", "", nil)
	list, _ = body["aliases"].([]any)
	renamed, _ := list[0].(map[string]any)
	if renamed["display_name"] != "Corp Renamed" {
		t.Errorf("update did not persist: %+v", renamed)
	}

	code, _ = doHandler(t, s.handleDeleteClientAlias, "DELETE", "", map[string]string{"id": strconv.FormatInt(id, 10)})
	if code != 200 {
		t.Fatalf("delete: code=%d", code)
	}
	_, body = doHandler(t, s.handleListClientAliases, "GET", "", nil)
	list, _ = body["aliases"].([]any)
	if len(list) != 0 {
		t.Fatalf("expected empty list after delete, got %+v", list)
	}
}

func TestClientAliasHTTPReportsUnavailableWithNoService(t *testing.T) {
	s := &Server{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	code, _ := doHandler(t, s.handleListClientAliases, "GET", "", nil)
	if code != 503 {
		t.Fatalf("code = %d, want 503", code)
	}
}

func TestClientAliasHTTPRejectsDuplicateCIDR(t *testing.T) {
	s := newClientAliasTestServer(t)
	code, _ := doHandler(t, s.handleCreateClientAlias, "POST", `{"cidr":"10.0.0.0/8","display_name":"Corp"}`, nil)
	if code != 201 {
		t.Fatalf("first create: code=%d", code)
	}
	code, body := doHandler(t, s.handleCreateClientAlias, "POST", `{"cidr":"10.0.0.0/8","display_name":"Corp Again"}`, nil)
	if code != 400 {
		t.Fatalf("duplicate create: code=%d body=%+v, want 400", code, body)
	}
}
