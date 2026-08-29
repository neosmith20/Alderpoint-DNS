package httpapi

// HTTP-layer proof for the Event Subscriptions/Delivery History routes.

import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"alderpointdns/go-controlplane/internal/dbmigrate"
	"alderpointdns/go-controlplane/internal/notifications"
)

func newNotificationsDispatchTestServer(t *testing.T) *Server {
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
	return &Server{Notifications: &notifications.Service{DB: db}, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

func TestHandleListEventCategoriesReturnsTheRealFixedList(t *testing.T) {
	s := newNotificationsDispatchTestServer(t)
	code, body := doHandler(t, s.handleListEventCategories, "GET", "", nil)
	if code != 200 {
		t.Fatalf("code = %d", code)
	}
	cats, _ := body["categories"].([]any)
	if len(cats) == 0 {
		t.Fatal("expected a non-empty real event category list")
	}
	found := false
	for _, c := range cats {
		m, _ := c.(map[string]any)
		if m["key"] == "deploy_failure" {
			found = true
			if m["wired"] != true {
				t.Errorf("deploy_failure wired = %v, want true (a real call site fires it)", m["wired"])
			}
		}
	}
	if !found {
		t.Fatalf("expected deploy_failure in the category list, got %+v", cats)
	}
}

func TestNotificationSubscriptionHTTPLifecycle(t *testing.T) {
	s := newNotificationsDispatchTestServer(t)
	ctx := context.Background()
	p, err := s.Notifications.Create(ctx, "webhook", "Ops", nil)
	if err != nil {
		t.Fatal(err)
	}

	code, body := doHandler(t, s.handleCreateNotificationSubscription, "POST",
		`{"provider_id":"`+p.ProviderID+`","event_category":"deploy_failure","min_severity":"critical","enabled":true}`, nil)
	if code != 201 {
		t.Fatalf("create: code=%d body=%+v", code, body)
	}

	code, body = doHandler(t, s.handleListNotificationSubscriptions, "GET", "", nil)
	if code != 200 {
		t.Fatalf("list: code=%d", code)
	}
	subs, _ := body["subscriptions"].([]any)
	if len(subs) != 1 {
		t.Fatalf("subscriptions = %+v, want 1", subs)
	}
	sub, _ := subs[0].(map[string]any)
	if sub["provider_name"] != "Ops" || sub["event_category"] != "deploy_failure" {
		t.Fatalf("unexpected subscription: %+v", sub)
	}
	id := int64(sub["id"].(float64))

	code, _ = doHandler(t, s.handleDeleteNotificationSubscription, "DELETE", "", map[string]string{"id": strconv.FormatInt(id, 10)})
	if code != 200 {
		t.Fatalf("delete: code=%d", code)
	}
	_, body = doHandler(t, s.handleListNotificationSubscriptions, "GET", "", nil)
	subs, _ = body["subscriptions"].([]any)
	if len(subs) != 0 {
		t.Fatalf("expected empty after delete, got %+v", subs)
	}
}

func TestNotificationSubscriptionHTTPRejectsUnknownCategory(t *testing.T) {
	s := newNotificationsDispatchTestServer(t)
	p, err := s.Notifications.Create(context.Background(), "webhook", "Ops", nil)
	if err != nil {
		t.Fatal(err)
	}
	code, body := doHandler(t, s.handleCreateNotificationSubscription, "POST",
		`{"provider_id":"`+p.ProviderID+`","event_category":"not-a-real-category","min_severity":"warning","enabled":true}`, nil)
	if code != 400 {
		t.Fatalf("code = %d, body = %+v, want 400", code, body)
	}
}

func TestNotificationHistoryHTTPReflectsRealDispatchedEntries(t *testing.T) {
	s := newNotificationsDispatchTestServer(t)
	ctx := context.Background()
	p, err := s.Notifications.Create(ctx, "webhook", "Ops", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Notifications.SetSubscription(ctx, p.ProviderID, "deploy_failure", "warning", true, nil); err != nil {
		t.Fatal(err)
	}
	// No secret configured -- Dispatch will record a real "failed" outcome,
	// which is exactly what this test proves reaches the History endpoint.
	if _, err := s.Notifications.Dispatch(ctx, "deploy_failure", "critical", "dns_runtime", "rolled back", false); err != nil {
		t.Fatal(err)
	}

	code, body := doHandler(t, s.handleListNotificationHistory, "GET", "", nil)
	if code != 200 {
		t.Fatalf("code = %d", code)
	}
	history, _ := body["history"].([]any)
	if len(history) != 1 {
		t.Fatalf("history = %+v, want 1 real entry", history)
	}
	entry, _ := history[0].(map[string]any)
	if entry["status"] != "failed" || !strings.Contains(entry["message"].(string), "rolled back") {
		t.Fatalf("unexpected history entry: %+v", entry)
	}
}
