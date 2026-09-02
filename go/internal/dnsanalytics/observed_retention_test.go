package dnsanalytics

import (
	"context"
	"testing"
	"time"
)

// TestCleanStaleClientsOnlyRemovesClientsOlderThanCutoff is the core
// safety property Observed Clients retention depends on: a client is
// removed only once its OWN most recent query is older than the cutoff,
// never based on its earliest rows -- a recently-seen client's full
// history (however old parts of it are) must survive untouched.
func TestCleanStaleClientsOnlyRemovesClientsOlderThanCutoff(t *testing.T) {
	db := openTestDB(t)
	r := &Reader{DB: db}
	ctx := context.Background()
	now := time.Now().Unix()

	staleOnly := int64(now - 200*24*60*60) // 200 days ago, never seen since
	insertEventClient(t, db, staleOnly, "10.0.0.1", "old.example.com", OutcomeAllowed)

	// Recently-seen client with an OLD row too -- the old row must
	// survive, because this client's most recent query is recent.
	insertEventClient(t, db, staleOnly, "10.0.0.2", "old.example.com", OutcomeAllowed)
	insertEventClient(t, db, now, "10.0.0.2", "new.example.com", OutcomeAllowed)

	cutoff := now - 90*24*60*60 // 90-day retention window

	preview, err := r.PreviewStaleClients(ctx, cutoff)
	if err != nil {
		t.Fatal(err)
	}
	if preview != 1 {
		t.Fatalf("PreviewStaleClients = %d, want 1 (only 10.0.0.1)", preview)
	}

	removed, err := r.CleanStaleClients(ctx, cutoff)
	if err != nil {
		t.Fatal(err)
	}
	if removed != 1 {
		t.Fatalf("CleanStaleClients removed %d clients, want 1", removed)
	}

	var staleCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM query_events WHERE client = ?`, "10.0.0.1").Scan(&staleCount); err != nil {
		t.Fatal(err)
	}
	if staleCount != 0 {
		t.Fatalf("expected the stale client's rows to be gone, found %d", staleCount)
	}

	var survivorCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM query_events WHERE client = ?`, "10.0.0.2").Scan(&survivorCount); err != nil {
		t.Fatal(err)
	}
	if survivorCount != 2 {
		t.Fatalf("expected the recently-seen client's full history (including its old row) to survive untouched, found %d rows, want 2", survivorCount)
	}
}

func TestCleanStaleClientsNoStaleClientsIsANoOp(t *testing.T) {
	db := openTestDB(t)
	r := &Reader{DB: db}
	ctx := context.Background()
	now := time.Now().Unix()
	insertEventClient(t, db, now, "10.0.0.5", "example.com", OutcomeAllowed)

	removed, err := r.CleanStaleClients(ctx, now-90*24*60*60)
	if err != nil {
		t.Fatal(err)
	}
	if removed != 0 {
		t.Fatalf("expected zero clients removed when nothing is stale, got %d", removed)
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM query_events`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expected the one real row to survive, found %d", count)
	}
}
