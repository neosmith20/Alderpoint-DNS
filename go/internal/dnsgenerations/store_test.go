package dnsgenerations

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"alderpointdns/go-controlplane/internal/dbmigrate"

	_ "modernc.org/sqlite"
)

func newTestStore(t *testing.T) *Store {
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
	return &Store{DB: db}
}

func TestRecordAssignsSequentialGenerationNumbers(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	n1, err := s.Record(ctx, RecordInput{Trigger: "apply", Promoted: true, DnsdistConf: "conf-v1"})
	if err != nil {
		t.Fatal(err)
	}
	n2, err := s.Record(ctx, RecordInput{Trigger: "apply", Promoted: true, DnsdistConf: "conf-v2"})
	if err != nil {
		t.Fatal(err)
	}
	if n1 != 1 || n2 != 2 {
		t.Fatalf("expected sequential generation numbers 1, 2, got %d, %d", n1, n2)
	}
}

func TestOnlyPromotedGenerationsGetASavedSnapshot(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if _, err := s.Record(ctx, RecordInput{Trigger: "apply", Promoted: false, DnsdistConf: "should-not-be-saved", Error: "validation failed"}); err != nil {
		t.Fatal(err)
	}
	history, err := s.History(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 1 || history[0].HasSnapshot {
		t.Fatalf("expected a failed attempt to have no saved snapshot, got %+v", history)
	}
}

func TestLatestAndPreviousPromoted(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if _, err := s.Record(ctx, RecordInput{Trigger: "apply", Promoted: true, DnsdistConf: "conf-v1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Record(ctx, RecordInput{Trigger: "apply", Promoted: false, Error: "oops"}); err != nil { // a failed attempt in between must not count as "promoted"
		t.Fatal(err)
	}
	if _, err := s.Record(ctx, RecordInput{Trigger: "apply", Promoted: true, DnsdistConf: "conf-v2"}); err != nil {
		t.Fatal(err)
	}

	latest, err := s.LatestPromoted(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if latest == nil || latest.GenerationNumber != 3 {
		t.Fatalf("expected the latest PROMOTED generation to be #3 (skipping the failed #2), got %+v", latest)
	}

	prev, err := s.PreviousPromoted(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if prev == nil || prev.GenerationNumber != 1 {
		t.Fatalf("expected the previous promoted generation to be #1, got %+v", prev)
	}

	conf, err := s.SnapshotConf(ctx, prev.GenerationNumber)
	if err != nil {
		t.Fatal(err)
	}
	if conf != "conf-v1" {
		t.Fatalf("SnapshotConf = %q, want the real saved conf-v1", conf)
	}
}

func TestNoPromotedGenerationsIsHonestlyNil(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	latest, err := s.LatestPromoted(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if latest != nil {
		t.Fatalf("expected nil with no promoted generations yet, got %+v", latest)
	}
}
