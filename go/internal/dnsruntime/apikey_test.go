package dnsruntime

import (
	"context"
	"testing"
)

func TestLoadOrCreateDnsdistAPIKeyPersistsAcrossCalls(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	first, err := LoadOrCreateDnsdistAPIKey(ctx, db)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	if first == "" {
		t.Fatal("expected a real generated key, got empty string")
	}

	// A second call -- simulating a fresh process start against the same
	// database, exactly the real-world case this fix targets -- must
	// return the SAME key, not generate a new one.
	second, err := LoadOrCreateDnsdistAPIKey(ctx, db)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if second != first {
		t.Fatalf("key changed across calls: first=%q second=%q -- this is the exact regression the persistence fix closes", first, second)
	}
}

func TestLoadOrCreateDnsdistAPIKeyGeneratesDistinctKeysPerDatabase(t *testing.T) {
	ctx := context.Background()
	dbA := newTestDB(t)
	dbB := newTestDB(t)

	keyA, err := LoadOrCreateDnsdistAPIKey(ctx, dbA)
	if err != nil {
		t.Fatalf("db A: %v", err)
	}
	keyB, err := LoadOrCreateDnsdistAPIKey(ctx, dbB)
	if err != nil {
		t.Fatalf("db B: %v", err)
	}
	if keyA == keyB {
		t.Fatalf("expected distinct random keys for two independent databases, got the same value twice: %q", keyA)
	}
}
