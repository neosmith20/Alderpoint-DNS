package httpapi

import "testing"

func TestSubscriptionIDFromNameLowercasesFirst(t *testing.T) {
	id := subscriptionIDFromName("Test List")
	if id[0] != 't' {
		t.Fatalf("subscriptionIDFromName(%q) = %q, want to start with lowercase 'test-list-...'", "Test List", id)
	}
	want := "test-list-"
	if len(id) < len(want) || id[:len(want)] != want {
		t.Fatalf("subscriptionIDFromName(%q) = %q, want prefix %q", "Test List", id, want)
	}
}

func TestSubscriptionIDFromNameIsUnique(t *testing.T) {
	a := subscriptionIDFromName("Same Name")
	b := subscriptionIDFromName("Same Name")
	if a == b {
		t.Error("two calls with the same name should produce different ids (time-based suffix)")
	}
}
