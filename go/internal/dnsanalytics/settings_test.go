package dnsanalytics

import "testing"

func TestAnonymizeClientFull(t *testing.T) {
	got := anonymizeClient("203.0.113.9", "full", "truncate", "secret")
	if got != "203.0.113.9" {
		t.Fatalf("full mode must never modify the client, got %q", got)
	}
}

func TestAnonymizeClientTruncateIPv4(t *testing.T) {
	got := anonymizeClient("203.0.113.9", "anonymized_clients", "truncate", "secret")
	if got != "203.0.113.0/24" {
		t.Fatalf("expected the containing /24, got %q", got)
	}
}

func TestAnonymizeClientTruncateIPv6(t *testing.T) {
	got := anonymizeClient("2001:db8::9", "anonymized_clients", "truncate", "secret")
	if got != "2001:db8::/64" {
		t.Fatalf("expected the containing /64, got %q", got)
	}
}

func TestAnonymizeClientHashIsStableAndDistinct(t *testing.T) {
	a := anonymizeClient("203.0.113.9", "anonymized_clients", "hash", "secret")
	b := anonymizeClient("203.0.113.9", "anonymized_clients", "hash", "secret")
	c := anonymizeClient("203.0.113.20", "anonymized_clients", "hash", "secret")
	if a != b {
		t.Fatalf("hash must be stable for the same input+secret: %q != %q", a, b)
	}
	if a == c {
		t.Fatalf("different clients must not collide: both hashed to %q", a)
	}
	if a[:5] != "anon-" || len(a) != 21 {
		t.Fatalf("expected 'anon-' + 16 hex chars, got %q", a)
	}
}

func TestAnonymizeClientHashDiffersBySecret(t *testing.T) {
	a := anonymizeClient("203.0.113.9", "anonymized_clients", "hash", "secret-one")
	b := anonymizeClient("203.0.113.9", "anonymized_clients", "hash", "secret-two")
	if a == b {
		t.Fatalf("changing the secret must change the hash")
	}
}

func TestAnonymizeClientTruncateFallsBackToHashForNonIP(t *testing.T) {
	got := anonymizeClient("not-an-ip", "anonymized_clients", "truncate", "secret")
	if got[:5] != "anon-" {
		t.Fatalf("a value that doesn't parse as an IP must fall back to hashing, got %q", got)
	}
}

func TestApplySettingsAnalyticsDisabledDropsEvent(t *testing.T) {
	wtr := &Writer{Settings: NewSettingsHolder(Settings{AnalyticsEnabled: false})}
	_, keep := wtr.applySettings(event{domain: "example.com.", client: "203.0.113.9"})
	if keep {
		t.Fatal("expected the event to be dropped when analytics_enabled=false")
	}
}

func TestApplySettingsFullModeKeepsEverything(t *testing.T) {
	s := DefaultSettings()
	wtr := &Writer{Settings: NewSettingsHolder(s)}
	ev, keep := wtr.applySettings(event{domain: "example.com.", client: "203.0.113.9"})
	if !keep {
		t.Fatal("expected the event to be kept in full/detailed mode")
	}
	if ev.domain != "example.com." || ev.client != "203.0.113.9" {
		t.Fatalf("full mode must not modify domain/client, got %+v", ev)
	}
}

func TestApplySettingsAggregateOnlyBlanksDomainAndAnonymizesClient(t *testing.T) {
	s := DefaultSettings()
	s.PrivacyMode = "aggregate_only"
	wtr := &Writer{Settings: NewSettingsHolder(s), AnonymizationSecret: "secret"}
	ev, keep := wtr.applySettings(event{domain: "example.com.", client: "203.0.113.9", qtype: "A"})
	if !keep {
		t.Fatal("aggregate_only must still keep the row (just less identifying), not drop it")
	}
	if ev.domain != "" {
		t.Fatalf("aggregate_only must blank the domain, got %q", ev.domain)
	}
	if ev.client == "203.0.113.9" {
		t.Fatal("aggregate_only must anonymize the client")
	}
	if ev.qtype != "A" {
		t.Fatal("aggregate_only must not touch unrelated fields like qtype")
	}
}

func TestApplySettingsAnonymizedClientsKeepsDomain(t *testing.T) {
	s := DefaultSettings()
	s.PrivacyMode = "anonymized_clients"
	wtr := &Writer{Settings: NewSettingsHolder(s), AnonymizationSecret: "secret"}
	ev, keep := wtr.applySettings(event{domain: "example.com.", client: "203.0.113.9"})
	if !keep {
		t.Fatal("expected the event to be kept")
	}
	if ev.domain != "example.com." {
		t.Fatalf("anonymized_clients must keep the domain, got %q", ev.domain)
	}
	if ev.client == "203.0.113.9" {
		t.Fatal("anonymized_clients must anonymize the client")
	}
}

func TestApplySettingsDetailedLoggingDisabledBlanksDomainEvenInFullPrivacy(t *testing.T) {
	s := DefaultSettings()
	s.DetailedQueryLoggingEnabled = false
	wtr := &Writer{Settings: NewSettingsHolder(s)}
	ev, keep := wtr.applySettings(event{domain: "example.com.", client: "203.0.113.9"})
	if !keep {
		t.Fatal("expected the event to be kept")
	}
	if ev.domain != "" {
		t.Fatalf("detailed_query_logging_enabled=false must blank the domain, got %q", ev.domain)
	}
	if ev.client != "203.0.113.9" {
		t.Fatal("detailed_query_logging_enabled=false alone (privacy_mode still full) must not touch the client")
	}
}

func TestSettingsHolderNilIsSafeAndDefaults(t *testing.T) {
	var h *SettingsHolder
	got := h.Load()
	want := DefaultSettings()
	if got != want {
		t.Fatalf("nil holder should load DefaultSettings, got %+v want %+v", got, want)
	}
}
