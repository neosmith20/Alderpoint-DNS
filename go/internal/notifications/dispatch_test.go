package notifications

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSetSubscriptionRejectsUnknownEventCategory(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	p, err := s.Create(ctx, "webhook", "Ops", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetSubscription(ctx, p.ProviderID, "not-a-real-category", "warning", true, nil); err == nil {
		t.Fatal("expected an error for an unknown event category")
	}
}

func TestSetSubscriptionRejectsUnknownProvider(t *testing.T) {
	s := newTestService(t)
	if err := s.SetSubscription(context.Background(), "no-such-provider", "deploy_failure", "warning", true, nil); err == nil {
		t.Fatal("expected an error for an unknown provider_id")
	}
}

func TestSetSubscriptionAndListRoundTrip(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	p, err := s.Create(ctx, "webhook", "Ops", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetSubscription(ctx, p.ProviderID, "deploy_failure", "critical", true, nil); err != nil {
		t.Fatal(err)
	}
	list, err := s.ListSubscriptions(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].EventCategory != "deploy_failure" || list[0].MinSeverity != "critical" {
		t.Fatalf("unexpected subscriptions: %+v", list)
	}

	// Upsert: re-setting the same (provider, category) updates, doesn't duplicate.
	if err := s.SetSubscription(ctx, p.ProviderID, "deploy_failure", "info", true, nil); err != nil {
		t.Fatal(err)
	}
	list, _ = s.ListSubscriptions(ctx)
	if len(list) != 1 || list[0].MinSeverity != "info" {
		t.Fatalf("expected upsert not duplicate, got %+v", list)
	}
}

func TestDeleteSubscriptionRemovesIt(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	p, _ := s.Create(ctx, "webhook", "Ops", nil)
	s.SetSubscription(ctx, p.ProviderID, "deploy_failure", "warning", true, nil)
	list, _ := s.ListSubscriptions(ctx)
	if err := s.DeleteSubscription(ctx, list[0].ID); err != nil {
		t.Fatal(err)
	}
	list, _ = s.ListSubscriptions(ctx)
	if len(list) != 0 {
		t.Fatalf("expected empty after delete, got %+v", list)
	}
}

// TestDispatchSendsRealWebhookAndRecordsHistory is Dispatch's own real
// end-to-end proof: a real disposable webhook server, a real stored
// secret, a real subscription -- Dispatch must actually deliver the
// event's summary and record a real "sent" history row.
func TestDispatchSendsRealWebhookAndRecordsHistory(t *testing.T) {
	var receivedBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 1024)
		n, _ := r.Body.Read(buf)
		receivedBody = string(buf[:n])
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := newTestServiceWithSecrets(t)
	ctx := context.Background()
	p, err := s.Create(ctx, "webhook", "Ops", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetSecret(ctx, p.ProviderID, srv.URL); err != nil {
		t.Fatal(err)
	}
	if err := s.SetSubscription(ctx, p.ProviderID, "deploy_failure", "warning", true, nil); err != nil {
		t.Fatal(err)
	}

	outcomes, err := s.Dispatch(ctx, "deploy_failure", "critical", "dns_runtime", "promotion rolled back at stage health_check", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(outcomes) != 1 || outcomes[0].Status != "sent" {
		t.Fatalf("outcomes = %+v, want 1 sent", outcomes)
	}
	if receivedBody == "" {
		t.Fatal("the real disposable webhook server never received a request")
	}
	if !strings.Contains(receivedBody, "promotion rolled back") {
		t.Fatalf("webhook body = %q, want the real event summary", receivedBody)
	}

	history, err := s.ListHistory(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 1 || history[0].Status != "sent" || history[0].EventCategory != "deploy_failure" {
		t.Fatalf("history = %+v, want 1 real sent entry", history)
	}
}

// TestDispatchSkipsBelowMinSeverity proves severity filtering is real:
// a subscription requiring "critical" must never fire for a "warning".
func TestDispatchSkipsBelowMinSeverity(t *testing.T) {
	var called bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := newTestServiceWithSecrets(t)
	ctx := context.Background()
	p, _ := s.Create(ctx, "webhook", "Ops", nil)
	s.SetSecret(ctx, p.ProviderID, srv.URL)
	s.SetSubscription(ctx, p.ProviderID, "deploy_failure", "critical", true, nil)

	outcomes, err := s.Dispatch(ctx, "deploy_failure", "warning", "dns_runtime", "a minor thing", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(outcomes) != 0 {
		t.Fatalf("expected zero outcomes (below min_severity), got %+v", outcomes)
	}
	if called {
		t.Fatal("the real webhook server was called despite being below min_severity")
	}
}

// TestDispatchSuppressesRepeatWithinCooldown is the real cooldown/dedup
// proof: a second identical-fingerprint event within the cooldown
// window must be suppressed, not re-sent, and recorded as such.
func TestDispatchSuppressesRepeatWithinCooldown(t *testing.T) {
	var callCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := newTestServiceWithSecrets(t)
	ctx := context.Background()
	p, _ := s.Create(ctx, "webhook", "Ops", nil)
	s.SetSecret(ctx, p.ProviderID, srv.URL)
	longCooldown := 60
	s.SetSubscription(ctx, p.ProviderID, "deploy_failure", "warning", true, &longCooldown)

	first, err := s.Dispatch(ctx, "deploy_failure", "critical", "dns_runtime", "first failure", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 1 || first[0].Status != "sent" {
		t.Fatalf("first dispatch = %+v, want sent", first)
	}

	second, err := s.Dispatch(ctx, "deploy_failure", "critical", "dns_runtime", "same real condition, still failing", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(second) != 1 || second[0].Status != "suppressed" {
		t.Fatalf("second dispatch = %+v, want suppressed (within cooldown)", second)
	}
	if callCount != 1 {
		t.Fatalf("real webhook server was called %d times, want exactly 1 (second must be suppressed)", callCount)
	}

	history, _ := s.ListHistory(ctx, 10)
	if len(history) != 2 || history[0].Status != "suppressed" {
		t.Fatalf("history = %+v, want [suppressed, sent]", history)
	}
}

// TestDispatchRecoveryBypassesCooldown proves recovery notices are
// never suppressed, matching Python's own "recovered=True always
// delivered" contract.
func TestDispatchRecoveryBypassesCooldown(t *testing.T) {
	var callCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := newTestServiceWithSecrets(t)
	ctx := context.Background()
	p, _ := s.Create(ctx, "webhook", "Ops", nil)
	s.SetSecret(ctx, p.ProviderID, srv.URL)
	longCooldown := 60
	s.SetSubscription(ctx, p.ProviderID, "deploy_failure", "warning", true, &longCooldown)

	s.Dispatch(ctx, "deploy_failure", "critical", "dns_runtime", "failing", false)
	// Recovery still passes through the same min_severity gate Python's
	// own dispatch() applies regardless of `recovered` -- only cooldown/
	// dedup is bypassed for a recovery notice, so this must stay at or
	// above the subscription's "warning" threshold to reach that check.
	recovery, err := s.Dispatch(ctx, "deploy_failure", "warning", "dns_runtime", "recovered", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(recovery) != 1 || recovery[0].Status != "sent" {
		t.Fatalf("recovery dispatch = %+v, want sent (never suppressed)", recovery)
	}
	if callCount != 2 {
		t.Fatalf("real webhook server was called %d times, want 2 (recovery bypasses cooldown)", callCount)
	}
}

func TestDispatchRejectsUnknownEventCategory(t *testing.T) {
	s := newTestService(t)
	if _, err := s.Dispatch(context.Background(), "not-a-real-category", "warning", "x", "y", false); err == nil {
		t.Fatal("expected an error for an unknown event category")
	}
}

// TestDeleteProviderRemovesItsSubscriptions proves a real, previously
// disclosed-elsewhere bug class: this schema's ON DELETE CASCADE is
// inert (PRAGMA foreign_keys is never enabled), so Delete must clean up
// notification_subscriptions/notification_rate_state explicitly or a
// deleted provider leaves orphaned rows Dispatch would still try to use.
func TestDeleteProviderRemovesItsSubscriptions(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	p, err := s.Create(ctx, "webhook", "Ops", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetSubscription(ctx, p.ProviderID, "deploy_failure", "warning", true, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(ctx, p.ProviderID); err != nil {
		t.Fatal(err)
	}
	list, err := s.ListSubscriptions(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 0 {
		t.Fatalf("expected the subscription to be removed along with its provider, got %+v", list)
	}
}

func TestDispatchNoSubscriptionsIsAQuietNoOp(t *testing.T) {
	s := newTestService(t)
	outcomes, err := s.Dispatch(context.Background(), "deploy_failure", "critical", "x", "y", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(outcomes) != 0 {
		t.Fatalf("expected zero outcomes with no subscriptions, got %+v", outcomes)
	}
}
