package notifications

import (
	"context"
	"net"
	"strconv"
	"testing"

	"alderpointdns/go-controlplane/internal/upstreams"
)

// startUDPResponder is a minimal real UDP DNS responder -- echoes back
// a well-formed response with the same query ID, enough for
// dnsperf.QueryOnce's own Sample.OK contract (right ID, any answer).
func startUDPResponder(t *testing.T) (port int, stop func()) {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 512)
		for {
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			resp := make([]byte, n)
			copy(resp, buf[:n])
			resp[2] |= 0x80 // QR=1 (response)
			conn.WriteToUDP(resp, addr)
		}
	}()
	return conn.LocalAddr().(*net.UDPAddr).Port, func() { conn.Close(); <-done }
}

func TestCheckResolverAvailabilityFiresOnceAllEndpointsDown(t *testing.T) {
	svc := newTestServiceWithSecrets(t)
	ctx := context.Background()
	up := &upstreams.Service{DB: svc.DB}

	// Port 1 on loopback is never a real listener -- guaranteed
	// unreachable, no real network dependency, deterministic across
	// any environment (a genuine timeout, not a flake).
	if err := up.Create(ctx, "dead", "Dead resolver", "plain", "ordered", []upstreams.Endpoint{
		{Address: "127.0.0.1:1", Weight: 1},
	}); err != nil {
		t.Fatal(err)
	}

	p, _ := svc.Create(ctx, "webhook", "Ops", nil)
	srv := newFakeWebhookServer(t)
	if err := svc.SetSecret(ctx, p.ProviderID, srv.url); err != nil {
		t.Fatal(err)
	}
	if err := svc.SetSubscription(ctx, p.ProviderID, "resolver_all_unavailable", "info", true, nil); err != nil {
		t.Fatal(err)
	}

	if err := svc.CheckResolverAvailability(ctx, up); err != nil {
		t.Fatal(err)
	}
	if got := srv.count(); got != 1 {
		t.Fatalf("expected 1 real dispatch for a fully-down resolver set, got %d", got)
	}

	// A second check with the same (still down) state must not re-fire.
	if err := svc.CheckResolverAvailability(ctx, up); err != nil {
		t.Fatal(err)
	}
	if got := srv.count(); got != 1 {
		t.Fatalf("expected no additional dispatch for an unchanged bad state, got %d total", got)
	}
}

func TestCheckResolverAvailabilityRealUDPUpNeverFires(t *testing.T) {
	svc := newTestServiceWithSecrets(t)
	ctx := context.Background()
	up := &upstreams.Service{DB: svc.DB}

	port, stop := startUDPResponder(t)
	defer stop()

	if err := up.Create(ctx, "live", "Live resolver", "plain", "ordered", []upstreams.Endpoint{
		{Address: net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), Weight: 1},
	}); err != nil {
		t.Fatal(err)
	}

	p, _ := svc.Create(ctx, "webhook", "Ops", nil)
	srv := newFakeWebhookServer(t)
	svc.SetSecret(ctx, p.ProviderID, srv.url)
	svc.SetSubscription(ctx, p.ProviderID, "resolver_all_unavailable", "info", true, nil)

	if err := svc.CheckResolverAvailability(ctx, up); err != nil {
		t.Fatal(err)
	}
	if got := srv.count(); got != 0 {
		t.Fatalf("expected no dispatch for a genuinely reachable resolver, got %d", got)
	}
}

func TestCheckResolverAvailabilityRecoversAfterComingBack(t *testing.T) {
	svc := newTestServiceWithSecrets(t)
	ctx := context.Background()
	up := &upstreams.Service{DB: svc.DB}

	port, stop := startUDPResponder(t)
	stop() // start it, then immediately close it -- "down" for the first check

	if err := up.Create(ctx, "flaky", "Flaky resolver", "plain", "ordered", []upstreams.Endpoint{
		{Address: net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), Weight: 1},
	}); err != nil {
		t.Fatal(err)
	}
	p, _ := svc.Create(ctx, "webhook", "Ops", nil)
	srv := newFakeWebhookServer(t)
	svc.SetSecret(ctx, p.ProviderID, srv.url)
	svc.SetSubscription(ctx, p.ProviderID, "resolver_all_unavailable", "info", true, nil)

	if err := svc.CheckResolverAvailability(ctx, up); err != nil {
		t.Fatal(err)
	}
	if got := srv.count(); got != 1 {
		t.Fatalf("expected 1 dispatch for the initial down state, got %d", got)
	}

	// Bring a real listener back up on the exact same port and re-check.
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port})
	if err != nil {
		t.Skipf("could not rebind the same port for the recovery half of this test: %v", err)
	}
	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			resp := make([]byte, n)
			copy(resp, buf[:n])
			resp[2] |= 0x80
			conn.WriteToUDP(resp, addr)
		}
	}()
	defer conn.Close()

	if err := svc.CheckResolverAvailability(ctx, up); err != nil {
		t.Fatal(err)
	}
	if got := srv.count(); got != 2 {
		t.Fatalf("expected a second, real recovery dispatch once the resolver answers again, got %d total", got)
	}
}

func TestCheckResolverAvailabilityWithNothingEnabledIsANoOp(t *testing.T) {
	svc := newTestServiceWithSecrets(t)
	up := &upstreams.Service{DB: svc.DB}
	if err := svc.CheckResolverAvailability(context.Background(), up); err != nil {
		t.Fatalf("expected no error with zero configured upstream profiles, got %v", err)
	}
}

func TestCheckResolverAvailabilityWithNilServiceIsANoOp(t *testing.T) {
	svc := newTestServiceWithSecrets(t)
	if err := svc.CheckResolverAvailability(context.Background(), nil); err != nil {
		t.Fatalf("expected no error for a nil upstreams service, got %v", err)
	}
}

