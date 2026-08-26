package hostagentd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

var testVethCounter int64

// newTestVeth creates a real, disposable veth interface pair -- never a
// dummy interface (this host's kernel module rejects `ip link add ...
// type dummy` with a netlink policy error, a real environment quirk
// found live; veth works and is just as safe/inert for these tests) and
// never, ever the host's real NIC. Returns the "near" side's name, which
// the test brings up and mutates; the "far" side is left down and
// unused, just so the pair is valid to create.
func newTestVeth(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("ip command not available in this environment")
	}
	n := atomic.AddInt64(&testVethCounter, 1)
	near := fmt.Sprintf("apdns-t%d-a", n)
	far := fmt.Sprintf("apdns-t%d-b", n)
	if err := exec.Command("ip", "link", "add", "name", near, "type", "veth", "peer", "name", far).Run(); err != nil {
		t.Skipf("could not create a test veth pair (no CAP_NET_ADMIN in this environment?): %v", err)
	}
	t.Cleanup(func() {
		exec.Command("ip", "link", "del", near).Run() // also removes the peer
	})
	if err := exec.Command("ip", "link", "set", near, "up").Run(); err != nil {
		t.Fatalf("bringing up test interface: %v", err)
	}
	return near
}

func currentAddrs(t *testing.T, iface string) []string {
	t.Helper()
	out, err := exec.Command("ip", "-j", "addr", "show", "dev", iface).Output()
	if err != nil {
		t.Fatal(err)
	}
	return parseIPAddrJSON(string(out))
}

func TestNetworkApplyChangesTheRealInterfaceAddress(t *testing.T) {
	iface := newTestVeth(t)
	s := &Server{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	RegisterNetworkOps(s, NetworkConfig{AutoRevertTimeout: 30 * time.Second})

	result, err := s.handlers["network.apply"](context.Background(), json.RawMessage(fmt.Sprintf(
		`{"interface":%q,"addresses":["10.250.99.5/24"]}`, iface)))
	if err != nil {
		t.Fatalf("expected apply to succeed against a real test interface, got: %v", err)
	}
	encoded, _ := json.Marshal(result)
	if !strings.Contains(string(encoded), "applied_pending_confirmation") {
		t.Fatalf("expected applied_pending_confirmation status, got %s", encoded)
	}

	addrs := currentAddrs(t, iface)
	found := false
	for _, a := range addrs {
		if a == "10.250.99.5/24" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected the real interface to actually have the new address, got %+v", addrs)
	}
}

func TestNetworkConfirmCancelsAutoRevert(t *testing.T) {
	iface := newTestVeth(t)
	s := &Server{Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Audit: &AuditLog{}}
	RegisterNetworkOps(s, NetworkConfig{AutoRevertTimeout: 300 * time.Millisecond})

	_, err := s.handlers["network.apply"](context.Background(), json.RawMessage(fmt.Sprintf(
		`{"interface":%q,"addresses":["10.250.99.6/24"]}`, iface)))
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.handlers["network.confirm"](context.Background(), json.RawMessage(fmt.Sprintf(`{"interface":%q}`, iface)))
	if err != nil {
		t.Fatalf("expected confirm to succeed, got: %v", err)
	}

	time.Sleep(600 * time.Millisecond) // longer than the auto-revert window
	addrs := currentAddrs(t, iface)
	found := false
	for _, a := range addrs {
		if a == "10.250.99.6/24" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected the confirmed address to survive past the auto-revert window, got %+v", addrs)
	}
}

func TestNetworkAutoRevertRestoresThePreviousAddressWhenNotConfirmed(t *testing.T) {
	iface := newTestVeth(t)
	// Give the interface a known starting address before the test begins.
	if err := exec.Command("ip", "addr", "add", "10.250.99.1/24", "dev", iface).Run(); err != nil {
		t.Fatal(err)
	}

	s := &Server{Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Audit: &AuditLog{}}
	RegisterNetworkOps(s, NetworkConfig{AutoRevertTimeout: 300 * time.Millisecond})

	_, err := s.handlers["network.apply"](context.Background(), json.RawMessage(fmt.Sprintf(
		`{"interface":%q,"addresses":["10.250.99.7/24"]}`, iface)))
	if err != nil {
		t.Fatal(err)
	}
	// Deliberately never confirm.
	time.Sleep(700 * time.Millisecond)

	addrs := currentAddrs(t, iface)
	hasNew, hasOld := false, false
	for _, a := range addrs {
		if a == "10.250.99.7/24" {
			hasNew = true
		}
		if a == "10.250.99.1/24" {
			hasOld = true
		}
	}
	if hasNew || !hasOld {
		t.Fatalf("expected auto-revert to restore the original address and remove the unconfirmed one, got %+v", addrs)
	}
}

func TestNetworkRollbackRestoresImmediately(t *testing.T) {
	iface := newTestVeth(t)
	if err := exec.Command("ip", "addr", "add", "10.250.99.2/24", "dev", iface).Run(); err != nil {
		t.Fatal(err)
	}
	s := &Server{Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Audit: &AuditLog{}}
	RegisterNetworkOps(s, NetworkConfig{AutoRevertTimeout: 30 * time.Second})

	_, err := s.handlers["network.apply"](context.Background(), json.RawMessage(fmt.Sprintf(
		`{"interface":%q,"addresses":["10.250.99.8/24"]}`, iface)))
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.handlers["network.rollback"](context.Background(), json.RawMessage(fmt.Sprintf(`{"interface":%q}`, iface)))
	if err != nil {
		t.Fatalf("expected rollback to succeed, got: %v", err)
	}
	addrs := currentAddrs(t, iface)
	hasNew, hasOld := false, false
	for _, a := range addrs {
		if a == "10.250.99.8/24" {
			hasNew = true
		}
		if a == "10.250.99.2/24" {
			hasOld = true
		}
	}
	if hasNew || !hasOld {
		t.Fatalf("expected immediate rollback to restore the original address, got %+v", addrs)
	}
}

func TestNetworkApplyRejectsASecondPendingChangeOnTheSameInterface(t *testing.T) {
	iface := newTestVeth(t)
	s := &Server{Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Audit: &AuditLog{}}
	RegisterNetworkOps(s, NetworkConfig{AutoRevertTimeout: 30 * time.Second})

	_, err := s.handlers["network.apply"](context.Background(), json.RawMessage(fmt.Sprintf(
		`{"interface":%q,"addresses":["10.250.99.9/24"]}`, iface)))
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.handlers["network.apply"](context.Background(), json.RawMessage(fmt.Sprintf(
		`{"interface":%q,"addresses":["10.250.99.10/24"]}`, iface)))
	if err == nil {
		t.Fatal("expected a second apply on the same interface to be rejected while one is pending")
	}
}

func TestNetworkApplyRejectsMissingCIDR(t *testing.T) {
	s := &Server{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	RegisterNetworkOps(s, NetworkConfig{})
	_, err := s.handlers["network.apply"](context.Background(), json.RawMessage(`{"interface":"eth0","addresses":["10.0.0.5"]}`))
	if err == nil {
		t.Fatal("expected an error for a non-CIDR address")
	}
}

func TestNetworkConfirmOfNothingPendingIsRejected(t *testing.T) {
	s := &Server{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	RegisterNetworkOps(s, NetworkConfig{})
	_, err := s.handlers["network.confirm"](context.Background(), json.RawMessage(`{"interface":"nonexistent0"}`))
	if err == nil {
		t.Fatal("expected an error confirming when nothing is pending")
	}
}

func TestNetworkStatusReportsRealInterfaces(t *testing.T) {
	iface := newTestVeth(t)
	if err := exec.Command("ip", "addr", "add", "10.250.99.20/24", "dev", iface).Run(); err != nil {
		t.Fatal(err)
	}
	s := &Server{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	RegisterNetworkOps(s, NetworkConfig{})
	result, err := s.handlers["network.status"](context.Background(), json.RawMessage(fmt.Sprintf(`{"interface":%q}`, iface)))
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(result)
	if !strings.Contains(string(encoded), "10.250.99.20") {
		t.Fatalf("expected the real interface's real address in the status output, got %s", encoded)
	}
}
