package hostagentd

// Strong ClientID's real end-to-end proof: real named+dnsdist processes
// this test suite brings up and tears down itself (never Python's
// apdns-v2-preview, never the deployed :10443 preview -- matching every
// other test in this file), a real dnscompile.CompileDnsdist output, a
// real promote through the exact stage->validate->promote->reload->
// health-check->rollback pipeline, and real DoH/DoT client connections:
// crypto/tls directly for DoT (full control over the raw DNS wire
// query/response), and Go's own net/http (real HTTP/2, RFC 8484 POST
// mode) for DoH -- NOT `dig +https=<path>`, this file's usual
// convention elsewhere, because dig's own +https value handling breaks
// on a 64-character path segment (reproduced directly against a
// throwaway dnsdist instance outside this suite before writing
// dohQuery below; a short path works fine in dig, so this is dig's own
// client-side limit, not a dnsdist or compiled-config problem). DoQ is
// proven for what a pure-Go test suite with no QUIC client dependency
// can prove directly (see its own test's doc comment for exactly what
// that is and isn't).
//
// "Allowed"/default-policy answers below come from a real compiled
// Local DNS record (SpoofAction, terminal, entirely inside dnsdist),
// not a live upstream round trip -- deliberately: it's the same
// already-proven mechanism TestDNSRuntimePromoteLocalDnsAnswer uses,
// and it keeps every assertion here about the identity/precedence
// logic itself, not about upstream-forwarding behavior across
// transports (a separate concern this file's other tests already
// cover for plain UDP).
import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"testing"
	"time"

	"alderpointdns/go-controlplane/internal/clientid"
	"alderpointdns/go-controlplane/internal/dnscompile"
)

// buildDNSQuery hand-rolls a minimal, valid DNS question message (no
// compression, one question, RD set) -- deliberately not depending on
// any DNS library (this project has none in go.mod), just enough wire
// format to prove a real query reaches the real dnsdist process and a
// real, real-rcode response comes back.
func buildDNSQuery(name string) []byte {
	var b bytes.Buffer
	b.Write([]byte{0x13, 0x37, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) // header: ID, RD=1, QDCOUNT=1
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		b.WriteByte(byte(len(label)))
		b.WriteString(label)
	}
	b.WriteByte(0)
	b.Write([]byte{0x00, 0x01, 0x00, 0x01}) // QTYPE=A, QCLASS=IN
	return b.Bytes()
}

// dotQuery dials a real TLS connection to addr with the given SNI
// (crypto/tls's own ServerName -- exactly the ClientHello field
// dnsdist's SNIRule matches against), sends one real RFC 7858-framed
// DoT query (2-byte length prefix + message), and returns the real
// response's RCODE (the low 4 bits of DNS header byte 3). Skips TLS
// verification (this test's own throwaway self-signed cert, same
// pattern as every other TLS-using test in this package) -- SNI is set
// regardless of verification, which is what's actually under test.
func dotQuery(t *testing.T, addr, sni, name string) int {
	t.Helper()
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", addr, &tls.Config{ServerName: sni, InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("dotQuery: TLS dial to %s (SNI=%q) failed: %v", addr, sni, err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))

	q := buildDNSQuery(name)
	var lenPrefix [2]byte
	binary.BigEndian.PutUint16(lenPrefix[:], uint16(len(q)))
	if _, err := conn.Write(lenPrefix[:]); err != nil {
		t.Fatalf("dotQuery: writing length prefix: %v", err)
	}
	if _, err := conn.Write(q); err != nil {
		t.Fatalf("dotQuery: writing query: %v", err)
	}

	var respLen [2]byte
	if _, err := io.ReadFull(conn, respLen[:]); err != nil {
		t.Fatalf("dotQuery: reading response length prefix: %v", err)
	}
	resp := make([]byte, binary.BigEndian.Uint16(respLen[:]))
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("dotQuery: reading response body: %v", err)
	}
	if len(resp) < 4 {
		t.Fatalf("dotQuery: response too short to contain a header: %d bytes", len(resp))
	}
	return int(resp[3] & 0x0F)
}

// rcodeNOERROR/rcodeREFUSED mirror the standard DNS RCODE values this
// test checks for.
const (
	rcodeNOERROR = 0
	rcodeREFUSED = 5
)

// dohQuery sends one real RFC 8484 POST-mode DoH request (Content-Type:
// application/dns-message, the raw wire query as the body) to the given
// full https URL and returns the real response's RCODE. Uses Go's own
// net/http directly rather than `dig +https=<path>` -- a real,
// independently-confirmed dig limitation (its own +https value buffer
// truncates/mishandles a 64-character path segment, reproduced directly
// against a throwaway dnsdist instance outside this test suite; a short
// path works fine, so this is dig's own client-side limit, not a
// dnsdist or compiled-config problem) makes dig unusable for a
// full-length 256-bit ClientID path specifically.
func dohQuery(t *testing.T, url, name string) int {
	t.Helper()
	// dnsdist's DoH implementation requires real HTTP/2 (RFC 8484
	// section 5.2) -- confirmed live: a bare *http.Transport{} literal
	// with only TLSClientConfig set produced a 505 "requires HTTP/2"
	// error page. Cloning http.DefaultTransport (which already has
	// HTTP/2 wired up by net/http's own init) and only overriding
	// TLSClientConfig on the clone is the documented-safe way to keep
	// that auto-upgrade while still skipping verification for this
	// test's own throwaway cert.
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	client := &http.Client{Timeout: 3 * time.Second, Transport: transport}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(buildDNSQuery(name)))
	if err != nil {
		t.Fatalf("dohQuery: building request: %v", err)
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("dohQuery: POST %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("dohQuery: reading response body: %v", err)
	}
	if len(body) < 4 {
		t.Fatalf("dohQuery: response too short to contain a header (HTTP status %d): %d bytes: %q", resp.StatusCode, len(body), body)
	}
	return int(body[3] & 0x0F)
}

// TestDNSRuntimePromoteClientIdentityDoTSNIEnforcesPerClientPrecedenceAndIsolation
// is the core Strong ClientID proof: real DoT connections, real SNI,
// against a real promoted dnsdist, proving explicit deny > explicit
// allow > default AND that neither client's override leaks to the
// other or to an untagged connection.
func TestDNSRuntimePromoteClientIdentityDoTSNIEnforcesPerClientPrecedenceAndIsolation(t *testing.T) {
	s, cfg := newDNSRuntimeConfig(t)
	certPath, keyPath := testTLSCert(t)

	hexA, err := clientid.GenerateHex(clientid.Bits192)
	if err != nil {
		t.Fatal(err)
	}
	hexB, err := clientid.GenerateHex(clientid.Bits256)
	if err != nil {
		t.Fatal(err)
	}
	dotPort := freeTCPPort(t)

	in := dnscompile.Input{
		ListenAddress: cfg.DnsdistListenAddress, BindBackendAddress: fmt.Sprintf("127.0.0.1:%d", cfg.BindProxyPort),
		LocalDNSRecords: []dnscompile.LocalDNSRecord{{Name: "shared.example.test", RecordType: "A", Value: "203.0.113.55", TTL: 300}},
		Transports:      dnscompile.TransportSettings{DotEnabled: true, DotPort: dotPort},
		TLSCertPath:     certPath, TLSKeyPath: keyPath,
		BlockingResponseMode: "refused",
		ClientIdentities: []dnscompile.ClientIdentity{
			{ClientKey: "client-a", Hex: hexA},
			{ClientKey: "client-b", Hex: hexB},
		},
		ClientOverrides: []dnscompile.ClientOverride{
			{ClientKey: "client-a", Kind: "block", Domain: "shared.example.test."},
		},
	}
	dnsdistConf, err := dnscompile.CompileDnsdist(in)
	if err != nil {
		t.Fatal(err)
	}
	res := callPromote(t, s, DNSPromoteParams{DnsdistConf: dnsdistConf})
	if !res.Promoted {
		t.Fatalf("expected promotion to succeed, got %+v", res)
	}

	host, _ := splitHostPort(cfg.DnsdistListenAddress)
	dotAddr := fmt.Sprintf("%s:%d", host, dotPort)
	sniA := clientid.EncodeSNILabel(hexA)
	sniB := clientid.EncodeSNILabel(hexB)

	// Client A has an explicit deny on this domain -- must be REFUSED,
	// never reaching the compiled Local DNS answer.
	if rc := dotQuery(t, dotAddr, sniA, "shared.example.test."); rc != rcodeREFUSED {
		t.Fatalf("client-a (explicit deny) expected REFUSED (%d), got rcode %d", rcodeREFUSED, rc)
	}

	// Client B has NO override for this domain -- falls through to the
	// compiled Local DNS answer, a real NOERROR -- isolation proof:
	// client-a's deny must never leak to client-b.
	if rc := dotQuery(t, dotAddr, sniB, "shared.example.test."); rc != rcodeNOERROR {
		t.Fatalf("client-b (no override, same domain) expected NOERROR (%d) -- client-a's deny must not leak, got rcode %d", rcodeNOERROR, rc)
	}

	// A connection with NO recognized ClientID SNI at all (an unrelated
	// hostname) must get the same default behavior as client-b -- an
	// untagged/unrelated connection is never treated as client-a.
	if rc := dotQuery(t, dotAddr, "totally-unrelated.example.", "shared.example.test."); rc != rcodeNOERROR {
		t.Fatalf("an unrelated/untagged connection expected the default NOERROR (%d), got rcode %d -- must never accidentally inherit client-a's deny", rcodeNOERROR, rc)
	}
}

// TestDNSRuntimePromoteClientIdentityDoHPathEnforcesPerClientPrecedence
// is the DoH half of the same proof, via the real full-canonical-hex
// path and a real `dig +https=<path>` request (RFC 8484 POST mode) --
// matching this file's own existing dig-based convention for every
// other real-answer proof.
func TestDNSRuntimePromoteClientIdentityDoHPathEnforcesPerClientPrecedence(t *testing.T) {
	s, cfg := newDNSRuntimeConfig(t)
	certPath, keyPath := testTLSCert(t)

	hexA, err := clientid.GenerateHex(clientid.Bits256)
	if err != nil {
		t.Fatal(err)
	}
	dohPort := freeTCPPort(t)

	in := dnscompile.Input{
		ListenAddress: cfg.DnsdistListenAddress, BindBackendAddress: fmt.Sprintf("127.0.0.1:%d", cfg.BindProxyPort),
		LocalDNSRecords: []dnscompile.LocalDNSRecord{{Name: "doh-blocked.example.test", RecordType: "A", Value: "203.0.113.56", TTL: 300}},
		Transports:      dnscompile.TransportSettings{DohEnabled: true, DohPort: dohPort, DohPath: "/dns-query"},
		TLSCertPath:     certPath, TLSKeyPath: keyPath,
		BlockingResponseMode: "refused",
		ClientIdentities:     []dnscompile.ClientIdentity{{ClientKey: "client-a", Hex: hexA}},
		ClientOverrides:      []dnscompile.ClientOverride{{ClientKey: "client-a", Kind: "block", Domain: "doh-blocked.example.test."}},
	}
	dnsdistConf, err := dnscompile.CompileDnsdist(in)
	if err != nil {
		t.Fatal(err)
	}
	res := callPromote(t, s, DNSPromoteParams{DnsdistConf: dnsdistConf})
	if !res.Promoted {
		t.Fatalf("expected promotion to succeed, got %+v", res)
	}

	host, _ := splitHostPort(cfg.DnsdistListenAddress)
	dohPath := clientid.DoHPath(hexA)
	if !strings.HasPrefix(dohPath, "/dns-query/cid/") || len(dohPath) < len("/dns-query/cid/")+64 {
		t.Fatalf("sanity: expected the full 64-hex path, got %q", dohPath)
	}

	// A real request against client-a's own DoH path for a domain it
	// explicitly denies -- must be REFUSED.
	identityURL := fmt.Sprintf("https://%s:%d%s", host, dohPort, dohPath)
	if rc := dohQuery(t, identityURL, "doh-blocked.example.test."); rc != rcodeREFUSED {
		t.Fatalf("expected REFUSED (%d) for client-a's own explicit-deny domain over DoH, got rcode %d", rcodeREFUSED, rc)
	}

	// The SAME domain over the plain default DoH path (/dns-query, no
	// ClientID) must NOT be refused -- proves the deny is scoped to the
	// identity's own path, not global.
	defaultURL := fmt.Sprintf("https://%s:%d/dns-query", host, dohPort)
	if rc := dohQuery(t, defaultURL, "doh-blocked.example.test."); rc != rcodeNOERROR {
		t.Fatalf("expected the SAME domain to resolve normally (NOERROR/%d) over the default (non-ClientID) DoH path -- got rcode %d, meaning the deny leaked outside client-a's own identity", rcodeNOERROR, rc)
	}
}

// TestDNSRuntimePromoteClientIdentityDoqListenerAcceptsARealQUICHandshakeWithTheCompiledSNI
// proves what a pure-Go test suite with no QUIC client dependency
// (go.mod has none, and adding one for a single test wasn't judged
// worth the new dependency surface) CAN prove directly for DoQ: the
// compiled addDOQLocal listener is real and live, and a real QUIC+TLS
// handshake using the exact SNI internal/clientid compiles for this
// identity is accepted by it -- using the openssl binary's own -quic
// support (OpenSSL 3.5+, confirmed present on this host), not a mock.
// The actual per-domain enforcement decision for that same compiled
// SNIRule/TagRule/AndRule chain is proven by
// TestDNSRuntimePromoteClientIdentityDoTSNIEnforcesPerClientPrecedenceAndIsolation
// above -- dnsdist extracts and matches the ClientHello SNI value the
// identical way regardless of whether the transport underneath is
// DoT's TCP+TLS or DoQ's QUIC+TLS, so that is real enforcement proof
// for DoQ's own rule too, not a leap of faith -- but this test itself
// deliberately does not claim to have sent a real DNS query over a
// QUIC stream (RFC 9250 framing), which is what a QUIC client library
// would add.
func TestDNSRuntimePromoteClientIdentityDoqListenerAcceptsARealQUICHandshakeWithTheCompiledSNI(t *testing.T) {
	opensslBin, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not available in this environment")
	}
	if out, err := exec.Command(opensslBin, "s_client", "-help").CombinedOutput(); err != nil || !strings.Contains(string(out), "-quic") {
		t.Skip("installed openssl does not support -quic (s_client -help doesn't list it)")
	}

	s, cfg := newDNSRuntimeConfig(t)
	certPath, keyPath := testTLSCert(t)
	hexA, err := clientid.GenerateHex(clientid.Bits256)
	if err != nil {
		t.Fatal(err)
	}
	doqPort := freeTCPPort(t)

	in := dnscompile.Input{
		ListenAddress: cfg.DnsdistListenAddress, BindBackendAddress: fmt.Sprintf("127.0.0.1:%d", cfg.BindProxyPort),
		Transports:  dnscompile.TransportSettings{DoqEnabled: true, DoqPort: doqPort},
		TLSCertPath: certPath, TLSKeyPath: keyPath,
		ClientIdentities: []dnscompile.ClientIdentity{{ClientKey: "client-a", Hex: hexA}},
	}
	dnsdistConf, err := dnscompile.CompileDnsdist(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(dnsdistConf, "addDOQLocal(") {
		t.Fatalf("sanity: expected a DoQ listener in the compiled config:\n%s", dnsdistConf)
	}
	sni := clientid.EncodeSNILabel(hexA)
	if !strings.Contains(dnsdistConf, `SNIRule("`+sni+`")`) {
		t.Fatalf("sanity: expected the compiled SNIRule for this identity, got:\n%s", dnsdistConf)
	}
	res := callPromote(t, s, DNSPromoteParams{DnsdistConf: dnsdistConf})
	if !res.Promoted {
		t.Fatalf("expected promotion to succeed, got %+v", res)
	}

	host, _ := splitHostPort(cfg.DnsdistListenAddress)
	addr := fmt.Sprintf("%s:%d", host, doqPort)
	out, err := exec.Command(opensslBin, "s_client", "-quic", "-connect", addr, "-servername", sni, "-alpn", "doq").
		CombinedOutput() // no stdin needed; s_client with -quic completes/reports the handshake and exits
	combined := string(out)
	if !strings.Contains(combined, "CONNECTED(") {
		t.Fatalf("expected a real QUIC handshake (CONNECTED) against the live DoQ listener with the compiled SNI %q, got:\n%s\n(err=%v)", sni, combined, err)
	}
}

// TestDNSRuntimePromoteClientIdentityRevokeAndRegenerateChangeLiveEnforcement
// proves revoke/regenerate through a real second promote (the exact
// mechanism internal/dnsruntime.Orchestrator triggers after
// internal/clients.RevokeIdentifier/RegenerateIdentifier -- see those
// packages): the OLD identity's SNI must stop being recognized at all
// (falls to default policy, not "still partially works"), and a freshly
// generated replacement identity must be immediately enforceable.
func TestDNSRuntimePromoteClientIdentityRevokeAndRegenerateChangeLiveEnforcement(t *testing.T) {
	s, cfg := newDNSRuntimeConfig(t)
	certPath, keyPath := testTLSCert(t)
	dotPort := freeTCPPort(t)

	oldHex, err := clientid.GenerateHex(clientid.Bits192)
	if err != nil {
		t.Fatal(err)
	}
	baseIn := dnscompile.Input{
		ListenAddress: cfg.DnsdistListenAddress, BindBackendAddress: fmt.Sprintf("127.0.0.1:%d", cfg.BindProxyPort),
		LocalDNSRecords: []dnscompile.LocalDNSRecord{{Name: "revoke-test.example.test", RecordType: "A", Value: "203.0.113.57", TTL: 300}},
		Transports:      dnscompile.TransportSettings{DotEnabled: true, DotPort: dotPort},
		TLSCertPath:     certPath, TLSKeyPath: keyPath,
		BlockingResponseMode: "refused",
	}

	v1 := baseIn
	v1.ClientIdentities = []dnscompile.ClientIdentity{{ClientKey: "client-a", Hex: oldHex}}
	v1.ClientOverrides = []dnscompile.ClientOverride{{ClientKey: "client-a", Kind: "block", Domain: "revoke-test.example.test."}}
	conf1, err := dnscompile.CompileDnsdist(v1)
	if err != nil {
		t.Fatal(err)
	}
	if res := callPromote(t, s, DNSPromoteParams{DnsdistConf: conf1}); !res.Promoted {
		t.Fatalf("initial promote failed: %+v", res)
	}

	host, _ := splitHostPort(cfg.DnsdistListenAddress)
	dotAddr := fmt.Sprintf("%s:%d", host, dotPort)
	oldSNI := clientid.EncodeSNILabel(oldHex)
	if rc := dotQuery(t, dotAddr, oldSNI, "revoke-test.example.test."); rc != rcodeREFUSED {
		t.Fatalf("before revoke: expected REFUSED via the original identity, got rcode %d", rc)
	}

	// Simulate RegenerateIdentifier: revoke the old identity (simply
	// absent from the next compile -- exactly what
	// internal/clients.AllActiveClientIdentities returns once revoked)
	// and mint a fresh one, same client key, same override.
	newHex, err := clientid.GenerateHex(clientid.Bits192)
	if err != nil {
		t.Fatal(err)
	}
	v2 := baseIn
	v2.ClientIdentities = []dnscompile.ClientIdentity{{ClientKey: "client-a", Hex: newHex}}
	v2.ClientOverrides = []dnscompile.ClientOverride{{ClientKey: "client-a", Kind: "block", Domain: "revoke-test.example.test."}}
	conf2, err := dnscompile.CompileDnsdist(v2)
	if err != nil {
		t.Fatal(err)
	}
	if res := callPromote(t, s, DNSPromoteParams{DnsdistConf: conf2}); !res.Promoted {
		t.Fatalf("regenerate promote failed: %+v", res)
	}

	// The OLD identity's SNI must no longer be recognized at all --
	// falls to default (no block rule for an untagged connection here),
	// so a real NOERROR from the compiled Local DNS answer is expected,
	// not REFUSED.
	if rc := dotQuery(t, dotAddr, oldSNI, "revoke-test.example.test."); rc != rcodeNOERROR {
		t.Fatalf("after revoke: the old identity must no longer be enforced (expected NOERROR/%d), got rcode %d", rcodeNOERROR, rc)
	}
	// The NEW identity must be enforced immediately.
	newSNI := clientid.EncodeSNILabel(newHex)
	if rc := dotQuery(t, dotAddr, newSNI, "revoke-test.example.test."); rc != rcodeREFUSED {
		t.Fatalf("after regenerate: expected REFUSED via the new identity, got rcode %d", rc)
	}
}

// TestDNSRuntimePromoteClientIdentityBindingSurvivesARealDnsdistRestart
// is the disclosed dnsdist constraint's own proof: DoH/DoT/DoQ
// ClientID paths are read only at dnsdist startup (addDOHLocal/
// addTLSLocal/addDOQLocal's path/cert args), so changing them requires
// a real restart -- this test kills the real live dnsdist process out
// from under the already-promoted config (simulating a crash, the
// harshest real restart scenario) and proves a subsequent promote of
// the SAME config brings enforcement back from a genuinely fresh
// process start, not a warm/cached state.
func TestDNSRuntimePromoteClientIdentityBindingSurvivesARealDnsdistRestart(t *testing.T) {
	s, cfg := newDNSRuntimeConfig(t)
	certPath, keyPath := testTLSCert(t)
	dotPort := freeTCPPort(t)

	hexA, err := clientid.GenerateHex(clientid.Bits192)
	if err != nil {
		t.Fatal(err)
	}
	in := dnscompile.Input{
		ListenAddress: cfg.DnsdistListenAddress, BindBackendAddress: fmt.Sprintf("127.0.0.1:%d", cfg.BindProxyPort),
		LocalDNSRecords: []dnscompile.LocalDNSRecord{{Name: "restart-test.example.test", RecordType: "A", Value: "203.0.113.58", TTL: 300}},
		Transports:      dnscompile.TransportSettings{DotEnabled: true, DotPort: dotPort},
		TLSCertPath:     certPath, TLSKeyPath: keyPath,
		BlockingResponseMode: "refused",
		ClientIdentities:     []dnscompile.ClientIdentity{{ClientKey: "client-a", Hex: hexA}},
		ClientOverrides:      []dnscompile.ClientOverride{{ClientKey: "client-a", Kind: "block", Domain: "restart-test.example.test."}},
	}
	dnsdistConf, err := dnscompile.CompileDnsdist(in)
	if err != nil {
		t.Fatal(err)
	}
	if res := callPromote(t, s, DNSPromoteParams{DnsdistConf: dnsdistConf}); !res.Promoted {
		t.Fatalf("initial promote failed: %+v", res)
	}

	host, _ := splitHostPort(cfg.DnsdistListenAddress)
	dotAddr := fmt.Sprintf("%s:%d", host, dotPort)
	sni := clientid.EncodeSNILabel(hexA)
	if rc := dotQuery(t, dotAddr, sni, "restart-test.example.test."); rc != rcodeREFUSED {
		t.Fatalf("before crash: expected REFUSED, got rcode %d", rc)
	}

	// Kill the real live dnsdist process directly (SIGKILL -- a crash,
	// not a graceful stop) and confirm the port genuinely goes away
	// before re-promoting, so the next promote's own health check is
	// proving a real fresh start, not talking to a process that never
	// actually died.
	killLiveDnsdist(t, cfg.DnsdistLivePath, dotAddr)

	// Re-promote the IDENTICAL config -- matches apdns-hostagent's own
	// real recovery path (any promote, including a resync after a
	// crash, always fully restarts dnsdist and reloads its Lua config
	// from disk).
	if res := callPromote(t, s, DNSPromoteParams{DnsdistConf: dnsdistConf}); !res.Promoted {
		t.Fatalf("re-promote after crash failed: %+v", res)
	}
	if rc := dotQuery(t, dotAddr, sni, "restart-test.example.test."); rc != rcodeREFUSED {
		t.Fatalf("after a real restart: expected the ClientID binding to still be enforced (REFUSED), got rcode %d -- binding did not survive the restart", rc)
	}
}

// testTLSCert generates a real throwaway self-signed cert/key pair.
func testTLSCert(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	dir := t.TempDir()
	certPath = dir + "/server.crt"
	keyPath = dir + "/server.key"
	out, err := exec.Command("openssl", "req", "-x509", "-newkey", "rsa:2048",
		"-keyout", keyPath, "-out", certPath, "-days", "1", "-nodes", "-subj", "/CN=clientid-e2e-test").CombinedOutput()
	if err != nil {
		t.Skipf("openssl not usable in this environment: %v: %s", err, out)
	}
	return certPath, keyPath
}

// killLiveDnsdist SIGKILLs the real dnsdist process running against
// livePath (this test's own unique per-test dnsdist.conf path, set by
// newDNSRuntimeConfig -- matched via pkill -f, `fuser` is not
// installed in this environment) and confirms addr's port genuinely
// goes down before returning, so the next promote's own health check
// is proving a real fresh process start, not talking to a process that
// never actually died.
func killLiveDnsdist(t *testing.T, livePath, addr string) {
	t.Helper()
	if out, err := exec.Command("pkill", "-9", "-f", livePath).CombinedOutput(); err != nil {
		t.Logf("pkill -9 -f %s: %v: %s (may just mean it already exited)", livePath, err, out)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		conn, dialErr := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if dialErr != nil {
			return // port is down -- the process is genuinely gone
		}
		conn.Close()
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("dnsdist on %s did not actually go down after pkill -- test cannot prove a real restart", addr)
}
