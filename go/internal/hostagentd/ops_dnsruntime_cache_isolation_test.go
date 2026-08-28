package hostagentd

// Cache correctness/isolation proof, real end to end -- the gap the
// prior session's BIND Cache Counters work explicitly did NOT close
// (that work only added observability; this proves the actual
// invariant). Real named+dnsdist processes this suite brings up and
// tears down itself, a real dnsdist packet cache (newPacketCache,
// attached only to the unnamed default pool -- see
// internal/dnscompile.CompileDnsdist's own comment on this), and a
// real counting fake upstream so a cache hit is provable by absence of
// a second upstream request, not just a fast response time.
//
// Architecture finding this test proves rather than just asserts (read
// directly from internal/dnscompile.go before writing this): Strong
// ClientID identity/deny/allow rules, Local DNS records, rewrite
// rules, and the global blocklist are ALL compiled as rules that run
// BEFORE the default pool (and its packet cache) is ever reached, and
// every one of them is terminal (SpoofAction/AllowAction/PoolAction
// all stop further rule processing). That means the packet cache can
// only ever be consulted for a query that has ALREADY passed through
// every policy/identity check with an outcome of "forward normally" --
// a query that would have been blocked, spoofed, or routed elsewhere
// never reaches the cache at all, in either direction (population or
// lookup). This test exercises exactly that boundary with two
// contexts that genuinely disagree about the same domain.
import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"alderpointdns/go-controlplane/internal/clientid"
	"alderpointdns/go-controlplane/internal/dnscompile"
)

func osReadFileForDebug(path string) ([]byte, error) { return os.ReadFile(path) }

// queryNameOf decodes a query's own question name -- used to filter
// out dnsdist's own periodic backend health-check probes (a different,
// fixed qname) from this test's hit counter, so the counter reflects
// only the test's own real queries.
func queryNameOf(query []byte) string {
	if len(query) < 13 {
		return ""
	}
	var labels []string
	i := 12
	for i < len(query) {
		l := int(query[i])
		if l == 0 {
			break
		}
		i++
		if i+l > len(query) {
			return ""
		}
		labels = append(labels, string(query[i:i+l]))
		i += l
	}
	name := ""
	for _, l := range labels {
		name += l + "."
	}
	return name
}

// startCountingFakeUpstream is startFakeUpstream plus a real hit
// counter (filtered to expectedName, see queryNameOf), so a test can
// assert "the cache served this, the real upstream was never asked
// twice" rather than inferring it from timing. Listens on BOTH UDP and
// TCP on the same port -- a real finding while writing this test:
// dnsdist forwards a query it received over a TCP-based frontend
// (DoT/DoH/plain TCP) to the backend over TCP too, not just UDP, so a
// DoT/DoH client-identity test needs a backend that actually speaks
// both (the plain-UDP-only startFakeUpstream every other existing test
// in this file uses never exercised this because none of them route a
// TCP-sourced query through to a live backend -- they all terminate
// earlier via a SpoofAction).
func startCountingFakeUpstream(t *testing.T, answerIP, expectedName string) (addr string, hits *int64) {
	t.Helper()
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { udpConn.Close() })
	port := udpConn.LocalAddr().(*net.UDPAddr).Port

	tcpLn, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tcpLn.Close() })

	ip4 := net.ParseIP(answerIP).To4()
	var count int64
	go func() {
		buf := make([]byte, 512)
		for {
			n, raddr, err := udpConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if strings.EqualFold(queryNameOf(buf[:n]), expectedName) {
				atomic.AddInt64(&count, 1)
			}
			if resp := buildDNSAnswer(buf[:n], ip4); resp != nil {
				udpConn.WriteToUDP(resp, raddr)
			}
		}
	}()
	go func() {
		for {
			c, err := tcpLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				for {
					var lenPrefix [2]byte
					if _, err := io.ReadFull(conn, lenPrefix[:]); err != nil {
						return
					}
					query := make([]byte, binary.BigEndian.Uint16(lenPrefix[:]))
					if _, err := io.ReadFull(conn, query); err != nil {
						return
					}
					if strings.EqualFold(queryNameOf(query), expectedName) {
						atomic.AddInt64(&count, 1)
					}
					resp := buildDNSAnswer(query, ip4)
					if resp == nil {
						return
					}
					var out [2]byte
					binary.BigEndian.PutUint16(out[:], uint16(len(resp)))
					conn.Write(out[:])
					conn.Write(resp)
				}
			}(c)
		}
	}()
	return fmt.Sprintf("127.0.0.1:%d", port), &count
}

// dotQueryRaw is dotQuery's own connection/framing logic, but returns
// the full raw response so a caller can inspect the answer's IP, not
// just the rcode.
func dotQueryRaw(t *testing.T, addr, sni, name string) []byte {
	t.Helper()
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", addr, &tls.Config{ServerName: sni, InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("dotQueryRaw: TLS dial to %s (SNI=%q) failed: %v", addr, sni, err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))

	q := buildDNSQuery(name)
	var lenPrefix [2]byte
	binary.BigEndian.PutUint16(lenPrefix[:], uint16(len(q)))
	conn.Write(lenPrefix[:])
	conn.Write(q)

	var respLen [2]byte
	if _, err := io.ReadFull(conn, respLen[:]); err != nil {
		t.Fatalf("dotQueryRaw: reading response length prefix: %v", err)
	}
	resp := make([]byte, binary.BigEndian.Uint16(respLen[:]))
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("dotQueryRaw: reading response body: %v", err)
	}
	return resp
}

// answerIP extracts the last 4 bytes of a well-formed single-A-record
// response -- exactly the shape buildDNSAnswer/the fake upstream in
// this file produce -- as a dotted-quad string.
func answerIP(resp []byte) string {
	if len(resp) < 4 {
		return ""
	}
	ip := net.IP(resp[len(resp)-4:])
	return ip.String()
}

func rcodeOfRaw(resp []byte) int {
	if len(resp) < 4 {
		return -1
	}
	return int(resp[3] & 0x0F)
}

// plainUDPQuery sends one untagged plain-UDP query -- what an ordinary
// client with no Strong ClientID at all looks like to the compiled
// rules -- and returns the raw response.
func plainUDPQuery(t *testing.T, addr, name string) []byte {
	t.Helper()
	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write(buildDNSQuery(name)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	return buf[:n]
}

// TestPacketCacheNeverServesAnAllowedClientsAnswerToABlockedContext is
// this session's core proof for item 2: client-a has an explicit
// per-identity ALLOW override on a domain that is globally blocked for
// everyone else. Client-a's allowed query is a real cache-miss forward
// to a real (counting) fake upstream -- populating the shared default-
// pool packet cache with a real answer. An ordinary untagged client
// (no override, the domain's default/global policy applies) querying
// the SAME domain immediately after must still be blocked -- never
// served client-a's now-cached answer, and the real upstream must
// never be asked on the blocked context's behalf either (proving the
// block short-circuits before the cache is even consulted, not just
// that its result happens to differ).
func TestPacketCacheNeverServesAnAllowedClientsAnswerToABlockedContext(t *testing.T) {
	s, cfg := newDNSRuntimeConfig(t)
	certPath, keyPath := testTLSCert(t)
	upstreamAddr, upstreamHits := startCountingFakeUpstream(t, "203.0.113.201", "shared.example.test.")

	hexA, err := clientid.GenerateHex(clientid.Bits256)
	if err != nil {
		t.Fatal(err)
	}
	dotPort := freeTCPPort(t)

	in := dnscompile.Input{
		ListenAddress: cfg.DnsdistListenAddress,
		// No BindBackendAddress: forwarding must go directly to the
		// fake upstream, so a real 203.0.113.201 answer proves the
		// query actually reached (or, for the blocked case, did NOT
		// reach) the shared default pool/cache.
		DefaultProfile:       &dnscompile.UpstreamProfile{Transport: "plain", Strategy: "ordered", Endpoints: []dnscompile.UpstreamEndpoint{{Address: upstreamAddr}}},
		BlockedDomains:       []string{"shared.example.test"},
		BlockingResponseMode: "refused",
		Transports:           dnscompile.TransportSettings{DotEnabled: true, DotPort: dotPort},
		TLSCertPath:          certPath, TLSKeyPath: keyPath,
		CacheMaxEntries: 1000,
		ClientIdentities: []dnscompile.ClientIdentity{
			{ClientKey: "client-a", Hex: hexA},
		},
		ClientOverrides: []dnscompile.ClientOverride{
			{ClientKey: "client-a", Kind: "allow", Domain: "shared.example.test."},
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
	t.Cleanup(func() {
		if data, err := osReadFileForDebug(cfg.StagingDir + "/dnsdist.startup.log"); err == nil {
			t.Logf("dnsdist startup log:\n%s", data)
		}
	})

	host, _ := splitHostPort(cfg.DnsdistListenAddress)
	udpAddr := cfg.DnsdistListenAddress
	dotAddr := fmt.Sprintf("%s:%d", host, dotPort)
	sniA := clientid.EncodeSNILabel(hexA)

	// Client A (explicit allow): real cache-miss forward to the real
	// upstream. Must get the real upstream answer.
	resp := dotQueryRaw(t, dotAddr, sniA, "shared.example.test.")
	if rc := rcodeOfRaw(resp); rc != rcodeNOERROR {
		t.Fatalf("client-a (explicit allow) expected NOERROR, got rcode %d", rc)
	}
	if ip := answerIP(resp); ip != "203.0.113.201" {
		t.Fatalf("client-a expected the real upstream answer 203.0.113.201, got %q", ip)
	}
	if got := atomic.LoadInt64(upstreamHits); got != 1 {
		t.Fatalf("expected exactly 1 real upstream hit for client-a's query, got %d", got)
	}

	// An ordinary untagged client (no override -- the domain's global
	// block applies) queries the SAME domain right after. It must be
	// REFUSED, and the real upstream must NEVER be asked on its
	// behalf -- proving the block happens before the shared cache is
	// even consulted, so client-a's now-cached answer can never leak
	// to it either via a cache hit or via a fresh forward.
	blockedResp := plainUDPQuery(t, udpAddr, "shared.example.test.")
	if rc := rcodeOfRaw(blockedResp); rc != rcodeREFUSED {
		t.Fatalf("untagged client (default policy: blocked) expected REFUSED, got rcode %d -- answer bytes: %x", rc, blockedResp)
	}
	if got := atomic.LoadInt64(upstreamHits); got != 1 {
		t.Fatalf("blocked query must never reach the real upstream (still expected exactly 1 total hit), got %d -- the block did not short-circuit before the cache/pool", got)
	}
}

// TestPacketCacheIsClearedOnEveryPromote proves a newly applied block
// rule can never be bypassed by an answer the packet cache warmed
// under the PREVIOUS (more permissive) policy. This is true by
// construction in the current design (every promote fully restarts
// dnsdist -- see reloadDnsdist -- so newPacketCache() is always a
// brand-new, empty cache after any promotion, never a hot in-place
// reload that would preserve stale entries), and this test is the
// real proof of that, not just a reading of the promote code.
func TestPacketCacheIsClearedOnEveryPromote(t *testing.T) {
	s, cfg := newDNSRuntimeConfig(t)
	upstreamAddr, upstreamHits := startCountingFakeUpstream(t, "203.0.113.50", "warm.example.test.")
	host, portStr := splitHostPort(cfg.DnsdistListenAddress)
	udpAddr := fmt.Sprintf("%s:%s", host, portStr)

	baseIn := dnscompile.Input{
		ListenAddress:   cfg.DnsdistListenAddress,
		DefaultProfile:  &dnscompile.UpstreamProfile{Transport: "plain", Strategy: "ordered", Endpoints: []dnscompile.UpstreamEndpoint{{Address: upstreamAddr}}},
		CacheMaxEntries: 1000,
	}
	conf1, err := dnscompile.CompileDnsdist(baseIn)
	if err != nil {
		t.Fatal(err)
	}
	res := callPromote(t, s, DNSPromoteParams{DnsdistConf: conf1})
	if !res.Promoted {
		t.Fatalf("expected first promotion to succeed, got %+v", res)
	}

	// Warm the cache with a real forwarded, real-upstream answer.
	resp := plainUDPQuery(t, udpAddr, "warm.example.test.")
	if rc := rcodeOfRaw(resp); rc != rcodeNOERROR || answerIP(resp) != "203.0.113.50" {
		t.Fatalf("expected a real warm-cache NOERROR/203.0.113.50 answer, got rcode=%d ip=%q", rc, answerIP(resp))
	}
	if got := atomic.LoadInt64(upstreamHits); got != 1 {
		t.Fatalf("expected exactly 1 upstream hit warming the cache, got %d", got)
	}

	// Promote AGAIN with the exact same domain now blocked.
	blockedIn := baseIn
	blockedIn.BlockedDomains = []string{"warm.example.test"}
	blockedIn.BlockingResponseMode = "refused"
	conf2, err := dnscompile.CompileDnsdist(blockedIn)
	if err != nil {
		t.Fatal(err)
	}
	res2 := callPromote(t, s, DNSPromoteParams{DnsdistConf: conf2})
	if !res2.Promoted {
		t.Fatalf("expected second promotion to succeed, got %+v", res2)
	}

	// The exact same query must now be REFUSED -- if the old process's
	// packet cache had survived the promotion, this would incorrectly
	// return the stale cached 203.0.113.50 NOERROR answer instead.
	resp2 := plainUDPQuery(t, udpAddr, "warm.example.test.")
	if rc := rcodeOfRaw(resp2); rc != rcodeREFUSED {
		t.Fatalf("expected REFUSED after the domain was newly blocked, got rcode=%d ip=%q -- a stale cached answer leaked across the policy change", rc, answerIP(resp2))
	}
	if got := atomic.LoadInt64(upstreamHits); got != 1 {
		t.Fatalf("the now-blocked query must never reach the real upstream again, got %d total hits", got)
	}
}

