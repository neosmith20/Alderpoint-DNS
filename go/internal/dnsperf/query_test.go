package dnsperf

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"
)

func genCertKeyPair(t *testing.T) tls.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-cert"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"127.0.0.1", "localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// dnsReply builds a minimal, well-formed DNS response echoing the
// request's ID and an A-record answer -- a real wire-format reply, not
// a canned byte string copy-pasted from elsewhere.
func dnsReply(query []byte) []byte {
	if len(query) < 12 {
		return query
	}
	id := query[:2]
	resp := make([]byte, 0, 32)
	resp = append(resp, id...)
	resp = append(resp, 0x81, 0x80) // response, no error
	resp = append(resp, 0x00, 0x01) // QDCOUNT=1
	resp = append(resp, 0x00, 0x01) // ANCOUNT=1
	resp = append(resp, 0x00, 0x00, 0x00, 0x00)
	resp = append(resp, query[12:]...) // echo question section
	resp = append(resp, 0xC0, 0x0C)    // pointer to name
	resp = append(resp, 0x00, 0x01)    // TYPE A
	resp = append(resp, 0x00, 0x01)    // CLASS IN
	resp = append(resp, 0x00, 0x00, 0x00, 0x3C)
	resp = append(resp, 0x00, 0x04)
	resp = append(resp, 127, 0, 0, 1)
	return resp
}

func startUDPResponder(t *testing.T) (port int, stop func()) {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		buf := make([]byte, 512)
		for {
			conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, addr, err := conn.ReadFromUDP(buf)
			select {
			case <-done:
				return
			default:
			}
			if err != nil {
				continue
			}
			conn.WriteToUDP(dnsReply(buf[:n]), addr)
		}
	}()
	return conn.LocalAddr().(*net.UDPAddr).Port, func() { close(done); conn.Close() }
}

func startTCPResponder(t *testing.T) (port int, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go serveTCPFramed(ln)
	return ln.Addr().(*net.TCPAddr).Port, func() { ln.Close() }
}

func serveTCPFramed(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			for {
				hdr := make([]byte, 2)
				if _, err := readFull(c, hdr); err != nil {
					return
				}
				size := int(binary.BigEndian.Uint16(hdr))
				body := make([]byte, size)
				if _, err := readFull(c, body); err != nil {
					return
				}
				reply := dnsReply(body)
				out := make([]byte, 2+len(reply))
				binary.BigEndian.PutUint16(out[:2], uint16(len(reply)))
				copy(out[2:], reply)
				c.Write(out)
			}
		}(conn)
	}
}

func readFull(c net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := c.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func startDoTResponder(t *testing.T) (port int, stop func()) {
	t.Helper()
	cert := genCertKeyPair(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	go serveTCPFramed(ln)
	return ln.Addr().(*net.TCPAddr).Port, func() { ln.Close() }
}

func startDoHResponder(t *testing.T) (port int, stop func()) {
	t.Helper()
	cert := genCertKeyPair(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/dns-query", func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 512)
		n, _ := r.Body.Read(buf)
		w.Header().Set("content-type", "application/dns-message")
		w.Write(dnsReply(buf[:n]))
	})
	srv := &http.Server{Handler: mux, TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}}}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.ServeTLS(ln, "", "")
	return ln.Addr().(*net.TCPAddr).Port, func() { srv.Close() }
}

func TestQueryOnceUDPReal(t *testing.T) {
	port, stop := startUDPResponder(t)
	defer stop()
	s := QueryOnce(context.Background(), "127.0.0.1", port, "example.com.", 1, "udp", 2*time.Second, "")
	if !s.OK || s.Timeout {
		t.Fatalf("expected ok sample, got %+v", s)
	}
	if s.RCode == nil || *s.RCode != 0 {
		t.Fatalf("expected rcode 0, got %+v", s.RCode)
	}
}

func TestQueryOnceTCPReal(t *testing.T) {
	port, stop := startTCPResponder(t)
	defer stop()
	s := QueryOnce(context.Background(), "127.0.0.1", port, "example.com.", 1, "tcp", 2*time.Second, "")
	if !s.OK || s.Timeout {
		t.Fatalf("expected ok sample, got %+v", s)
	}
}

func TestQueryOnceDoTReal(t *testing.T) {
	port, stop := startDoTResponder(t)
	defer stop()
	s := QueryOnce(context.Background(), "127.0.0.1", port, "example.com.", 1, "dot", 2*time.Second, "")
	if !s.OK || s.Timeout {
		t.Fatalf("expected ok sample, got %+v", s)
	}
}

func TestQueryOnceDoHReal(t *testing.T) {
	port, stop := startDoHResponder(t)
	defer stop()
	s := QueryOnce(context.Background(), "127.0.0.1", port, "example.com.", 1, "doh", 2*time.Second, "/dns-query")
	if !s.OK || s.Timeout {
		t.Fatalf("expected ok sample, got %+v", s)
	}
}

func TestQueryOnceUDPTimeout(t *testing.T) {
	// Bind a socket that never replies.
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	port := conn.LocalAddr().(*net.UDPAddr).Port
	s := QueryOnce(context.Background(), "127.0.0.1", port, "example.com.", 1, "udp", 200*time.Millisecond, "")
	if s.OK || !s.Timeout {
		t.Fatalf("expected timeout sample, got %+v", s)
	}
}

func TestQueryManyEstablishedDoTReal(t *testing.T) {
	port, stop := startDoTResponder(t)
	defer stop()
	samples := QueryManyEstablished(context.Background(), EstablishedCase{
		Server: "127.0.0.1", Port: port, Domain: "example.com.", QType: 1,
		Protocol: "dot-established", Queries: 5, Timeout: 2 * time.Second,
	})
	if len(samples) != 5 {
		t.Fatalf("expected 5 samples, got %d", len(samples))
	}
	for _, s := range samples {
		if !s.OK || s.Timeout {
			t.Fatalf("expected ok sample, got %+v", s)
		}
	}
}

func TestQueryManyEstablishedDoHReal(t *testing.T) {
	port, stop := startDoHResponder(t)
	defer stop()
	samples := QueryManyEstablished(context.Background(), EstablishedCase{
		Server: "127.0.0.1", Port: port, Domain: "example.com.", QType: 1, Path: "/dns-query",
		Protocol: "doh-established", Queries: 5, Timeout: 2 * time.Second,
	})
	if len(samples) != 5 {
		t.Fatalf("expected 5 samples, got %d", len(samples))
	}
	for _, s := range samples {
		if !s.OK || s.Timeout {
			t.Fatalf("expected ok sample, got %+v", s)
		}
	}
}

func TestPercentileMatchesPythonCeilIndexing(t *testing.T) {
	values := []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	// Python: idx = min(len-1, max(0, ceil((95/100)*10)-1)) = ceil(9.5)-1 = 10-1 = 9 -> ordered[9] = 10
	if v, _ := Percentile(values, 95); v != 10 {
		t.Fatalf("p95 = %v, want 10", v)
	}
	// ceil((50/100)*10)-1 = ceil(5)-1 = 4 -> ordered[4] = 5
	if v, _ := Percentile(values, 50); v != 5 {
		t.Fatalf("p50-via-percentile = %v, want 5", v)
	}
}

func TestSummarizeMatchesPythonShape(t *testing.T) {
	rc0 := 0
	rc2 := 2
	rc3 := 3
	samples := []Sample{
		{OK: true, LatencyMs: 10, RCode: &rc0},
		{OK: true, LatencyMs: 20, RCode: &rc0},
		{OK: true, LatencyMs: 30, RCode: &rc0},
		{OK: false, Timeout: true, LatencyMs: 2000},
		{OK: true, LatencyMs: 5, RCode: &rc2},
		{OK: true, LatencyMs: 5, RCode: &rc3},
	}
	sum := Summarize(samples)
	if sum.Count != 6 || sum.Success != 5 || sum.Timeouts != 1 || sum.Errors != 1 {
		t.Fatalf("unexpected summary: %+v", sum)
	}
	if sum.ServFail != 1 || sum.NXDomain != 1 {
		t.Fatalf("unexpected rcode tallies: %+v", sum)
	}
	if sum.P50Ms == nil || sum.MaxMs == nil || *sum.MaxMs != 30 {
		t.Fatalf("unexpected percentile fields: %+v", sum)
	}
}

func TestSummarizeEmptyNeverFakesZero(t *testing.T) {
	sum := Summarize(nil)
	if sum.P50Ms != nil || sum.P95Ms != nil || sum.P99Ms != nil || sum.MaxMs != nil {
		t.Fatalf("empty samples must report nil percentiles, not fake zeroes: %+v", sum)
	}
}
