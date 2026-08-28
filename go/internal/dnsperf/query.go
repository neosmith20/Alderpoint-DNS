// Package dnsperf is a native Go port of app/v2/dns_performance.py's
// low-level query engine: build one DNS question packet, exchange it
// over UDP/TCP/DoT/DoH (optionally over an already-established
// connection, matching Python's query_once/query_many_established), and
// summarize a batch of samples with the same percentile math. Field-
// matched against the Python source, read directly, not guessed.
//
// This package has no host-network-reachability assumptions of its own
// -- callers decide where it's safe to run it from. In this migration
// that's internal/hostagentd (root, real host network namespace), the
// same "web container is isolated, hostagent is not" boundary already
// documented for Cache/Replication/Network Configuration.
package dnsperf

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"
)

// Sample is one query's real, observed outcome -- never synthesized.
// Field-matches Python's per-sample dict.
type Sample struct {
	OK        bool    `json:"ok"`
	Timeout   bool    `json:"timeout"`
	LatencyMs float64 `json:"latency_ms"`
	RCode     *int    `json:"rcode,omitempty"`
	Bytes     int     `json:"bytes,omitempty"`
	Error     string  `json:"error,omitempty"`
}

// Summary mirrors Python's summarize() exactly, including its
// ceil-based percentile indexing.
type Summary struct {
	Count    int      `json:"count"`
	Success  int      `json:"success"`
	Timeouts int      `json:"timeouts"`
	Errors   int      `json:"errors"`
	P50Ms    *float64 `json:"p50_ms"`
	P95Ms    *float64 `json:"p95_ms"`
	P99Ms    *float64 `json:"p99_ms"`
	MaxMs    *float64 `json:"max_ms"`
	ServFail int      `json:"servfail"`
	NXDomain int      `json:"nxdomain"`
}

func round3(v float64) float64 { return math.Round(v*1000) / 1000 }

// Percentile matches Python's _percentile: ceil((pct/100)*n)-1, clamped
// into range, against the sorted slice.
func Percentile(values []float64, pct float64) (float64, bool) {
	if len(values) == 0 {
		return 0, false
	}
	ordered := append([]float64(nil), values...)
	sort.Float64s(ordered)
	idx := int(math.Ceil((pct/100.0)*float64(len(ordered)))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx > len(ordered)-1 {
		idx = len(ordered) - 1
	}
	return ordered[idx], true
}

func median(values []float64) float64 {
	ordered := append([]float64(nil), values...)
	sort.Float64s(ordered)
	n := len(ordered)
	if n%2 == 1 {
		return ordered[n/2]
	}
	return (ordered[n/2-1] + ordered[n/2]) / 2
}

// Summarize matches Python's summarize() field-for-field.
func Summarize(samples []Sample) Summary {
	var latencies []float64
	errors := 0
	timeouts := 0
	servfail := 0
	nxdomain := 0
	for _, s := range samples {
		if s.OK && !s.Timeout {
			latencies = append(latencies, s.LatencyMs)
		}
		if !s.OK {
			errors++
		}
		if s.Timeout {
			timeouts++
		}
		if s.RCode != nil && *s.RCode == 2 {
			servfail++
		}
		if s.RCode != nil && *s.RCode == 3 {
			nxdomain++
		}
	}
	out := Summary{Count: len(samples), Success: len(latencies), Timeouts: timeouts, Errors: errors, ServFail: servfail, NXDomain: nxdomain}
	if len(latencies) > 0 {
		p50 := round3(median(latencies))
		out.P50Ms = &p50
		if p95, ok := Percentile(latencies, 95); ok {
			v := round3(p95)
			out.P95Ms = &v
		}
		if p99, ok := Percentile(latencies, 99); ok {
			v := round3(p99)
			out.P99Ms = &v
		}
		max := latencies[0]
		for _, v := range latencies {
			if v > max {
				max = v
			}
		}
		maxv := round3(max)
		out.MaxMs = &maxv
	}
	return out
}

// --- packet construction / parsing (matches Python's _question/_query_packet/_rcode) ---

func question(name string, qtype uint16) []byte {
	name = strings.TrimSuffix(name, ".")
	var body []byte
	if name != "" {
		for _, label := range strings.Split(name, ".") {
			if label == "" {
				continue
			}
			body = append(body, byte(len(label)))
			body = append(body, []byte(label)...)
		}
	}
	body = append(body, 0x00)
	tail := make([]byte, 4)
	binary.BigEndian.PutUint16(tail[0:2], qtype)
	binary.BigEndian.PutUint16(tail[2:4], 1) // IN class
	return append(body, tail...)
}

func queryPacket(name string, qtype uint16) (uint16, []byte) {
	id := uint16(rand.Intn(65535) + 1)
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], id)
	binary.BigEndian.PutUint16(header[2:4], 0x0100) // RD=1
	binary.BigEndian.PutUint16(header[4:6], 1)      // QDCOUNT=1
	return id, append(header, question(name, qtype)...)
}

func rcodeOf(packet []byte) *int {
	if len(packet) < 12 {
		return nil
	}
	v := int(packet[3] & 0x0F)
	return &v
}

func responseID(data []byte) (uint16, bool) {
	if len(data) < 2 {
		return 0, false
	}
	return binary.BigEndian.Uint16(data[:2]), true
}

func recvExact(r io.Reader, size int) ([]byte, error) {
	buf := make([]byte, 0, size)
	tmp := make([]byte, size)
	for len(buf) < size {
		n, err := r.Read(tmp[:size-len(buf)])
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			return buf, err
		}
		if n == 0 {
			break
		}
	}
	return buf, nil
}

func tcpExchange(conn net.Conn, packet []byte) ([]byte, error) {
	lenPrefix := make([]byte, 2)
	binary.BigEndian.PutUint16(lenPrefix, uint16(len(packet)))
	if _, err := conn.Write(append(lenPrefix, packet...)); err != nil {
		return nil, err
	}
	hdr, err := recvExact(conn, 2)
	if err != nil {
		return nil, err
	}
	if len(hdr) != 2 {
		return nil, fmt.Errorf("short TCP length header")
	}
	size := int(binary.BigEndian.Uint16(hdr))
	return recvExact(conn, size)
}

func dohExchange(client *http.Client, url, path string, packet []byte) ([]byte, error) {
	req, err := http.NewRequest(http.MethodPost, url+path, strings.NewReader(string(packet)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("content-type", "application/dns-message")
	req.Header.Set("accept", "application/dns-message")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH HTTP %d", resp.StatusCode)
	}
	return body, nil
}

// insecureTLSConfig matches Python's _tls_context(): this is an
// internal performance diagnostic against the appliance's own
// self-signed cert, timing the DNS exchange itself, not chain
// validation.
func insecureTLSConfig() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true} //nolint:gosec
}

// QueryOnce matches Python's query_once: one full exchange (including
// connection setup for tcp/dot/doh), timed with a monotonic clock.
func QueryOnce(ctx context.Context, server string, port int, name string, qtype uint16, protocol string, timeout time.Duration, path string) Sample {
	id, packet := queryPacket(name, qtype)
	started := time.Now()
	elapsed := func() float64 { return float64(time.Since(started)) / float64(time.Millisecond) }

	var data []byte
	var err error
	switch protocol {
	case "tcp":
		var conn net.Conn
		conn, err = net.DialTimeout("tcp", fmt.Sprintf("%s:%d", server, port), timeout)
		if err == nil {
			conn.SetDeadline(time.Now().Add(timeout))
			data, err = tcpExchange(conn, packet)
			conn.Close()
		}
	case "dot":
		var conn net.Conn
		conn, err = net.DialTimeout("tcp", fmt.Sprintf("%s:%d", server, port), timeout)
		if err == nil {
			conn.SetDeadline(time.Now().Add(timeout))
			tlsConn := tls.Client(conn, insecureTLSConfig())
			if hsErr := tlsConn.HandshakeContext(ctx); hsErr != nil {
				err = hsErr
			} else {
				data, err = tcpExchange(tlsConn, packet)
			}
			tlsConn.Close()
		}
	case "doh":
		client := &http.Client{Timeout: timeout, Transport: &http.Transport{TLSClientConfig: insecureTLSConfig()}}
		data, err = dohExchange(client, fmt.Sprintf("https://%s:%d", server, port), path, packet)
	default: // "udp"
		var conn net.Conn
		conn, err = net.DialTimeout("udp", fmt.Sprintf("%s:%d", server, port), timeout)
		if err == nil {
			conn.SetDeadline(time.Now().Add(timeout))
			if _, werr := conn.Write(packet); werr != nil {
				err = werr
			} else {
				buf := make([]byte, 4096)
				var n int
				n, err = conn.Read(buf)
				if err == nil {
					data = buf[:n]
				}
			}
			conn.Close()
		}
	}
	if err != nil {
		return Sample{OK: false, Timeout: true, LatencyMs: elapsed(), Error: err.Error()}
	}
	rid, ok := responseID(data)
	return Sample{OK: ok && rid == id, Timeout: false, LatencyMs: elapsed(), RCode: rcodeOf(data), Bytes: len(data)}
}

// EstablishedCase is the subset of BenchmarkCase needed by
// QueryManyEstablished.
type EstablishedCase struct {
	Server, Domain, Path string
	Port                 int
	QType                uint16
	Protocol             string // "dot-established" | "doh-established"
	Queries              int
	Timeout              time.Duration
}

// QueryManyEstablished matches Python's query_many_established: one
// connection/TLS-session set up once, then every query in the batch
// reuses it -- distinct latency semantics from QueryOnce (which times
// connection setup on every single query).
func QueryManyEstablished(ctx context.Context, c EstablishedCase) []Sample {
	protocol := strings.TrimSuffix(c.Protocol, "-established")
	samples := make([]Sample, 0, max(1, c.Queries))

	switch protocol {
	case "dot":
		raw, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", c.Server, c.Port), c.Timeout)
		if err != nil {
			return []Sample{{OK: false, Timeout: true, Error: "connection setup failed: " + err.Error()}}
		}
		defer raw.Close()
		tlsConn := tls.Client(raw, insecureTLSConfig())
		defer tlsConn.Close()
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return []Sample{{OK: false, Timeout: true, Error: "connection setup failed: " + err.Error()}}
		}
		for i := 0; i < max(1, c.Queries); i++ {
			tlsConn.SetDeadline(time.Now().Add(c.Timeout))
			id, packet := queryPacket(c.Domain, c.QType)
			started := time.Now()
			data, err := tcpExchange(tlsConn, packet)
			elapsed := float64(time.Since(started)) / float64(time.Millisecond)
			if err != nil {
				samples = append(samples, Sample{OK: false, Timeout: true, LatencyMs: elapsed, Error: err.Error()})
				continue
			}
			rid, ok := responseID(data)
			samples = append(samples, Sample{OK: ok && rid == id, Timeout: false, LatencyMs: elapsed, RCode: rcodeOf(data), Bytes: len(data)})
		}
	case "doh":
		client := &http.Client{Timeout: c.Timeout, Transport: &http.Transport{TLSClientConfig: insecureTLSConfig()}}
		url := fmt.Sprintf("https://%s:%d", c.Server, c.Port)
		for i := 0; i < max(1, c.Queries); i++ {
			id, packet := queryPacket(c.Domain, c.QType)
			started := time.Now()
			data, err := dohExchange(client, url, c.Path, packet)
			elapsed := float64(time.Since(started)) / float64(time.Millisecond)
			if err != nil {
				samples = append(samples, Sample{OK: false, Timeout: true, LatencyMs: elapsed, Error: err.Error()})
				continue
			}
			rid, ok := responseID(data)
			samples = append(samples, Sample{OK: ok && rid == id, Timeout: false, LatencyMs: elapsed, RCode: rcodeOf(data), Bytes: len(data)})
		}
	default:
		return []Sample{{OK: false, Timeout: true, Error: fmt.Sprintf("unsupported established protocol: %s", c.Protocol)}}
	}
	return samples
}
