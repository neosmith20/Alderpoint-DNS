package dnsanalytics

import (
	"context"
	"database/sql"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	dnstap "github.com/dnstap/golang-dnstap"
	"github.com/miekg/dns"
	"google.golang.org/protobuf/proto"
)

// Writer is the analytics producer: a dnstap Frame Streams unix-socket
// server fed directly by dnsdist (see internal/dnscompile's
// DnstapSocketPath wiring), decoding each real client-response message
// and durably inserting one query_events row per query. Entirely
// decoupled from the DNS hot path -- dnsdist's own FrameStreamLogger is
// asynchronous with a bounded internal queue and drops entries rather
// than block a query if this process is slow, unreachable, or not
// running at all (dnsdist's documented, designed behavior for exactly
// this use case). A dead or backed-up Writer therefore degrades
// analytics completeness, never DNS answering latency or correctness.
type Writer struct {
	DB  *sql.DB
	Log *slog.Logger

	// lastHeartbeat is updated by the accept/decode loop roughly once a
	// second regardless of query volume, so Health (reader.go) can tell
	// "listener alive, genuinely no traffic" apart from "listener loop
	// exited" -- the same distinction internal/pyanalytics/health.go's
	// doc comment identifies as the real V1.1.1 failure class this
	// governing task named.
	lastHeartbeat atomic.Int64 // unix seconds
	insertedTotal atomic.Int64
	decodeErrors  atomic.Int64

	mu      sync.Mutex
	batch   []event
	started bool
}

type event struct {
	ts        int64
	domain    string
	qtype     string
	rcode     string
	protocol  string
	client    string
	latencyMs float64
	outcome   string
}

// Heartbeat reports (unix seconds of last activity, whether it has ever
// started). A zero timestamp with started=true means the loop is up but
// has not yet ticked its first second -- callers should treat "just
// started" as fresh, not stale.
func (wtr *Writer) Heartbeat() (int64, bool) {
	return wtr.lastHeartbeat.Load(), wtr.started
}

func (wtr *Writer) Stats() (inserted, decodeErrors int64) {
	return wtr.insertedTotal.Load(), wtr.decodeErrors.Load()
}

// Run listens on socketPath (creating/replacing the unix socket file)
// and blocks, decoding dnstap frames and batching them into the
// database, until ctx is cancelled. Safe to run in its own goroutine;
// intended to run for the lifetime of the "web" process.
func (wtr *Writer) Run(ctx context.Context, socketPath string) error {
	input, err := dnstap.NewFrameStreamSockInputFromPath(socketPath)
	if err != nil {
		return err
	}
	input.SetTimeout(5 * time.Second)

	raw := make(chan []byte, 256)
	wtr.started = true
	wtr.lastHeartbeat.Store(time.Now().Unix())

	go input.ReadInto(raw)

	flush := time.NewTicker(500 * time.Millisecond)
	defer flush.Stop()
	heartbeat := time.NewTicker(1 * time.Second)
	defer heartbeat.Stop()
	prune := time.NewTicker(1 * time.Hour)
	defer prune.Stop()

	for {
		select {
		case <-ctx.Done():
			wtr.flush(context.Background())
			return nil
		case f := <-raw:
			if ev, ok := decodeFrame(f); ok {
				wtr.mu.Lock()
				wtr.batch = append(wtr.batch, ev)
				wtr.mu.Unlock()
			} else {
				wtr.decodeErrors.Add(1)
			}
		case <-flush.C:
			wtr.flush(ctx)
		case <-heartbeat.C:
			wtr.lastHeartbeat.Store(time.Now().Unix())
		case <-prune.C:
			wtr.pruneOld(ctx)
		}
	}
}

func (wtr *Writer) flush(ctx context.Context) {
	wtr.mu.Lock()
	batch := wtr.batch
	wtr.batch = nil
	wtr.mu.Unlock()
	if len(batch) == 0 {
		return
	}
	tx, err := wtr.DB.BeginTx(ctx, nil)
	if err != nil {
		if wtr.Log != nil {
			wtr.Log.Warn("dnsanalytics: begin tx failed, dropping batch", "err", err, "batch_size", len(batch))
		}
		return
	}
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO query_events
		(ts, domain, qtype, rcode, protocol, client, latency_ms, outcome)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		tx.Rollback()
		if wtr.Log != nil {
			wtr.Log.Warn("dnsanalytics: prepare insert failed, dropping batch", "err", err)
		}
		return
	}
	for _, ev := range batch {
		if _, err := stmt.ExecContext(ctx, ev.ts, ev.domain, ev.qtype, ev.rcode, ev.protocol, ev.client, ev.latencyMs, ev.outcome); err != nil {
			if wtr.Log != nil {
				wtr.Log.Warn("dnsanalytics: insert failed", "err", err)
			}
		}
	}
	stmt.Close()
	if err := tx.Commit(); err != nil {
		if wtr.Log != nil {
			wtr.Log.Warn("dnsanalytics: commit failed, batch lost", "err", err, "batch_size", len(batch))
		}
		return
	}
	wtr.insertedTotal.Add(int64(len(batch)))
}

// retentionSeconds bounds query_events growth on appliance-class disks.
// 35 days comfortably covers the "Last 7 Days" requirement with margin;
// this is a disclosed operational choice, not a requirement from the
// governing task.
const retentionSeconds = 35 * 24 * 3600

func (wtr *Writer) pruneOld(ctx context.Context) {
	cutoff := time.Now().Unix() - retentionSeconds
	if _, err := wtr.DB.ExecContext(ctx, `DELETE FROM query_events WHERE ts < ?`, cutoff); err != nil && wtr.Log != nil {
		wtr.Log.Warn("dnsanalytics: prune failed", "err", err)
	}
}

// decodeFrame turns one raw dnstap Frame Streams payload into an event.
// Returns ok=false for anything that isn't a decodable message carrying
// a real DNS response (malformed frame, query-only message, etc.) --
// never panics on attacker- or bug-controlled input, since this reads
// directly off a socket dnsdist writes to.
func decodeFrame(raw []byte) (event, bool) {
	var dt dnstap.Dnstap
	if err := proto.Unmarshal(raw, &dt); err != nil || dt.Message == nil {
		return event{}, false
	}
	m := dt.Message
	if len(m.ResponseMessage) == 0 {
		return event{}, false
	}
	var resp dns.Msg
	if err := resp.Unpack(m.ResponseMessage); err != nil || len(resp.Question) == 0 {
		return event{}, false
	}

	outcome := OutcomeAllowed
	if len(dt.Extra) > 0 && strings.TrimSpace(string(dt.Extra)) == OutcomeBlocked {
		outcome = OutcomeBlocked
	}

	ts := time.Now().Unix()
	if m.ResponseTimeSec != nil {
		ts = int64(*m.ResponseTimeSec)
	}

	var latencyMs float64
	if m.QueryTimeSec != nil && m.ResponseTimeSec != nil {
		qns := int64(*m.QueryTimeSec) * 1e9
		rns := int64(*m.ResponseTimeSec) * 1e9
		if m.QueryTimeNsec != nil {
			qns += int64(*m.QueryTimeNsec)
		}
		if m.ResponseTimeNsec != nil {
			rns += int64(*m.ResponseTimeNsec)
		}
		if d := rns - qns; d >= 0 {
			latencyMs = float64(d) / 1e6
		}
	}

	protocol := "udp"
	if m.SocketProtocol != nil && *m.SocketProtocol == dnstap.SocketProtocol_TCP {
		protocol = "tcp"
	}

	client := ""
	if len(m.QueryAddress) == 4 || len(m.QueryAddress) == 16 {
		client = net.IP(m.QueryAddress).String()
	}

	domain := strings.ToLower(strings.TrimSuffix(resp.Question[0].Name, "."))
	qtype := dns.TypeToString[resp.Question[0].Qtype]
	rcode := dns.RcodeToString[resp.Rcode]

	return event{
		ts: ts, domain: domain, qtype: qtype, rcode: rcode,
		protocol: protocol, client: client, latencyMs: latencyMs, outcome: outcome,
	}, true
}
