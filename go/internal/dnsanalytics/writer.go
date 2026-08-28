package dnsanalytics

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	dnstap "github.com/dnstap/golang-dnstap"
	"github.com/miekg/dns"
	"google.golang.org/protobuf/proto"
)

// TrafficProbe reports a monotonically-increasing count of real DNS
// traffic reaching the appliance, from an observation point entirely
// independent of dnstap/dnsdist -- the live "web" process wires this to
// a real apdns-hostagent cache.status RPC summing BIND's own
// statistics-channel cachestats hits+misses (see
// cmd/alderpointdns-go/main.go). That independence is the whole point:
// it's what lets the watchdog below tell "dnstap pipe genuinely stalled
// while real queries keep flowing" apart from "household network is
// just quiet right now" -- something a dnsdist/dnstap-derived signal
// could never do, since it would go quiet for the exact same reason the
// thing it's supposed to be diagnosing did.
//
// ok=false means the probe could not be evaluated right now (e.g.
// apdns-hostagent unreachable) -- callers must treat that as "unknown",
// never as "count=0, confirmed no traffic".
type TrafficProbe func(ctx context.Context) (count int64, ok bool)

// Real, live-observed constants (see the 2026-08-28 session's
// alderpointdns-go-live-analytics-dnstap diagnostic history): dnsdist's
// fstrm connection to this Writer can go silently idle -- stays
// established at the socket level, stops delivering frames, no error on
// either side -- for a multi-minute, apparently unbounded stretch.
// dnsdist's own FrameStream logger only ever reconnects on a real write
// error; it never spontaneously notices a one-sided stall. The fix
// implemented below: this receiver actively closes its accepted
// connection once it has independent evidence (via TrafficProbe) that
// real traffic is flowing but no frames are arriving -- that forces
// dnsdist's next write to fail, which IS a real error dnsdist's own
// logger reacts to by reconnecting.
const (
	// ingestionStaleThreshold is how long with zero frames before a
	// stall becomes a *candidate* -- always cross-checked against
	// TrafficProbe before being treated as real (see watchdog).
	ingestionStaleThreshold = 45 * time.Second
	// watchdogInterval is how often the cross-check runs.
	watchdogInterval = 15 * time.Second
	// recoveryCooldown rate-limits forced reconnects so a slow-to-settle
	// dnsdist restart can't be thrashed into repeated forced closes.
	recoveryCooldown = 20 * time.Second
	// minTrafficDeltaToFlagStall: require more than a couple of BIND
	// queries' worth of movement before concluding "traffic is really
	// flowing" -- guards against a single stray retried query producing
	// a false positive right at the threshold.
	minTrafficDeltaToFlagStall = 2
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

	// TrafficProbe, when set, is consulted by the stall watchdog (see
	// this file's own doc comment on the type). nil is a valid,
	// supported "no probe wired" state -- Health then reports degraded
	// rather than silently trusting a stale pipe (see reader.go).
	TrafficProbe TrafficProbe

	// lastHeartbeat is updated by the accept/decode loop roughly once a
	// second regardless of query volume, so Health (reader.go) can tell
	// "listener alive, genuinely no traffic" apart from "listener loop
	// exited" -- the same distinction internal/pyanalytics/health.go's
	// doc comment identifies as the real V1.1.1 failure class this
	// governing task named. Note this alone CANNOT detect the silent
	// fstrm stall this package was built to survive (see lastFrameAt).
	lastHeartbeat atomic.Int64 // unix seconds
	// startedAt is when Run began listening -- used as the ingestion-age
	// baseline before the very first frame of this process's lifetime
	// ever arrives (lastFrameAt stays 0 until then).
	startedAt atomic.Int64
	// lastFrameAt is updated only when a real dnstap frame is
	// successfully decoded -- the actual "is data flowing" signal,
	// distinct from lastHeartbeat above.
	lastFrameAt   atomic.Int64
	insertedTotal atomic.Int64
	decodeErrors  atomic.Int64

	// stalled/recoveryCount/lastRecoveryAt/lastProbeOK are the
	// watchdog's own findings, surfaced by Ingestion() to reader.go's
	// Health.
	stalled        atomic.Bool
	recoveryCount  atomic.Int64
	lastRecoveryAt atomic.Int64
	lastProbeOK    atomic.Bool

	connsMu sync.Mutex
	conns   map[uint64]net.Conn

	// lastProbeCount/haveProbeBaseline are watchdog-only state, kept as
	// Writer fields (rather than local variables inside watchdog) so
	// checkIngestionOnce can be driven directly and repeatedly by a
	// test without waiting on real timers.
	lastProbeCount    atomic.Int64
	haveProbeBaseline atomic.Bool

	// StaleThreshold/WatchdogInterval override the package defaults
	// (ingestionStaleThreshold/watchdogInterval) when non-zero -- tests
	// only; production leaves these unset.
	StaleThreshold   time.Duration
	WatchdogInterval time.Duration

	mu      sync.Mutex
	batch   []event
	started bool
}

func (wtr *Writer) staleThreshold() time.Duration {
	if wtr.StaleThreshold > 0 {
		return wtr.StaleThreshold
	}
	return ingestionStaleThreshold
}

func (wtr *Writer) watchdogInterval() time.Duration {
	if wtr.WatchdogInterval > 0 {
		return wtr.WatchdogInterval
	}
	return watchdogInterval
}

// IngestionStatus is Ingestion()'s result -- see reader.go's Health for
// how each field demotes (or doesn't) the overall analytics status.
type IngestionStatus struct {
	LastFrameAt            int64
	FrameAgeSeconds        float64
	Stalled                bool
	RecoveryCount          int64
	LastRecoveryAt         int64
	TrafficProbeConfigured bool
	TrafficProbeOK         bool
}

// Ingestion reports the watchdog's current findings. Safe to call
// before Run starts (all zero values -- reader.go's existing
// started/Heartbeat check already covers "not started" separately).
func (wtr *Writer) Ingestion() IngestionStatus {
	last := wtr.lastFrameAt.Load()
	baseline := wtr.startedAt.Load()
	if last != 0 {
		baseline = last
	}
	age := float64(0)
	if baseline != 0 {
		age = time.Since(time.Unix(baseline, 0)).Seconds()
	}
	return IngestionStatus{
		LastFrameAt:            last,
		FrameAgeSeconds:        age,
		Stalled:                wtr.stalled.Load(),
		RecoveryCount:          wtr.recoveryCount.Load(),
		LastRecoveryAt:         wtr.lastRecoveryAt.Load(),
		TrafficProbeConfigured: wtr.TrafficProbe != nil,
		TrafficProbeOK:         wtr.lastProbeOK.Load(),
	}
}

func (wtr *Writer) trackConn(id uint64, c net.Conn) {
	wtr.connsMu.Lock()
	if wtr.conns == nil {
		wtr.conns = make(map[uint64]net.Conn)
	}
	wtr.conns[id] = c
	wtr.connsMu.Unlock()
}

func (wtr *Writer) untrackConn(id uint64) {
	wtr.connsMu.Lock()
	delete(wtr.conns, id)
	wtr.connsMu.Unlock()
}

// closeAllConns forcibly closes every currently-accepted dnstap
// connection -- the recovery action: closing our end turns dnsdist's
// next write into a real error, which IS something dnsdist's own
// FrameStream logger reacts to by reconnecting (unlike a one-sided
// silent stall, which it never notices on its own). Returns how many
// connections were closed, for logging/diagnostics.
func (wtr *Writer) closeAllConns() int {
	wtr.connsMu.Lock()
	conns := make([]net.Conn, 0, len(wtr.conns))
	for _, c := range wtr.conns {
		conns = append(conns, c)
	}
	wtr.connsMu.Unlock()
	for _, c := range conns {
		c.Close()
	}
	return len(conns)
}

// dnstapLoggerAdapter routes golang-dnstap's own internal connection
// accept/close/error log lines (otherwise silent) through this
// package's slog.Logger -- added live 2026-08-28 while diagnosing a
// real, unresolved intermittent stall where dnsdist's fstrm connection
// stays established (confirmed via `ss`) but stops delivering frames
// with no error on either side; this at least makes golang-dnstap's own
// side of that story visible in the process's normal logs going
// forward.
type dnstapLoggerAdapter struct{ log *slog.Logger }

func (a dnstapLoggerAdapter) Printf(format string, v ...interface{}) {
	a.log.Info("dnsanalytics: dnstap transport", "msg", fmt.Sprintf(format, v...))
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
//
// Unlike a plain dnstap.NewFrameStreamSockInputFromPath, this manages
// its own accept loop so it can retain and, when the watchdog below
// declares a real stall, forcibly close the currently-accepted
// connection(s) -- see closeAllConns's doc comment for why that's the
// actual fix, not just detection.
func (wtr *Writer) Run(ctx context.Context, socketPath string) error {
	os.Remove(socketPath)
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return err
	}
	defer ln.Close()

	raw := make(chan []byte, 256)
	wtr.started = true
	now := time.Now().Unix()
	wtr.lastHeartbeat.Store(now)
	wtr.startedAt.Store(now)

	go wtr.acceptLoop(ctx, ln, raw)
	go wtr.watchdog(ctx)

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
				wtr.lastFrameAt.Store(time.Now().Unix())
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

// acceptLoop mirrors dnstap.FrameStreamSockInput.ReadInto, with one
// addition: every accepted connection is tracked (trackConn/
// untrackConn) so the watchdog can forcibly close it on a confirmed
// stall.
func (wtr *Writer) acceptLoop(ctx context.Context, ln net.Listener, raw chan []byte) {
	var connID uint64
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return // Run is shutting down; the listener close caused this Accept error
			}
			if wtr.Log != nil {
				wtr.Log.Warn("dnsanalytics: accept failed", "err", err)
			}
			continue
		}
		id := atomic.AddUint64(&connID, 1)
		wtr.trackConn(id, conn)

		// Timeout only governs the initial handshake/control-message
		// exchange (see golang-dnstap's own ReaderOptions.Timeout doc
		// comment) -- it does NOT apply to steady-state frame reads,
		// which is exactly why a stalled connection blocks forever
		// here rather than erroring on its own; recovery is the
		// watchdog's forced Close, not this timeout.
		input, err := dnstap.NewFrameStreamInputTimeout(conn, true, 5*time.Second)
		if err != nil {
			if wtr.Log != nil {
				wtr.Log.Warn("dnsanalytics: opening frame stream input failed", "conn_id", id, "err", err)
			}
			wtr.untrackConn(id)
			conn.Close()
			continue
		}
		if wtr.Log != nil {
			input.SetLogger(dnstapLoggerAdapter{wtr.Log})
			wtr.Log.Info("dnsanalytics: accepted dnstap connection", "conn_id", id)
		}
		go func(id uint64, input *dnstap.FrameStreamInput, conn net.Conn) {
			input.ReadInto(raw)
			wtr.untrackConn(id)
			conn.Close()
			if wtr.Log != nil {
				wtr.Log.Info("dnsanalytics: dnstap connection closed", "conn_id", id)
			}
		}(id, input, conn)
	}
}

// watchdog is the active bounded health probe: it periodically asks
// whether real DNS traffic (via TrafficProbe, an observation point
// entirely independent of dnstap) is flowing while no dnstap frames
// have arrived for longer than ingestionStaleThreshold. Only that
// combination -- stale AND independently-confirmed real traffic -- is
// treated as a genuine stall; stale with quiet/unconfirmable traffic is
// left alone rather than thrashing a healthy-but-idle connection.
func (wtr *Writer) watchdog(ctx context.Context) {
	t := time.NewTicker(wtr.watchdogInterval())
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			wtr.checkIngestionOnce(ctx)
		}
	}
}

// checkIngestionOnce is one watchdog tick's decision, factored out so
// tests can drive it directly and deterministically instead of waiting
// on real timers.
func (wtr *Writer) checkIngestionOnce(ctx context.Context) {
	ing := wtr.Ingestion()
	if ing.FrameAgeSeconds < wtr.staleThreshold().Seconds() {
		wtr.stalled.Store(false)
		return
	}

	if wtr.TrafficProbe == nil {
		// No independent signal available: cannot tell a quiet network
		// from a real stall. Conservative (report degraded so this is
		// never silently "ok"), but never force-close blind -- that
		// would risk thrashing a healthy, merely-idle connection.
		wtr.stalled.Store(true)
		return
	}

	pctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	count, ok := wtr.TrafficProbe(pctx)
	cancel()
	wtr.lastProbeOK.Store(ok)
	if !ok {
		wtr.stalled.Store(true) // can't verify right now; conservative
		return
	}

	lastCount := wtr.lastProbeCount.Load()
	haveBaseline := wtr.haveProbeBaseline.Swap(true)
	trafficFlowing := haveBaseline && count > lastCount+minTrafficDeltaToFlagStall
	wtr.lastProbeCount.Store(count)

	if !trafficFlowing {
		// Genuinely quiet network -- no frames is correct, not a
		// failure.
		wtr.stalled.Store(false)
		return
	}

	wtr.recover(ctx, time.Duration(ing.FrameAgeSeconds*float64(time.Second)))
}

// recover is the forced-reconnect action, rate-limited by
// recoveryCooldown so a slow-settling dnsdist restart can't be thrashed
// by repeated forced closes while it's already in the middle of
// reconnecting.
func (wtr *Writer) recover(ctx context.Context, frameAge time.Duration) {
	now := time.Now()
	if last := wtr.lastRecoveryAt.Load(); last != 0 && now.Sub(time.Unix(last, 0)) < recoveryCooldown {
		wtr.stalled.Store(true)
		return
	}
	wtr.stalled.Store(true)
	wtr.lastRecoveryAt.Store(now.Unix())
	n := wtr.recoveryCount.Add(1)
	closed := wtr.closeAllConns()

	detail := fmt.Sprintf("no dnstap frames for %.0fs while BIND traffic counter kept advancing beyond the noise threshold -- forced close of %d dnstap connection(s) to trigger dnsdist's real reconnect-on-write-error behavior", frameAge.Seconds(), closed)
	if wtr.Log != nil {
		wtr.Log.Warn("dnsanalytics: ingestion stall detected, forcing dnstap reconnect", "frame_age_seconds", frameAge.Seconds(), "recovery_count", n, "closed_connections", closed)
	}
	wtr.recordIngestionEvent(ctx, "recovery_attempted", detail)
}

// recordIngestionEvent durably persists one stall/recovery diagnostic
// row (see store.go's ingestion_events table) so this history survives
// a process restart -- a real diagnostic trail, not just whatever
// happens to still be in a live log tail. Uses its own short-lived
// context so a slow/locked DB can never block the watchdog.
func (wtr *Writer) recordIngestionEvent(parent context.Context, kind, detail string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := wtr.DB.ExecContext(ctx, `INSERT INTO ingestion_events (ts, kind, detail) VALUES (?, ?, ?)`,
		time.Now().Unix(), kind, detail); err != nil && wtr.Log != nil {
		wtr.Log.Warn("dnsanalytics: failed to record ingestion event", "err", err)
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
