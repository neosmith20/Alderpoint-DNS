package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"
	"strings"
	"sync"
	"time"
)

type ctxKey int

const (
	requestIDKey ctxKey = iota
	timingKey
)

func newRequestID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func RequestIDFromContext(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey).(string)
	return id
}

// stageTimer accumulates named stage durations for the Server-Timing
// response header -- the Go equivalent of app/v2/webapp.py's
// _timed_stage/_add_timing, so a slow request's breakdown (DB query vs.
// hashing vs. serialization) is visible without a profiler attached.
type stageTimer struct {
	mu     sync.Mutex
	stages []stageEntry
}
type stageEntry struct {
	name string
	ms   float64
}

func (t *stageTimer) add(name string, d time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.stages = append(t.stages, stageEntry{name, float64(d.Microseconds()) / 1000.0})
}

func (t *stageTimer) header() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	parts := make([]string, 0, len(t.stages))
	for _, s := range t.stages {
		parts = append(parts, fmt.Sprintf("%s;dur=%.2f", s.name, s.ms))
	}
	return strings.Join(parts, ", ")
}

// TimedStage records how long fn takes under name, for the current
// request's Server-Timing header. Safe to call with no timer in context
// (e.g. from a background job) -- it's just a no-op then.
func TimedStage[T any](ctx context.Context, name string, fn func() (T, error)) (T, error) {
	start := time.Now()
	result, err := fn()
	if t, ok := ctx.Value(timingKey).(*stageTimer); ok {
		t.add(name, time.Since(start))
	}
	return result, err
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

// Instrument wraps every request with: a request ID (returned as
// X-Request-ID and included in every log line), a Server-Timing
// accumulator, structured JSON access logging, and panic recovery (a
// handler panic becomes a logged 500 JSON error, never a crashed process
// or a bare stack trace sent to the client).
func Instrument(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID := newRequestID()
		timer := &stageTimer{}
		ctx := context.WithValue(r.Context(), requestIDKey, reqID)
		ctx = context.WithValue(ctx, timingKey, timer)
		r = r.WithContext(ctx)
		w.Header().Set("X-Request-ID", reqID)

		sw := &statusWriter{ResponseWriter: w, status: 200}
		start := time.Now()

		defer func() {
			// Set before any WriteHeader call below so it's never dropped
			// as a "header set after response started" no-op.
			if th := timer.header(); th != "" {
				w.Header().Set("Server-Timing", th)
			}
			if rec := recover(); rec != nil {
				logger.Error("panic recovered", "request_id", reqID, "method", r.Method, "path", r.URL.Path,
					"panic", fmt.Sprint(rec), "stack", string(debug.Stack()))
				Err(http.StatusInternalServerError, "internal_error", "an unexpected error occurred").WriteJSON(sw)
			}
			logger.Info("req", "request_id", reqID, "method", r.Method, "path", r.URL.Path,
				"status", sw.status, "dur_us", time.Since(start).Microseconds())
		}()

		next.ServeHTTP(sw, r)
	})
}
