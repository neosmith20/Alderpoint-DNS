package httpapi

import "net/http"

// dnsPerfUnavailable mirrors hostagentUnavailable's honest-degraded
// contract: DNS Performance depends on the same host-control agent as
// Cache, plus a fully-configured DNS runtime (this is a real
// benchmark of the appliance's own live listeners, not a synthetic
// number).
const dnsPerfUnavailable = "DNS Performance requires a configured DNS runtime and a reachable host-control agent"

func (s *Server) handleDNSPerfStatus(w http.ResponseWriter, r *http.Request) {
	if s.DNSPerf == nil {
		WriteJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "unavailable", "detail": dnsPerfUnavailable})
		return
	}
	running, lastError := s.DNSPerf.Status()
	report, err := s.DNSPerf.Read()
	resp := map[string]any{"benchmark_running": running, "last_error": lastError, "report": report}
	if err != nil {
		// Honest in-band disclosure of a real read failure -- never a
		// silently empty/absent report standing in for "no report yet".
		resp["report_error"] = err.Error()
	}
	WriteJSON(w, http.StatusOK, resp)
}

func (s *Server) handleDNSPerfBenchmark(w http.ResponseWriter, r *http.Request) {
	if s.DNSPerf == nil {
		WriteJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "unavailable", "detail": dnsPerfUnavailable})
		return
	}
	if ok := s.DNSPerf.Start(r.Context()); !ok {
		WriteJSON(w, http.StatusOK, map[string]any{"status": "already_running"})
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"status": "started"})
}

func (s *Server) handleDNSPerfClear(w http.ResponseWriter, r *http.Request) {
	if s.DNSPerf == nil {
		WriteJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "unavailable", "detail": dnsPerfUnavailable})
		return
	}
	if err := s.DNSPerf.Clear(); err != nil {
		Err(http.StatusInternalServerError, "internal_error", err.Error()).WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"status": "cleared"})
}
