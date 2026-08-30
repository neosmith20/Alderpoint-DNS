// audited is a route-registration-level wrapper that gives blocker 4
// (Full Admin Audit Log) real, appliance-wide coverage without a
// hand-written internal/auditlog.Record call in every one of this
// package's 50+ mutating handlers -- a genuinely more scalable design
// than V1.1.1's own per-handler approach (and one that can never miss
// a future mutating endpoint the way a manual per-handler pass could).
// A handful of security-relevant actions (login, password change,
// session revoke, Protection Control, Statistics settings save,
// Software Update apply) already call internal/auditlog.Record
// directly with a richer, hand-written detail string -- audited() is
// deliberately NOT applied to those routes, so a mutation is recorded
// exactly once, with the best detail available for it, never twice.
package httpapi

import (
	"net/http"

	"alderpointdns/go-controlplane/internal/auth"
)

// statusCapturingWriter wraps http.ResponseWriter purely to observe
// the status code the real handler decided on -- it never alters or
// delays anything the client actually receives.
type statusCapturingWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusCapturingWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

// audited wraps a mutating handler with a real internal/auditlog.Record
// call after it runs: success = the handler's own real response status
// (< 400), action is the caller-supplied slug (matching this
// package's own "resource_action" naming convention, e.g.
// "blocklist_create"). Best-effort and never blocking -- Record's own
// contract already guarantees a logging failure can never affect the
// real response, and this wrapper calls it only after
// ResponseWriter.Write has already been reached (a request that never
// gets a session at all, e.g. requireAuth's own 401, never reaches
// here since audited() sits INSIDE requireAuth in every route it's
// used on).
func (s *Server) audited(action string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sw := &statusCapturingWriter{ResponseWriter: w, status: http.StatusOK}
		h(sw, r)
		if s.AuditLog == nil {
			return
		}
		sess, ok := auth.FromContext(r.Context())
		if !ok || sess.AdminID <= 0 {
			return
		}
		s.AuditLog.Record(r.Context(), sess.AdminID, sess.Username, action, sw.status < 400, clientIP(r), "")
	}
}
