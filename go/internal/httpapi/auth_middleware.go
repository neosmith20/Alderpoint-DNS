package httpapi

import (
	"database/sql"
	"net/http"
	"time"

	"alderpointdns/go-controlplane/internal/auth"
)

// RequireAuth validates the session cookie and, for any non-GET/HEAD
// request, the X-CSRF-Token header -- the exact same two-part contract as
// app/v2/webapp.py's current_admin + per-route check_csrf calls, just
// enforced in one place instead of once per handler.
func RequireAuth(store *auth.Store, ttl, lastSeenInterval time.Duration, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(auth.SessionCookieName)
		if err != nil {
			Err(http.StatusUnauthorized, "not_authenticated", "no session").WriteJSON(w)
			return
		}
		sess, err := store.ValidateSession(r.Context(), c.Value, ttl, lastSeenInterval)
		if err == sql.ErrNoRows {
			Err(http.StatusUnauthorized, "not_authenticated", "session expired or invalid").WriteJSON(w)
			return
		} else if err != nil {
			Err(http.StatusInternalServerError, "internal_error", "session lookup failed").WriteJSON(w)
			return
		}

		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if !auth.CheckCSRF(sess, r.Header.Get("X-CSRF-Token")) {
				Err(http.StatusForbidden, "invalid_csrf_token", "missing or incorrect X-CSRF-Token header").WriteJSON(w)
				return
			}
		}

		ctx := auth.WithSession(r.Context(), sess)
		next(w, r.WithContext(ctx))
	}
}
