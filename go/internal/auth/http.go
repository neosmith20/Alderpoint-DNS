package auth

import (
	"context"
	"crypto/subtle"
	"net/http"
	"time"
)

// SetSessionCookie mirrors app/v2/webapp.py's _set_session_cookie:
// HttpOnly, SameSite=Strict, Secure when the request came in over TLS.
func SetSessionCookie(w http.ResponseWriter, r *http.Request, sessionID string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(ttl.Seconds()),
	})
}

func ClearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}

// CheckCSRF constant-time-compares the X-CSRF-Token header against the
// session's stored token -- required on every mutating (non-GET) request,
// same contract as app/v2/webapp.py's check_csrf.
func CheckCSRF(sess *Session, headerValue string) bool {
	if headerValue == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(headerValue), []byte(sess.CSRF)) == 1
}

type ctxKey int

const sessionCtxKey ctxKey = 0

func WithSession(ctx context.Context, s *Session) context.Context {
	return context.WithValue(ctx, sessionCtxKey, s)
}

func FromContext(ctx context.Context) (*Session, bool) {
	s, ok := ctx.Value(sessionCtxKey).(*Session)
	return s, ok
}
