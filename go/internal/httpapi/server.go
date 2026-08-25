package httpapi

import (
	"database/sql"
	"log/slog"
	"net/http"
	"time"

	"alderpointdns/go-controlplane/internal/auth"
	"alderpointdns/go-controlplane/internal/blocklists"
	"alderpointdns/go-controlplane/internal/localdns"
)

type Server struct {
	DB         *sql.DB
	Auth       *auth.Store
	Blocklists *blocklists.Service
	LocalDNS   *localdns.Service
	StaticDir  string
	Log        *slog.Logger

	Version    string
	StartedAt  time.Time
	SessionTTL time.Duration
	LastSeen   time.Duration
}

func (s *Server) Uptime() time.Duration { return time.Since(s.StartedAt) }

// Routes builds the full route table. requireAuth wraps every
// authenticated handler with session+CSRF enforcement in one place.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	requireAuth := func(h http.HandlerFunc) http.HandlerFunc {
		return RequireAuth(s.Auth, s.SessionTTL, s.LastSeen, h)
	}

	mux.HandleFunc("GET /api/health", s.handleHealth)
	mux.HandleFunc("GET /api/setup/status", s.handleSetupStatus)
	mux.HandleFunc("POST /api/setup", s.handleSetup)
	mux.HandleFunc("POST /api/login", s.handleLogin)
	mux.HandleFunc("POST /api/logout", requireAuth(s.handleLogout))
	mux.HandleFunc("GET /api/session", requireAuth(s.handleSession))
	mux.HandleFunc("POST /api/session/revoke-others", requireAuth(s.handleRevokeOtherSessions))

	mux.HandleFunc("GET /api/blocklists", requireAuth(s.handleListBlocklists))
	mux.HandleFunc("POST /api/blocklists", requireAuth(s.handleCreateBlocklist))
	mux.HandleFunc("POST /api/blocklists/settings", requireAuth(s.handleBlocklistSettings))
	mux.HandleFunc("POST /api/blocklists/refresh-all", requireAuth(s.handleRefreshAllBlocklists))
	mux.HandleFunc("GET /api/blocklists/jobs/{id}", requireAuth(s.handleBlocklistJob))
	mux.HandleFunc("POST /api/blocklists/{id}/interval", requireAuth(s.handleSetBlocklistInterval))
	mux.HandleFunc("POST /api/blocklists/{id}/toggle", requireAuth(s.handleToggleBlocklist))
	mux.HandleFunc("POST /api/blocklists/{id}/refresh", requireAuth(s.handleRefreshOneBlocklist))
	mux.HandleFunc("DELETE /api/blocklists/{id}", requireAuth(s.handleDeleteBlocklist))

	mux.HandleFunc("GET /api/local-dns", requireAuth(s.handleListLocalDNS))
	mux.HandleFunc("POST /api/local-dns", requireAuth(s.handleCreateLocalDNS))
	mux.HandleFunc("PATCH /api/local-dns/{id}", requireAuth(s.handleUpdateLocalDNS))
	mux.HandleFunc("DELETE /api/local-dns/{id}", requireAuth(s.handleDeleteLocalDNS))

	mux.HandleFunc("/", s.handleStatic)

	return Instrument(s.Log, mux)
}
