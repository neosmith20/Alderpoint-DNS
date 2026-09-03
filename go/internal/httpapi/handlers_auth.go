package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strconv"

	"alderpointdns/go-controlplane/internal/auth"
	"alderpointdns/go-controlplane/internal/bootstrap"
	"alderpointdns/go-controlplane/internal/localdns"
)

// setupSessionCookieName is deliberately distinct from
// auth.SessionCookieName -- this cookie only ever proves "this browser
// presented the real one-time bootstrap token", nothing more, and is
// never valid for any authenticated route.
const setupSessionCookieName = "alderpointdns_v2_setup_session"

func setSetupSessionCookie(w http.ResponseWriter, r *http.Request, sessionID string) {
	http.SetCookie(w, &http.Cookie{
		Name: setupSessionCookieName, Value: sessionID, Path: "/",
		HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode,
		MaxAge: 15 * 60,
	})
}

func clearSetupSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name: setupSessionCookieName, Value: "", Path: "/",
		HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode,
		MaxAge: -1,
	})
}

// handleSetupBootstrap exchanges a real one-time bootstrap token (see
// internal/bootstrap's doc comment -- delivered only via this
// process's own log/console, never over the network) for a short-
// lived setup session. This is the ONLY new thing an unauthenticated
// LAN client can do before presenting a valid token: everything else
// about first-run setup now requires it.
func (s *Server) handleSetupBootstrap(w http.ResponseWriter, r *http.Request) {
	if s.Bootstrap == nil {
		Err(http.StatusInternalServerError, "internal_error", "bootstrap gate not configured").WriteJSON(w)
		return
	}
	var body struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid request body").WriteJSON(w)
		return
	}
	sessionID, csrf, err := s.Bootstrap.VerifyToken(body.Token, clientIP(r))
	if err != nil {
		switch {
		case errors.Is(err, bootstrap.ErrLockedOut):
			Err(http.StatusTooManyRequests, "locked_out", "too many failed attempts; try again later").WriteJSON(w)
		case errors.Is(err, bootstrap.ErrNoActiveToken):
			Err(http.StatusConflict, "already_configured", "setup is not open (an owner account may already exist)").WriteJSON(w)
		default:
			// Deliberately the same generic message/status for "wrong
			// token" as any other failure -- never lets a caller
			// distinguish "close" from "not close" or fingerprint
			// remaining attempts.
			Err(http.StatusUnauthorized, "invalid_token", "invalid or expired bootstrap token").WriteJSON(w)
		}
		return
	}
	setSetupSessionCookie(w, r, sessionID)
	WriteJSON(w, http.StatusOK, map[string]any{"status": "ok", "csrf": csrf})
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) handleSetupStatus(w http.ResponseWriter, r *http.Request) {
	required, err := s.Auth.SetupRequired(r.Context())
	if err != nil {
		Err(http.StatusInternalServerError, "internal_error", "setup status check failed").WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"setup_required": required})
}

type setupRequest struct {
	Username        string `json:"username"`
	Password        string `json:"password"`
	ConfirmPassword string `json:"confirm_password"`
	CreateLocalDNS  bool   `json:"create_local_dns"`
	ServerHostname  string `json:"server_hostname"`
	ServerIP        string `json:"server_ip"`
}

func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	if s.Bootstrap == nil {
		Err(http.StatusInternalServerError, "internal_error", "bootstrap gate not configured").WriteJSON(w)
		return
	}
	// Real gate, checked before touching the database at all: the
	// caller must hold a session this process itself issued in
	// response to a real, correct bootstrap token (see
	// handleSetupBootstrap). The DB's own "zero admins" check below
	// stays too, as defense in depth -- but this is what actually stops
	// an unauthenticated LAN client from racing to claim the appliance,
	// not just "whoever's request the database transaction happened to
	// commit first".
	setupCookie, _ := r.Cookie(setupSessionCookieName)
	setupSessionID := ""
	if setupCookie != nil {
		setupSessionID = setupCookie.Value
	}
	if err := s.Bootstrap.CheckSession(setupSessionID, r.Header.Get("X-CSRF-Token")); err != nil {
		Err(http.StatusUnauthorized, "setup_session_required", "present a valid bootstrap token at /api/setup/bootstrap first").WriteJSON(w)
		return
	}

	var req setupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid request body").WriteJSON(w)
		return
	}
	if len(req.Username) < 1 || len(req.Username) > 64 {
		ErrField(http.StatusBadRequest, "validation_error", "username required (max 64 chars)", "username").WriteJSON(w)
		return
	}
	if len(req.Password) < 12 || len(req.Password) > 256 {
		ErrField(http.StatusBadRequest, "validation_error", "password must be 12-256 characters", "password").WriteJSON(w)
		return
	}
	if req.Password != req.ConfirmPassword {
		Err(http.StatusBadRequest, "validation_error", "password and confirm password do not match").WriteJSON(w)
		return
	}

	if _, err := s.Auth.CreateFirstAdmin(r.Context(), req.Username, req.Password); err != nil {
		if err == auth.ErrAlreadyConfigured {
			Err(http.StatusConflict, "already_configured", "initial setup has already been completed").WriteJSON(w)
			return
		}
		Err(http.StatusInternalServerError, "internal_error", "setup failed").WriteJSON(w)
		return
	}
	// The real admin account now exists -- permanently disable the
	// bootstrap mechanism (deletes the token file, clears every
	// in-memory setup session, including any second browser tab that
	// raced in with the same token) and this browser's own setup
	// cookie. Nothing about first-run setup can ever be reached again
	// in this process's lifetime.
	s.Bootstrap.Consume()
	clearSetupSessionCookie(w, r)

	var localDNSResult any
	if req.CreateLocalDNS {
		host := req.ServerHostname
		if host == "" {
			host = "alderpointdns"
		}
		ip := req.ServerIP
		if ip == "" {
			ip = detectLikelyServerIP()
		}
		if ip == "" {
			localDNSResult = map[string]any{"error": "no server address could be detected; add a Local DNS record manually"}
		} else if _, err := s.LocalDNS.Create(r.Context(), localdns.CreateInput{
			Name: host, RecordType: "A", Value: ip, TTL: 300, Enabled: true,
		}); err != nil {
			localDNSResult = map[string]any{"error": err.Error()}
		} else {
			localDNSResult = map[string]any{"hostname": host, "address": ip}
		}
	}

	WriteJSON(w, http.StatusOK, map[string]any{"status": "created", "local_dns": localDNSResult})
}

// detectLikelyServerIP finds the first non-loopback IPv4 address on the
// host -- a deliberately simple heuristic for Milestone 1 (matching how
// the setup form still lets the operator override it). The real
// app/v2/network_config.py-driven detection is a later-milestone item;
// see the migration report's "known limitations".
func detectLikelyServerIP() string {
	if ips := detectServerIPs(); len(ips) > 0 {
		return ips[0]
	}
	return ""
}

// detectServerIPs lists every non-loopback IPv4 address on the host, in
// net.InterfaceAddrs' own order -- used both by first-run setup (via
// detectLikelyServerIP above) and by the Encryption page's DNS Transports
// client-setup guidance, which needs to offer a real LAN address to hand
// a remote client instead of ever suggesting "localhost".
func detectServerIPs() []string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []string
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok || ipNet.IP.IsLoopback() {
			continue
		}
		if v4 := ipNet.IP.To4(); v4 != nil {
			out = append(out, v4.String())
		}
	}
	return out
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid request body").WriteJSON(w)
		return
	}
	sess, err := s.Auth.Login(r.Context(), req.Username, req.Password, clientIP(r), r.UserAgent())
	if err != nil {
		switch err {
		case auth.ErrRateLimited:
			Err(http.StatusTooManyRequests, "rate_limited", "too many failed login attempts; try again later").WriteJSON(w)
		case auth.ErrInvalidCredentials:
			Err(http.StatusUnauthorized, "invalid_credentials", "invalid username or password").WriteJSON(w)
		default:
			Err(http.StatusInternalServerError, "internal_error", "login failed").WriteJSON(w)
		}
		return
	}
	auth.SetSessionCookie(w, r, sess.ID, s.SessionTTL)
	WriteJSON(w, http.StatusOK, map[string]any{"status": "ok", "csrf": sess.CSRF})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(auth.SessionCookieName)
	if err == nil {
		s.Auth.Logout(r.Context(), c.Value)
	}
	auth.ClearSessionCookie(w, r)
	WriteJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	sess, _ := auth.FromContext(r.Context())
	WriteJSON(w, http.StatusOK, map[string]any{"authenticated": true, "username": sess.Username, "csrf": sess.CSRF})
}

func (s *Server) handleRevokeOtherSessions(w http.ResponseWriter, r *http.Request) {
	sess, _ := auth.FromContext(r.Context())
	n, err := s.Auth.RevokeOtherSessions(r.Context(), sess.AdminID, sess.ID)
	if err != nil {
		Err(http.StatusInternalServerError, "internal_error", "revoke failed").WriteJSON(w)
		return
	}
	s.AuditLog.Record(r.Context(), sess.AdminID, sess.Username, "sessions_revoked", true, clientIP(r), sessionsRevokedDetail(n))
	WriteJSON(w, http.StatusOK, map[string]any{"status": "ok", "revoked_count": n})
}

func sessionsRevokedDetail(n int64) string {
	if n == 1 {
		return "1 other session revoked"
	}
	return strconv.FormatInt(n, 10) + " other session(s) revoked"
}

// handleListSessions backs the Administration page's Sessions table,
// matching V1.1.1's own real administration_context() query
// field-for-field (see internal/auth.Store.ListSessions's own doc
// comment).
func (s *Server) handleListSessions(w http.ResponseWriter, r *http.Request) {
	sess, _ := auth.FromContext(r.Context())
	rows, err := s.Auth.ListSessions(r.Context(), sess.AdminID, sess.ID)
	if err != nil {
		Err(http.StatusInternalServerError, "internal_error", "failed to load sessions").WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"sessions": rows})
}

// handleListAuditLog backs the Administration page's Recent
// Administrative Activity table -- see internal/auditlog's own doc
// comment for exactly which actions are recorded.
func (s *Server) handleListAuditLog(w http.ResponseWriter, r *http.Request) {
	sess, _ := auth.FromContext(r.Context())
	if s.AuditLog == nil {
		WriteJSON(w, http.StatusOK, map[string]any{"entries": []any{}})
		return
	}
	entries, err := s.AuditLog.List(r.Context(), sess.AdminID, 25)
	if err != nil {
		Err(http.StatusInternalServerError, "internal_error", "failed to load audit log").WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"entries": entries})
}

// handleListAuditLogAll backs the Advanced > Operations > Audit Log page --
// every administrator's activity (unlike handleListAuditLog above, which
// stays scoped to the calling admin for Administration's own smaller
// summary card). See internal/auditlog.Service.ListAll's doc comment for
// the real, disclosed shape/scope ceiling.
func (s *Server) handleListAuditLogAll(w http.ResponseWriter, r *http.Request) {
	if s.AuditLog == nil {
		WriteJSON(w, http.StatusOK, map[string]any{"entries": []any{}})
		return
	}
	limit := 500
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			limit = n
		}
	}
	entries, err := s.AuditLog.ListAll(r.Context(), limit)
	if err != nil {
		Err(http.StatusInternalServerError, "internal_error", "failed to load audit log").WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"entries": entries})
}

type changePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	sess, _ := auth.FromContext(r.Context())
	var req changePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid request body").WriteJSON(w)
		return
	}
	if len(req.NewPassword) < 12 || len(req.NewPassword) > 256 {
		ErrField(http.StatusBadRequest, "validation_error", "password must be 12-256 characters", "new_password").WriteJSON(w)
		return
	}
	err := s.Auth.ChangePassword(r.Context(), sess.AdminID, req.CurrentPassword, req.NewPassword)
	if err == auth.ErrInvalidCredentials {
		s.AuditLog.Record(r.Context(), sess.AdminID, sess.Username, "password_change", false, clientIP(r), "current password incorrect")
		ErrField(http.StatusUnauthorized, "invalid_credentials", "current password is incorrect", "current_password").WriteJSON(w)
		return
	} else if err != nil {
		Err(http.StatusInternalServerError, "internal_error", "password change failed").WriteJSON(w)
		return
	}
	// V1.1.1 parity: changing the password signs out every other active
	// session automatically (webapp.py's own real
	// administration_change_password, read directly -- and disclosed on
	// this exact page's own copy in both V1 and V2's AdministrationView).
	// Best-effort: a failure here must never undo an already-successful
	// password change.
	revoked, _ := s.Auth.RevokeOtherSessions(r.Context(), sess.AdminID, sess.ID)
	s.AuditLog.Record(r.Context(), sess.AdminID, sess.Username, "password_change", true, clientIP(r), sessionsRevokedDetail(revoked))
	WriteJSON(w, http.StatusOK, map[string]any{"status": "ok", "revoked_count": revoked})
}

// handleSystemStatus reports the appliance-level facts the Administration
// page (timezone display) and future pages need. Deliberately small: only
// what the Go control plane itself owns today (config, version, uptime).
// It does not proxy Python's much larger /api/system/status (workers,
// discovery, bind contexts, replication) -- see PARITY_MATRIX.md's
// System Status row for that real remaining scope.
func (s *Server) handleSystemStatus(w http.ResponseWriter, r *http.Request) {
	WriteJSON(w, http.StatusOK, map[string]any{
		"version":            s.Version,
		"uptime_seconds":     int(s.Uptime().Seconds()),
		"appliance_name":     s.applianceDisplayName(r.Context()),
		"appliance_timezone": s.ApplianceTimezone,
		// Real, already-enforced authentication security state
		// (Administration > Authentication Security) -- s.SessionTTL is
		// the exact value RequireAuth checks on every request;
		// auth.LoginFailureMax/Window are the exact constants Login
		// itself rate-limits against. Not owner-configurable yet, but
		// real, not invented.
		"session_timeout_seconds":         int(s.SessionTTL.Seconds()),
		"login_rate_limit_max_attempts":   auth.LoginFailureMax,
		"login_rate_limit_window_seconds": int(auth.LoginFailureWindow.Seconds()),
	})
}

// applianceDisplayName: the DB-stored override (General Settings >
// Appliance Identity) when one has been set, else the boot-time
// appliance.yaml value -- see internal/appliancesettings' own doc
// comment for why this indirection exists at all.
func (s *Server) applianceDisplayName(ctx context.Context) string {
	if s.ApplianceSettings != nil {
		if name, err := s.ApplianceSettings.Get(ctx); err == nil && name != "" {
			return name
		}
	}
	return s.ApplianceName
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	components := map[string]any{}
	status := "ok"

	var schemaVersion int
	err := s.DB.QueryRowContext(r.Context(), `SELECT max(version) FROM schema_migrations`).Scan(&schemaVersion)
	if err != nil {
		components["control_db"] = map[string]any{"status": "unavailable", "detail": err.Error()}
		status = "degraded"
	} else {
		components["control_db"] = map[string]any{"status": "ok", "schema_version": schemaVersion}
	}

	// Analytics writer/receiver liveness (see internal/pyanalytics/
	// health.go's own doc comment for exactly what this closes: a real
	// V1.1.1 failure class where DNS and this health check both stayed
	// "ok" while the analytics writer was actually dead). A degraded or
	// failed analytics component demotes overall status the same way a
	// stale background worker does in Python's own /api/health -- never
	// silently folded into "ok", but also never demoted below
	// "degraded": DNS itself is reported separately and is what actually
	// governs whether the appliance is serving.
	if s.Analytics != nil {
		h := s.Analytics.Health(r.Context())
		components["analytics"] = h
		if h.Status != "ok" && status == "ok" {
			status = "degraded"
		}
	} else {
		components["analytics"] = map[string]any{"status": "unconfigured", "reason": analyticsUnavailable}
	}

	// Process memory/goroutine visibility -- see
	// handlers_health_process.go's own doc comment for why this was
	// added and why it never demotes overall status.
	components["process"] = currentProcessStats()

	WriteJSON(w, http.StatusOK, map[string]any{
		"status":         status,
		"components":     components,
		"version":        s.Version,
		"uptime_seconds": int(s.Uptime().Seconds()),
	})
}
