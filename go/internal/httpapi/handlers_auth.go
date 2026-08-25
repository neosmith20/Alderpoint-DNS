package httpapi

import (
	"encoding/json"
	"net"
	"net/http"

	"alderpointdns/go-controlplane/internal/auth"
	"alderpointdns/go-controlplane/internal/localdns"
)

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
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok || ipNet.IP.IsLoopback() {
			continue
		}
		if v4 := ipNet.IP.To4(); v4 != nil {
			return v4.String()
		}
	}
	return ""
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
	WriteJSON(w, http.StatusOK, map[string]any{"status": "ok", "revoked_count": n})
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

	WriteJSON(w, http.StatusOK, map[string]any{
		"status":         status,
		"components":     components,
		"version":        s.Version,
		"uptime_seconds": int(s.Uptime().Seconds()),
	})
}
