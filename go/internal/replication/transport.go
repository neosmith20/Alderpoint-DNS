// Real mutual-TLS transport: the primary's own listener (accepts
// /replication/enroll with no client cert required -- CERT_OPTIONAL,
// matching Python's own build_server_ssl_context exactly, since
// enrollment is called before a replica has any client certificate at
// all -- and /replication/generations/latest + /replication/ack, both
// requiring a client cert that must chain to this node's own CA and
// belong to a real, active replica) and the replica's own HTTPS client
// (verifies the server chains to the CA it was enrolled against;
// hostname checking is deliberately disabled, matching Python's own
// documented simplification -- the primary's reachable address is
// admin-configured, often a bare IP, and may not match a cert SAN; CA-
// chain verification, the actual trust boundary here, stays mandatory).
package replication

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

func certPath(dir string) string       { return filepath.Join(dir, "server.crt") }
func keyPath(dir string) string        { return filepath.Join(dir, "server.key") }
func clientCertPath(dir string) string { return filepath.Join(dir, "client.crt") }
func clientKeyPath(dir string) string  { return filepath.Join(dir, "client.key") }
func caCertPath(dir string) string     { return filepath.Join(dir, "ca.crt") }

// ensureServerCertFiles issues (if not already present) this node's own
// mTLS server certificate -- a real file pair readable by this
// unprivileged process (it terminates its own TLS, no privilege
// needed), signed by this node's own CA (apdns-hostagent-issued, never
// hand-rolled).
func (s *Service) ensureServerCertFiles(ctx context.Context) error {
	if s.CertDir == "" {
		return fmt.Errorf("no certificate directory configured for this deployment")
	}
	if _, err := os.Stat(certPath(s.CertDir)); err == nil {
		if _, err := os.Stat(keyPath(s.CertDir)); err == nil {
			return nil
		}
	}
	if _, err := s.EnsureCA(ctx); err != nil {
		return err
	}
	sans := []string{"127.0.0.1", "::1"}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if ipNet, ok := a.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
				sans = append(sans, ipNet.IP.String())
			}
		}
	}
	issued, err := s.issueCert(ctx, "alderpointdns-replication-primary", sans, "server", 10*365)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(s.CertDir, 0o750); err != nil {
		return err
	}
	if err := os.WriteFile(certPath(s.CertDir), []byte(issued.CertPEM), 0o644); err != nil {
		return err
	}
	return os.WriteFile(keyPath(s.CertDir), []byte(issued.KeyPEM), 0o600)
}

// StoreEnrollmentMaterial persists what a primary's EnrollmentResult
// handed back so this replica's own poller can use it -- matching
// Python's store_enrollment_material() exactly.
func (s *Service) StoreEnrollmentMaterial(ctx context.Context, primaryAddress string, result EnrollmentResult) error {
	if s.CertDir == "" {
		return fmt.Errorf("no certificate directory configured for this deployment")
	}
	if err := os.MkdirAll(s.CertDir, 0o750); err != nil {
		return err
	}
	if err := os.WriteFile(caCertPath(s.CertDir), []byte(result.CACertPEM), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(clientCertPath(s.CertDir), []byte(result.ClientCertPEM), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(clientKeyPath(s.CertDir), []byte(result.ClientKeyPEM), 0o600); err != nil {
		return err
	}
	for k, v := range map[string]string{
		"role": "replica", "primary_address": primaryAddress,
		"last_applied_generation": "0", "last_applied_hash": "",
	} {
		if err := s.setSetting(ctx, k, v); err != nil {
			return err
		}
	}
	return nil
}

// --- primary-side listener ------------------------------------------------

type primaryListener struct {
	srv    *http.Server
	cancel context.CancelFunc
}

func peerFingerprint(r *http.Request) string {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return ""
	}
	sum := sha256.Sum256(r.TLS.PeerCertificates[0].Raw)
	return hex.EncodeToString(sum[:])
}

func writeJSONReply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// StartPrimaryListener starts (or, if already running, is a no-op for)
// this node's own real mTLS HTTPS listener. Requires a server cert/key
// (ensureServerCertFiles) and CA cert to already exist.
func (s *Service) StartPrimaryListener(ctx context.Context) error {
	if s.server != nil {
		return nil
	}
	settings, err := s.GetSettings(ctx)
	if err != nil {
		return err
	}
	if settings.Role != "primary" {
		return fmt.Errorf("this node's role is %q, not primary", settings.Role)
	}
	if err := s.ensureServerCertFiles(ctx); err != nil {
		return err
	}
	// Re-read settings: ensureServerCertFiles may have just generated
	// and persisted the CA for the first time (a real bug caught live
	// by this session's own Chromium proof -- the `settings` fetched
	// above is stale the very first time this ever runs, since it was
	// read before the CA existed, and CACertPEM would be empty).
	settings, err = s.GetSettings(ctx)
	if err != nil {
		return err
	}
	cert, err := tls.LoadX509KeyPair(certPath(s.CertDir), keyPath(s.CertDir))
	if err != nil {
		return fmt.Errorf("loading server certificate: %w", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM([]byte(settings.CACertPEM)) {
		return fmt.Errorf("failed to load this node's own CA certificate")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /replication/enroll", s.handleEnrollRequest)
	mux.HandleFunc("GET /replication/generations/latest", s.handleLatestGenerationRequest)
	mux.HandleFunc("POST /replication/ack", s.handleAckRequest)

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    caPool,
		ClientAuth:   tls.VerifyClientCertIfGiven, // enroll has no cert yet; other endpoints check for one themselves
	}
	listenAddr := fmt.Sprintf("%s:%d", settings.ListenHost, settings.ListenPort)
	ln, err := tls.Listen("tcp", listenAddr, tlsCfg)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", listenAddr, err)
	}
	srv := &http.Server{Handler: mux}
	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			if s.Log != nil {
				s.Log.Error("replication primary listener exited", "err", err)
			}
		}
	}()
	_, cancel := context.WithCancel(context.Background())
	s.server = &primaryListener{srv: srv, cancel: cancel}
	return nil
}

func (s *Service) StopPrimaryListener() {
	if s.server == nil {
		return
	}
	s.server.srv.Close()
	s.server.cancel()
	s.server = nil
}

func (s *Service) handleEnrollRequest(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Token == "" {
		writeJSONReply(w, http.StatusBadRequest, map[string]string{"error": "token is required"})
		return
	}
	result, err := s.ConsumeEnrollment(r.Context(), body.Token)
	if err != nil {
		writeJSONReply(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSONReply(w, http.StatusOK, result)
}

func (s *Service) authenticatedReplica(r *http.Request) (*Replica, error) {
	fp := peerFingerprint(r)
	if fp == "" {
		return nil, fmt.Errorf("client certificate required")
	}
	replica, err := s.replicaByFingerprint(r.Context(), fp)
	if err != nil {
		return nil, err
	}
	if replica == nil {
		return nil, fmt.Errorf("unrecognized client certificate")
	}
	if replica.Status != "active" {
		return nil, fmt.Errorf("replica is %s", replica.Status)
	}
	return replica, nil
}

func (s *Service) handleLatestGenerationRequest(w http.ResponseWriter, r *http.Request) {
	replica, err := s.authenticatedReplica(r)
	if err != nil {
		writeJSONReply(w, http.StatusForbidden, map[string]string{"error": err.Error()})
		return
	}
	gen, err := s.LatestGeneration(r.Context(), true)
	if err != nil {
		writeJSONReply(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	s.DB.ExecContext(r.Context(), `UPDATE replication_replicas SET last_seen_at=? WHERE id=?`, now(), replica.ID)
	writeJSONReply(w, http.StatusOK, map[string]any{"generation": gen})
}

func (s *Service) handleAckRequest(w http.ResponseWriter, r *http.Request) {
	replica, err := s.authenticatedReplica(r)
	if err != nil {
		writeJSONReply(w, http.StatusForbidden, map[string]string{"error": err.Error()})
		return
	}
	var body struct {
		GenerationNumber int64  `json:"generation_number"`
		ContentHash      string `json:"content_hash"`
		Result           string `json:"result"`
		Message          string `json:"message"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	msg := body.Result + ": " + body.Message
	if len(msg) > 500 {
		msg = msg[:500]
	}
	if body.Result == "success" {
		s.DB.ExecContext(r.Context(), `UPDATE replication_replicas SET last_seen_at=?, last_result=?, last_generation_acked=?, last_ack_hash=? WHERE id=?`,
			now(), msg, body.GenerationNumber, body.ContentHash, replica.ID)
	} else {
		s.DB.ExecContext(r.Context(), `UPDATE replication_replicas SET last_seen_at=?, last_result=? WHERE id=?`, now(), msg, replica.ID)
	}
	writeJSONReply(w, http.StatusOK, map[string]bool{"ok": true})
}

// --- replica-side HTTP client ----------------------------------------------

type replicaTransportConfig struct {
	primaryHost, primaryPort      string
	caCert, clientCert, clientKey string
}

func (s *Service) buildReplicaTransportConfig(ctx context.Context) (*replicaTransportConfig, error) {
	settings, err := s.GetSettings(ctx)
	if err != nil {
		return nil, err
	}
	if settings.Role != "replica" {
		return nil, fmt.Errorf("this node is not an enrolled replica")
	}
	if settings.PrimaryAddress == "" {
		return nil, fmt.Errorf("no primary address configured")
	}
	for _, p := range []string{caCertPath(s.CertDir), clientCertPath(s.CertDir), clientKeyPath(s.CertDir)} {
		if _, err := os.Stat(p); err != nil {
			return nil, fmt.Errorf("enrollment material missing (%s): %w", p, err)
		}
	}
	host, port, err := net.SplitHostPort(settings.PrimaryAddress)
	if err != nil {
		host, port = settings.PrimaryAddress, fmt.Sprintf("%d", DefaultListenPort)
	}
	return &replicaTransportConfig{
		primaryHost: host, primaryPort: port,
		caCert: caCertPath(s.CertDir), clientCert: clientCertPath(s.CertDir), clientKey: clientKeyPath(s.CertDir),
	}, nil
}

func (rc *replicaTransportConfig) httpClient() (*http.Client, error) {
	cert, err := tls.LoadX509KeyPair(rc.clientCert, rc.clientKey)
	if err != nil {
		return nil, fmt.Errorf("loading client certificate: %w", err)
	}
	caPEM, err := os.ReadFile(rc.caCert)
	if err != nil {
		return nil, fmt.Errorf("reading CA certificate: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("invalid CA certificate")
	}
	tlsCfg := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		RootCAs:            pool,
		InsecureSkipVerify: true, // real chain-to-CA verification happens in VerifyPeerCertificate below; hostname checking is deliberately skipped, matching Python's own documented choice
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return verifyChainToPool(rawCerts, pool)
		},
	}
	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}, nil
}

// verifyChainToPool is the real trust check InsecureSkipVerify above
// otherwise disables: every presented certificate must still chain to
// the configured CA pool. Only hostname matching is skipped.
func verifyChainToPool(rawCerts [][]byte, pool *x509.CertPool) error {
	if len(rawCerts) == 0 {
		return fmt.Errorf("no server certificate presented")
	}
	certs := make([]*x509.Certificate, 0, len(rawCerts))
	for _, raw := range rawCerts {
		cert, err := x509.ParseCertificate(raw)
		if err != nil {
			return err
		}
		certs = append(certs, cert)
	}
	intermediates := x509.NewCertPool()
	for _, c := range certs[1:] {
		intermediates.AddCert(c)
	}
	_, err := certs[0].Verify(x509.VerifyOptions{Roots: pool, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	return err
}

func httpsJSONRequest(ctx context.Context, client *http.Client, method, url string, body any) (int, map[string]any, error) {
	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		reqBody = io.NopCloser(bytes.NewReader(b))
	}
	req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out, nil
}

// EnrollWithPrimary is the replica side of the manual-token enrollment
// path -- trust-on-first-use for this one bootstrap call (no CA to
// verify against yet), exactly like Python's own enroll_with_primary().
func (s *Service) EnrollWithPrimary(ctx context.Context, primaryHost string, primaryPort int, token string) (EnrollmentResult, error) {
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, // TOFU bootstrap only, see doc comment
	}
	url := fmt.Sprintf("https://%s:%d/replication/enroll", primaryHost, primaryPort)
	status, data, err := httpsJSONRequest(ctx, client, http.MethodPost, url, map[string]string{"token": token})
	if err != nil {
		return EnrollmentResult{}, fmt.Errorf("connecting to primary: %w", err)
	}
	if status != http.StatusOK {
		errMsg, _ := data["error"].(string)
		if errMsg == "" {
			errMsg = fmt.Sprintf("enrollment failed with HTTP %d", status)
		}
		return EnrollmentResult{}, fmt.Errorf("%s", errMsg)
	}
	result := EnrollmentResult{
		NodeID: str(data["node_id"]), NodeName: str(data["node_name"]),
		CACertPEM: str(data["ca_cert_pem"]), ClientCertPEM: str(data["client_cert_pem"]), ClientKeyPEM: str(data["client_key_pem"]),
	}
	return result, nil
}

func str(v any) string {
	s, _ := v.(string)
	return s
}
