// Package softwareupdates implements the real remote-check half of
// Software Updates: a GitHub Releases channel (owner-confirmed real
// coordinates: github.com/neosmith20/Alderpoint-DNS -- this Go control
// plane had no update feed at all before this package; inventing one
// was a real infrastructure decision, not a wiring gap, so it was
// asked rather than guessed). The local half (stage/apply/rollback,
// mandatory pre-upgrade backup) was already real -- see
// internal/hostagentd/ops_update.go and
// internal/httpapi/handlers_hostagent.go's handleUpdateApply -- this
// package only adds "what is the latest real published version, and
// fetch it", handing the downloaded bytes to that already-verified
// stage pipeline rather than reinventing checksum/version verification.
package softwareupdates

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

var (
	ErrNotFound   = errors.New("not found")
	ErrValidation = errors.New("validation failed")
)

type ChannelSettings struct {
	RepoOwner           string `json:"repo_owner"`
	RepoName            string `json:"repo_name"`
	Token               string `json:"token,omitempty"` // never returned by Get -- write-only, matching every other stored credential in this codebase
	LastCheckedAt       string `json:"last_checked_at"`
	LastCheckStatus     string `json:"last_check_status"`
	LastCheckError      string `json:"last_check_error"`
	LatestVersion       string `json:"latest_version"`
	LatestDebURL        string `json:"latest_deb_url"`
	LatestSHA256SumsURL string `json:"latest_sha256sums_url"`
	LatestDebAssetName  string `json:"latest_deb_asset_name"`
	HasToken            bool   `json:"has_token"`
}

type Service struct {
	DB         *sql.DB
	HTTPClient *http.Client

	// githubAPIBase overrides https://api.github.com for tests (a real
	// httptest.Server), never set in production.
	githubAPIBase string
}

func (s *Service) httpClient() *http.Client {
	if s.HTTPClient != nil {
		return s.HTTPClient
	}
	return &http.Client{Timeout: 15 * time.Second}
}

func (s *Service) Get(ctx context.Context) (ChannelSettings, error) {
	var cs ChannelSettings
	var token string
	err := s.DB.QueryRowContext(ctx, `SELECT repo_owner, repo_name, token, last_checked_at, last_check_status, last_check_error,
		latest_version, latest_deb_url, latest_sha256sums_url, latest_deb_asset_name FROM update_channel_settings WHERE id = 1`).
		Scan(&cs.RepoOwner, &cs.RepoName, &token, &cs.LastCheckedAt, &cs.LastCheckStatus, &cs.LastCheckError,
			&cs.LatestVersion, &cs.LatestDebURL, &cs.LatestSHA256SumsURL, &cs.LatestDebAssetName)
	if err != nil {
		return ChannelSettings{}, err
	}
	cs.HasToken = token != ""
	return cs, nil
}

// SetChannel updates the repo coordinates (and token, when explicitly
// given -- an empty token here means "leave whatever is already
// stored", matching every other write-only-credential PUT in this
// codebase, so re-saving the owner/repo fields alone can never
// accidentally wipe a previously-set token).
func (s *Service) SetChannel(ctx context.Context, owner, name, token string, clearToken bool) error {
	owner = strings.TrimSpace(owner)
	name = strings.TrimSpace(name)
	if owner == "" || name == "" {
		return fmt.Errorf("%w: repo_owner and repo_name are required", ErrValidation)
	}
	if clearToken {
		_, err := s.DB.ExecContext(ctx, `UPDATE update_channel_settings SET repo_owner=?, repo_name=?, token='' WHERE id=1`, owner, name)
		return err
	}
	if token != "" {
		_, err := s.DB.ExecContext(ctx, `UPDATE update_channel_settings SET repo_owner=?, repo_name=?, token=? WHERE id=1`, owner, name, token)
		return err
	}
	_, err := s.DB.ExecContext(ctx, `UPDATE update_channel_settings SET repo_owner=?, repo_name=? WHERE id=1`, owner, name)
	return err
}

type ghAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}
type ghRelease struct {
	TagName    string    `json:"tag_name"`
	Prerelease bool      `json:"prerelease"`
	Draft      bool      `json:"draft"`
	Assets     []ghAsset `json:"assets"`
}

// CheckNow hits the configured GitHub repo's real /releases/latest
// endpoint, finds the one real .deb asset (name matching
// "alderpointdns*_all.deb", excluding the floating "_latest_" alias so
// a genuine version-named asset is always preferred when both exist)
// and its SHA256SUMS sibling if present, and persists the result --
// always persists SOMETHING (a real error is stored and returned, never
// silently dropped) so Software Updates can show a truthful
// "last checked / status" even when the check itself failed.
func (s *Service) CheckNow(ctx context.Context) (ChannelSettings, error) {
	cs, err := s.Get(ctx)
	if err != nil {
		return ChannelSettings{}, err
	}
	if cs.RepoOwner == "" || cs.RepoName == "" {
		return s.recordCheckResult(ctx, cs, "", "", "", "", fmt.Errorf("no update channel configured (repo_owner/repo_name are empty)"))
	}

	var token string
	s.DB.QueryRowContext(ctx, `SELECT token FROM update_channel_settings WHERE id=1`).Scan(&token)

	base := s.githubAPIBase
	if base == "" {
		base = "https://api.github.com"
	}
	url := fmt.Sprintf("%s/repos/%s/%s/releases/latest", base, cs.RepoOwner, cs.RepoName)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return s.recordCheckResult(ctx, cs, "", "", "", "", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := s.httpClient().Do(req)
	if err != nil {
		return s.recordCheckResult(ctx, cs, "", "", "", "", fmt.Errorf("contacting GitHub: %w", err))
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return s.recordCheckResult(ctx, cs, "", "", "", "", fmt.Errorf("GitHub returned HTTP %d: %s", resp.StatusCode, truncate(string(body), 200)))
	}
	var rel ghRelease
	if err := json.Unmarshal(body, &rel); err != nil {
		return s.recordCheckResult(ctx, cs, "", "", "", "", fmt.Errorf("parsing GitHub response: %w", err))
	}
	if rel.Draft {
		return s.recordCheckResult(ctx, cs, "", "", "", "", fmt.Errorf("latest release %q is a draft, not a real published release", rel.TagName))
	}
	version := strings.TrimPrefix(rel.TagName, "v")

	var debURL, debName, sumsURL string
	for _, a := range rel.Assets {
		lower := strings.ToLower(a.Name)
		if strings.HasSuffix(lower, ".deb") && strings.Contains(lower, "alderpointdns") && !strings.Contains(lower, "_latest_") {
			debURL, debName = a.BrowserDownloadURL, a.Name
		}
		if strings.EqualFold(a.Name, "SHA256SUMS") {
			sumsURL = a.BrowserDownloadURL
		}
	}
	if debURL == "" {
		return s.recordCheckResult(ctx, cs, version, "", "", "", fmt.Errorf("release %q has no .deb asset matching this appliance's own naming (alderpointdns*_all.deb)", rel.TagName))
	}
	return s.recordCheckResult(ctx, cs, version, debURL, sumsURL, debName, nil)
}

func (s *Service) recordCheckResult(ctx context.Context, cs ChannelSettings, version, debURL, sumsURL, debName string, checkErr error) (ChannelSettings, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	status, errMsg := "ok", ""
	if checkErr != nil {
		status, errMsg = "error", checkErr.Error()
	}
	_, err := s.DB.ExecContext(ctx, `UPDATE update_channel_settings SET
		last_checked_at=?, last_check_status=?, last_check_error=?,
		latest_version=COALESCE(NULLIF(?, ''), latest_version),
		latest_deb_url=COALESCE(NULLIF(?, ''), latest_deb_url),
		latest_sha256sums_url=?, latest_deb_asset_name=COALESCE(NULLIF(?, ''), latest_deb_asset_name)
		WHERE id=1`, now, status, errMsg, version, debURL, sumsURL, debName)
	if err != nil {
		return ChannelSettings{}, err
	}
	updated, getErr := s.Get(ctx)
	if getErr != nil {
		return ChannelSettings{}, getErr
	}
	return updated, checkErr
}

// FetchLatestDeb downloads the currently-known-latest .deb (from the
// most recent CheckNow) and, if a SHA256SUMS asset was found alongside
// it, verifies the downloaded bytes against the real published
// checksum before returning them -- a checksum mismatch here is
// refused outright, the same "never trust an unverified candidate"
// discipline internal/hostagentd's own OpUpdateStage already applies a
// second time (independently) once these bytes reach it.
func (s *Service) FetchLatestDeb(ctx context.Context) (data []byte, version, sha256Hex string, err error) {
	cs, err := s.Get(ctx)
	if err != nil {
		return nil, "", "", err
	}
	if cs.LatestDebURL == "" {
		return nil, "", "", fmt.Errorf("%w: no update has been checked yet, or the last check found no .deb asset -- run a check first", ErrValidation)
	}
	data, err = s.download(ctx, cs.LatestDebURL)
	if err != nil {
		return nil, "", "", fmt.Errorf("downloading %s: %w", cs.LatestDebAssetName, err)
	}
	sum := sha256.Sum256(data)
	gotHex := hex.EncodeToString(sum[:])

	if cs.LatestSHA256SumsURL != "" {
		sums, err := s.download(ctx, cs.LatestSHA256SumsURL)
		if err != nil {
			return nil, "", "", fmt.Errorf("downloading SHA256SUMS: %w", err)
		}
		want, ok := parseSHA256Sums(string(sums), cs.LatestDebAssetName)
		if !ok {
			return nil, "", "", fmt.Errorf("SHA256SUMS does not list %q -- refusing an unverifiable download", cs.LatestDebAssetName)
		}
		if want != gotHex {
			return nil, "", "", fmt.Errorf("checksum mismatch for %s: SHA256SUMS says %s, downloaded file hashes to %s -- refusing", cs.LatestDebAssetName, want, gotHex)
		}
	}
	return data, cs.LatestVersion, gotHex, nil
}

func (s *Service) download(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 200<<20)) // 200MB ceiling -- generous for a .deb, never unbounded
}

// parseSHA256Sums finds one filename's own hash in a standard
// `sha256sum`-format file ("<hex>  <filename>" per line).
func parseSHA256Sums(text, filename string) (string, bool) {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name := strings.TrimPrefix(fields[len(fields)-1], "*")
		if name == filename {
			return strings.ToLower(fields[0]), true
		}
	}
	return "", false
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
