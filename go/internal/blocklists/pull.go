package blocklists

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// download fetches url, parses it, and atomically promotes a staged
// runtime artifact for this one subscription only -- desired state
// (subscription row) -> compile (parse+validate) -> stage -> promote,
// same shape localdns.go uses. On any error, the previously-promoted
// file for this subscription (if any) is left completely untouched:
// "previous-good retention" falls out naturally from writing to a fresh
// staged path and only ever rename(2)-ing over the runtime path on full
// success.
func (s *Service) download(ctx context.Context, url, subscriptionID string) (ParseResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return ParseResult{}, err
	}
	resp, err := s.HTTPClient.Do(req)
	if err != nil {
		return ParseResult{}, fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ParseResult{}, fmt.Errorf("download: HTTP %d", resp.StatusCode)
	}

	result := Parse(resp.Body)

	if err := os.MkdirAll(s.StagingDir, 0o755); err != nil {
		return result, err
	}
	if err := os.MkdirAll(s.RuntimeDir, 0o755); err != nil {
		return result, err
	}

	stagedPath := filepath.Join(s.StagingDir, subscriptionID+".rpz")
	tmpPath := fmt.Sprintf("%s.tmp.%d", stagedPath, time.Now().UnixNano())
	f, err := os.Create(tmpPath)
	if err != nil {
		return result, err
	}
	w := bufio.NewWriter(f)
	for _, d := range result.Domains {
		fmt.Fprintf(w, "%s CNAME .\n", d)
	}
	if err := w.Flush(); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return result, err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmpPath)
		return result, err
	}
	if err := os.Rename(tmpPath, stagedPath); err != nil {
		return result, err
	}

	runtimePath := filepath.Join(s.RuntimeDir, subscriptionID+".rpz")
	if err := os.Rename(stagedPath, runtimePath); err != nil { // atomic promotion
		return result, err
	}
	return result, nil
}
