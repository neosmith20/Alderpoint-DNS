package softwareupdates

import (
	"context"
	"net/http"
	"testing"
	"time"
)

// TestCheckNowAgainstTheRealLiveGitHubRepo is the strongest proof this
// package's real GitHub Releases integration actually works: not a
// mocked httptest.Server standing in for GitHub's own response shape,
// but the real github.com/neosmith20/Alderpoint-DNS repo's own real
// /releases/latest endpoint (the owner-confirmed real channel this
// deployment is seeded with). Skips (never fails the suite) when this
// environment has no outbound network access -- a real, expected
// condition in some CI/sandbox environments, distinct from this
// package's own logic being broken (which the mocked tests in
// service_test.go already prove independently of network access).
func TestCheckNowAgainstTheRealLiveGitHubRepo(t *testing.T) {
	probeCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(probeCtx, http.MethodGet, "https://api.github.com", nil)
	if _, err := http.DefaultClient.Do(req); err != nil {
		t.Skipf("no outbound network access in this environment: %v", err)
	}

	s := newTestService(t)
	cs, err := s.CheckNow(context.Background())
	if err != nil {
		t.Fatalf("real check against github.com/neosmith20/Alderpoint-DNS failed: %v (%+v)", err, cs)
	}
	if cs.LatestVersion == "" || cs.LatestDebURL == "" {
		t.Fatalf("expected a real version+url from the real repo, got %+v", cs)
	}
	t.Logf("real live check result: version=%s url=%s", cs.LatestVersion, cs.LatestDebURL)
}
