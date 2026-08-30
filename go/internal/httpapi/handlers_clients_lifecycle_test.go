package httpapi

// HTTP-layer proof for the full managed-client lifecycle (edit, enable/
// disable, delete, group removal) added for the Clients & Access page
// build-out -- internal/clients' own service_test.go proves the
// underlying logic; this proves the routes are wired correctly end to
// end, including that they report the honest dns_runtime field where
// applicable (see internal/clients.SetClientEnabled/DeleteClient's own
// doc comments for why those two reach the live runtime and
// UpdateClient doesn't).
import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"alderpointdns/go-controlplane/internal/analyticssnapshot"
	"alderpointdns/go-controlplane/internal/clientalias"
	"alderpointdns/go-controlplane/internal/clients"
	"alderpointdns/go-controlplane/internal/dbmigrate"
	"alderpointdns/go-controlplane/internal/policy"
	"alderpointdns/go-controlplane/internal/pyanalytics"
)

func TestClientLifecycleHTTPEditEnableDeleteGroupRemoval(t *testing.T) {
	s := newPolicyTestServer(t)

	code, body := doHandler(t, s.handleCreateGroup, "POST", `{"name":"Kids","priority":1}`, nil)
	if code != 201 {
		t.Fatalf("create group: %d %+v", code, body)
	}
	groupID, _ := body["group_id"].(string)

	code, body = doHandler(t, s.handleCreateClient, "POST", `{"name":"Laptop","description":"orig"}`, nil)
	if code != 201 {
		t.Fatalf("create client: %d %+v", code, body)
	}
	clientIDf, _ := body["client_id"].(float64)
	clientID := int64(clientIDf)
	clientIDStr := strconv.FormatInt(clientID, 10)

	code, body = doHandler(t, s.handleAddClientGroup, "POST", `{"group_id":"`+groupID+`"}`, map[string]string{"id": clientIDStr})
	if code != 201 {
		t.Fatalf("add to group: %d %+v", code, body)
	}

	// Edit.
	code, body = doHandler(t, s.handleUpdateClient, "PATCH", `{"name":"Laptop2","description":"updated"}`, map[string]string{"id": clientIDStr})
	if code != 200 {
		t.Fatalf("update client: %d %+v", code, body)
	}
	code, listBody := doHandler(t, s.handleListClients, "GET", "", nil)
	if code != 200 {
		t.Fatalf("list clients: %d %+v", code, listBody)
	}
	list, _ := listBody["clients"].([]any)
	first, _ := list[0].(map[string]any)
	if first["name"] != "Laptop2" || first["description"] != "updated" {
		t.Fatalf("expected the edit to persist, got %+v", first)
	}

	// Disable.
	code, body = doHandler(t, s.handleSetClientEnabled, "POST", `{"enabled":false}`, map[string]string{"id": clientIDStr})
	if code != 200 {
		t.Fatalf("disable: %d %+v", code, body)
	}
	if _, ok := body["dns_runtime"]; !ok {
		t.Fatal("expected a dns_runtime field on disable (auto-apply convention)")
	}
	_, listBody = doHandler(t, s.handleListClients, "GET", "", nil)
	list, _ = listBody["clients"].([]any)
	first, _ = list[0].(map[string]any)
	if enabled, _ := first["enabled"].(bool); enabled {
		t.Fatal("expected enabled=false after disable")
	}

	// Remove from group.
	code, body = doHandler(t, s.handleRemoveClientGroup, "DELETE", "", map[string]string{"id": clientIDStr, "groupId": groupID})
	if code != 200 {
		t.Fatalf("remove from group: %d %+v", code, body)
	}
	_, listBody = doHandler(t, s.handleListClients, "GET", "", nil)
	list, _ = listBody["clients"].([]any)
	first, _ = list[0].(map[string]any)
	groups, _ := first["groups"].([]any)
	if len(groups) != 0 {
		t.Fatalf("expected no groups after removal, got %+v", groups)
	}

	// Delete.
	code, body = doHandler(t, s.handleDeleteClient, "DELETE", "", map[string]string{"id": clientIDStr})
	if code != 200 {
		t.Fatalf("delete: %d %+v", code, body)
	}
	_, listBody = doHandler(t, s.handleListClients, "GET", "", nil)
	list, _ = listBody["clients"].([]any)
	if len(list) != 0 {
		t.Fatalf("expected no clients after delete, got %+v", list)
	}

	// Deleting again is a real not-found, not a silent no-op.
	code, body = doHandler(t, s.handleDeleteClient, "DELETE", "", map[string]string{"id": clientIDStr})
	if code != 404 {
		t.Fatalf("expected 404 deleting an already-deleted client, got %d %+v", code, body)
	}
}

func TestObservedClientsHTTPDegradedWithoutAnalytics(t *testing.T) {
	s := newPolicyTestServer(t) // Analytics left nil, matching every other analytics-backed handler's nil-safe contract
	code, body := doHandler(t, s.handleListObservedClients, "GET", "", nil)
	if code != 200 {
		t.Fatalf("expected 200 even when degraded (truthful body, not an HTTP error): %d %+v", code, body)
	}
	if degraded, _ := body["degraded"].(bool); !degraded {
		t.Fatal("expected degraded=true with no Analytics wired")
	}
	observed, _ := body["observed"].([]any)
	if len(observed) != 0 {
		t.Fatalf("expected no observed rows while degraded, got %+v", observed)
	}
}

// TestObservedClientsHTTPFiltersLoopbackAndCrossReferencesManaged proves
// the real, disclosed-narrower discovery substitute: it excludes
// loopback/unspecified addresses from ever being presented as a host,
// and correctly flags an address that already belongs to a managed
// client's ipv4/ipv6 identifier.
func TestObservedClientsHTTPFiltersLoopbackAndCrossReferencesManaged(t *testing.T) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "control.db")
	db, err := sql.Open("sqlite", dbPath+"?_pragma=busy_timeout(3000)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := dbmigrate.Up(context.Background(), db, "../../schema/migrations"); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	clientsSvc := &clients.Service{DB: db}
	knownID, err := clientsSvc.CreateClient(context.Background(), "Known Laptop", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := clientsSvc.AddIdentifier(context.Background(), knownID, "ipv4", "192.168.1.50"); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	source := filepath.Join(dir, "aggregates.db")
	setup, err := sql.Open("sqlite", source)
	if err != nil {
		t.Fatal(err)
	}
	_, err = setup.Exec(`
		CREATE TABLE schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
		INSERT INTO schema_meta VALUES ('version', '1');
		CREATE TABLE time_buckets (bucket_start INTEGER, granularity TEXT, total_queries INTEGER, blocked_queries INTEGER, cache_hits INTEGER, cache_misses INTEGER);
		CREATE TABLE dimension_counts (bucket_start INTEGER, granularity TEXT, dimension TEXT, value TEXT, count INTEGER);
		CREATE TABLE live_buckets (bucket_start INTEGER PRIMARY KEY, total_queries INTEGER, blocked_queries INTEGER, cache_hits INTEGER, cache_misses INTEGER, updated_at REAL);
	`)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	bucketStart := (now / 60) * 60
	if _, err := setup.Exec(`INSERT INTO dimension_counts (bucket_start, granularity, dimension, value, count) VALUES
		(?, 'minute', 'client', '127.0.0.1', 40),
		(?, 'minute', 'client', '192.168.1.50', 25),
		(?, 'minute', 'client', '192.168.1.99', 12)`,
		bucketStart, bucketStart, bucketStart); err != nil {
		t.Fatal(err)
	}
	setup.Close()

	published := filepath.Join(dir, "published")
	staging := filepath.Join(dir, "staging")
	if _, err := analyticssnapshot.Refresh(context.Background(), source, published, staging, 3); err != nil {
		t.Fatal(err)
	}
	reader, err := pyanalytics.Open(published)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { reader.Close() })

	aliasSvc := &clientalias.Service{DB: db}
	if _, err := aliasSvc.Create(context.Background(), "192.168.1.96/28", "Guest devices", ""); err != nil {
		t.Fatal(err)
	}

	s := &Server{
		DB:            db,
		Policy:        &policy.Service{DB: db},
		Clients:       clientsSvc,
		ClientAliases: aliasSvc,
		Analytics:     reader,
		Log:           slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	code, body := doHandler(t, s.handleListObservedClients, "GET", "", nil)
	if code != 200 {
		t.Fatalf("observed: %d %+v", code, body)
	}
	observed, _ := body["observed"].([]any)
	seen := map[string]map[string]any{}
	for _, o := range observed {
		row, _ := o.(map[string]any)
		addr, _ := row["address"].(string)
		seen[addr] = row
	}
	if _, ok := seen["127.0.0.1"]; ok {
		t.Fatalf("loopback address must never be presented as an observed host, got %+v", observed)
	}
	known, ok := seen["192.168.1.50"]
	if !ok {
		t.Fatalf("expected the known address to appear, got %+v", observed)
	}
	if managed, _ := known["managed"].(bool); !managed {
		t.Fatalf("expected 192.168.1.50 to be flagged managed (matches an existing ipv4 identifier), got %+v", known)
	}
	newAddr, ok := seen["192.168.1.99"]
	if !ok {
		t.Fatalf("expected the new address to appear, got %+v", observed)
	}
	if managed, _ := newAddr["managed"].(bool); managed {
		t.Fatalf("expected 192.168.1.99 to be flagged unmanaged, got %+v", newAddr)
	}
	// 192.168.1.99 falls inside the real "Guest devices" alias CIDR
	// (192.168.1.96/28) -- closing the "Observed Clients never resolves
	// aliases" gap PARITY_MATRIX.md used to disclose.
	if label, _ := newAddr["alias_label"].(string); label != "Guest devices" {
		t.Fatalf("expected the unmanaged-but-aliased address to carry alias_label=\"Guest devices\", got %+v", newAddr)
	}
	if label, ok := known["alias_label"]; ok {
		t.Fatalf("a managed address must not also carry an alias_label (managed name always wins), got %+v", label)
	}
}

func TestListNetworksEmbedsPolicyLayer(t *testing.T) {
	s := newPolicyTestServer(t)
	code, body := doHandler(t, s.handleCreateNetwork, "POST", `{"network_id":"net-1","cidr":"10.0.0.0/24"}`, nil)
	if code != 201 {
		t.Fatalf("create network: %d %+v", code, body)
	}
	code, body = doHandler(t, s.handlePutNetworkPolicy, "PUT", `{"blocking_response_mode":"refused"}`, map[string]string{"id": "net-1"})
	if code != 200 {
		t.Fatalf("put network policy: %d %+v", code, body)
	}
	code, body = doHandler(t, s.handleListNetworks, "GET", "", nil)
	if code != 200 {
		t.Fatalf("list networks: %d %+v", code, body)
	}
	networks, _ := body["networks"].([]any)
	if len(networks) != 1 {
		t.Fatalf("expected 1 network, got %+v", networks)
	}
	n, _ := networks[0].(map[string]any)
	policyLayer, ok := n["policy"].(map[string]any)
	if !ok {
		t.Fatalf("expected an embedded policy layer, got %+v", n)
	}
	if policyLayer["blocking_response_mode"] != "refused" {
		t.Fatalf("expected the saved network policy to be embedded, got %+v", policyLayer)
	}
}
