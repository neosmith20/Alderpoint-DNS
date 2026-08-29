// A real "Query Log deep link": the Clients page's Client analytics
// table sets this before navigating to the Query Log route; Query Log
// reads it once on mount to seed its client filter, then clears it so a
// later, unrelated visit to Query Log doesn't inherit a stale filter.
// Deliberately not URL/query-string-based -- router.svelte.ts's route
// model is a bare `/ui/{routeId}` path with no query-param support
// today, so this small shared module is the real mechanism rather than
// a dead link that merely navigates without actually filtering.
let pendingClient = $state<string | null>(null);

export const queryLogPrefill = {
  setClient(client: string) {
    pendingClient = client;
  },
  takeClient(): string | null {
    const v = pendingClient;
    pendingClient = null;
    return v;
  },
};
