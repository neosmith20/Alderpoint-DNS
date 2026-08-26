// Real, session-only UI Performance log (System Status page's "UI
// Performance table (session-only)" row) -- records actual route-change
// latency (navigate() call -> the new page's component resolved and
// ready to render), not synthetic numbers. Never persisted: a page
// reload starts a fresh, empty log, matching "session-only" exactly.
// Bounded to the most recent 200 entries so a long session's memory use
// stays flat.

export interface PerfEntry {
  route: string;
  ms: number;
  at: number; // Date.now() at record time
}

const MAX_ENTRIES = 200;

class PerfLog {
  entries = $state<PerfEntry[]>([]);

  record(route: string, ms: number): void {
    const next = [...this.entries, { route, ms, at: Date.now() }];
    this.entries = next.length > MAX_ENTRIES ? next.slice(next.length - MAX_ENTRIES) : next;
  }

  clear(): void {
    this.entries = [];
  }
}

export const perfLog = new PerfLog();
