// A tiny per-key sequence guard against stale-response races: if two
// requests for the same key are in flight and the older one resolves
// after the newer one, its result must never be allowed to overwrite the
// newer state. Each call site owns one StaleGuard per logical resource
// (e.g. one for "blocklists list", one for "local-dns list").
export class StaleGuard {
  private seq = 0;

  /** Call before starting the async request; returns a token. */
  start(): number {
    this.seq += 1;
    return this.seq;
  }

  /** Call with the token from start(): true if this is still the latest request. */
  isCurrent(token: number): boolean {
    return token === this.seq;
  }
}
