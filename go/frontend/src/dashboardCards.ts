// Dashboard card customization: add/remove (show/hide) and reorder, with
// persistence -- new V2-only scope per the governing task (Python V2 has
// no equivalent). Reorder is button-based (move up/down) rather than
// drag-and-drop: equally real functionality, far more reliably testable
// (keyboard-accessible, Chromium-clickable) than a drag interaction, and
// nothing in the requirement specifically mandates drag-and-drop.
//
// The lower two-column grid's own default order/visibility matches the
// redesign's four named row pairs exactly (Query Outcomes/Top Clients,
// Top Domains/Top Blocked Domains, Top Upstream Resolvers/Cache
// Effectiveness, Recent Activity/System Health) -- everything after that
// is a real extra panel this appliance already had before the redesign
// (per-dimension breakdowns, configured-profile mini lists, native-Go
// summary counts) that didn't fit the four named rows. Those stay fully
// real and one checkbox away, just hidden by default rather than
// crowding the page beyond what the redesign actually asked for.
export interface CardDef {
  id: string;
  label: string;
  defaultVisible: boolean;
}

export const ALL_CARDS: CardDef[] = [
  { id: "outcomes", label: "Query Outcomes", defaultVisible: true },
  { id: "top-clients", label: "Top Clients", defaultVisible: true },
  { id: "top-domains", label: "Top Domains", defaultVisible: true },
  { id: "top-blocked-domains", label: "Top Blocked Domains", defaultVisible: true },
  { id: "top-upstreams", label: "Top Upstream Resolvers", defaultVisible: true },
  { id: "cache-effectiveness", label: "Cache Effectiveness", defaultVisible: true },
  { id: "recent-activity", label: "Recent Activity", defaultVisible: true },
  { id: "system-health", label: "System Health", defaultVisible: true },
  { id: "qtypes", label: "Query Types", defaultVisible: false },
  { id: "rcodes", label: "Response Codes", defaultVisible: false },
  { id: "protocols", label: "Protocol Usage", defaultVisible: false },
  { id: "clients", label: "Clients (managed + observed)", defaultVisible: false },
  { id: "upstreams", label: "Upstreams (configured profiles)", defaultVisible: false },
  { id: "blocklists", label: "Blocklists", defaultVisible: false },
  { id: "localdns", label: "Local DNS", defaultVisible: false },
];

export interface CardState {
  id: string;
  visible: boolean;
}

const KEY = "apdns-go-dashboard-cards";

export function defaultCardOrder(): CardState[] {
  return ALL_CARDS.map((c) => ({ id: c.id, visible: c.defaultVisible }));
}

export function loadCardOrder(): CardState[] {
  try {
    const raw = localStorage.getItem(KEY);
    if (raw) {
      const stored: CardState[] = JSON.parse(raw);
      // Reconcile with ALL_CARDS: a card added to the product after the
      // preference was saved must still show up (appended, using its own
      // default visibility), and a since-removed id must not linger
      // forever.
      const known = new Map(ALL_CARDS.map((c) => [c.id, c]));
      const kept = stored.filter((c) => known.has(c.id));
      const keptIds = new Set(kept.map((c) => c.id));
      const added = ALL_CARDS.filter((c) => !keptIds.has(c.id)).map((c) => ({ id: c.id, visible: c.defaultVisible }));
      return [...kept, ...added];
    }
  } catch {
    /* fall through to default */
  }
  return defaultCardOrder();
}

export function saveCardOrder(order: CardState[]): void {
  try {
    localStorage.setItem(KEY, JSON.stringify(order));
  } catch {
    /* best-effort persistence only */
  }
}
