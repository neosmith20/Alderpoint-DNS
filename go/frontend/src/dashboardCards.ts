// Dashboard card customization: add/remove (show/hide) and reorder, with
// persistence -- new V2-only scope per the governing task (Python V2 has
// no equivalent). Reorder is button-based (move up/down) rather than
// drag-and-drop: equally real functionality, far more reliably testable
// (keyboard-accessible, Chromium-clickable) than a drag interaction, and
// nothing in the requirement specifically mandates drag-and-drop.
export interface CardDef {
  id: string;
  label: string;
}

export const ALL_CARDS: CardDef[] = [
  { id: "blocklists", label: "Blocklists" },
  { id: "localdns", label: "Local DNS" },
  { id: "activity", label: "DNS Activity" },
  { id: "top-domains", label: "Top Domains" },
  { id: "top-blocked-domains", label: "Top Blocked Domains" },
];

export interface CardState {
  id: string;
  visible: boolean;
}

const KEY = "apdns-go-dashboard-cards";

export function loadCardOrder(): CardState[] {
  try {
    const raw = localStorage.getItem(KEY);
    if (raw) {
      const stored: CardState[] = JSON.parse(raw);
      // Reconcile with ALL_CARDS: a card added to the product after the
      // preference was saved must still show up (appended, visible), and
      // a since-removed id must not linger forever.
      const known = new Set(ALL_CARDS.map((c) => c.id));
      const kept = stored.filter((c) => known.has(c.id));
      const keptIds = new Set(kept.map((c) => c.id));
      const added = ALL_CARDS.filter((c) => !keptIds.has(c.id)).map((c) => ({ id: c.id, visible: true }));
      return [...kept, ...added];
    }
  } catch {
    /* fall through to default */
  }
  return ALL_CARDS.map((c) => ({ id: c.id, visible: true }));
}

export function saveCardOrder(order: CardState[]): void {
  try {
    localStorage.setItem(KEY, JSON.stringify(order));
  } catch {
    /* best-effort persistence only */
  }
}
