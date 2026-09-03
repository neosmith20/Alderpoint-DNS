// Owner-selectable color palette (Administration -> Appearance). Each
// swatch carries a base/strong pair (base drives buttons/links/active
// state, strong drives hover) plus a precomputed foreground color for
// text sitting on top of a filled base-colored surface -- picked by
// hand per swatch rather than computed from a live contrast formula,
// so every option is guaranteed legible in both themes without a
// runtime contrast check. 18 modern, distinct hues -- comfortably over
// the owner-requested minimum of 15.
export interface ColorSwatch {
  id: string;
  name: string;
  base: string;
  strong: string;
  fg: string;
}

export const COLOR_PALETTE: ColorSwatch[] = [
  { id: "teal", name: "Teal", base: "#0d9488", strong: "#0f766e", fg: "#ffffff" },
  { id: "cyan", name: "Cyan", base: "#0891b2", strong: "#0e7490", fg: "#ffffff" },
  { id: "sky", name: "Sky", base: "#0284c7", strong: "#0369a1", fg: "#ffffff" },
  { id: "blue", name: "Blue", base: "#2563eb", strong: "#1d4ed8", fg: "#ffffff" },
  { id: "indigo", name: "Indigo", base: "#4f46e5", strong: "#4338ca", fg: "#ffffff" },
  { id: "violet", name: "Violet", base: "#7c3aed", strong: "#6d28d9", fg: "#ffffff" },
  { id: "purple", name: "Purple", base: "#9333ea", strong: "#7e22ce", fg: "#ffffff" },
  { id: "fuchsia", name: "Fuchsia", base: "#c026d3", strong: "#a21caf", fg: "#ffffff" },
  { id: "pink", name: "Pink", base: "#db2777", strong: "#be185d", fg: "#ffffff" },
  { id: "rose", name: "Rose", base: "#e11d48", strong: "#be123c", fg: "#ffffff" },
  { id: "red", name: "Red", base: "#dc2626", strong: "#b91c1c", fg: "#ffffff" },
  { id: "orange", name: "Orange", base: "#ea580c", strong: "#c2410c", fg: "#ffffff" },
  { id: "amber", name: "Amber", base: "#d97706", strong: "#b45309", fg: "#ffffff" },
  { id: "yellow", name: "Yellow", base: "#ca8a04", strong: "#a16207", fg: "#1c1502" },
  { id: "lime", name: "Lime", base: "#65a30d", strong: "#4d7c0f", fg: "#ffffff" },
  { id: "green", name: "Green", base: "#16a34a", strong: "#15803d", fg: "#ffffff" },
  { id: "emerald", name: "Emerald", base: "#059669", strong: "#047857", fg: "#ffffff" },
  { id: "slate", name: "Slate", base: "#475569", strong: "#334155", fg: "#ffffff" },
];

export function swatchById(id: string): ColorSwatch | undefined {
  return COLOR_PALETTE.find((s) => s.id === id);
}
