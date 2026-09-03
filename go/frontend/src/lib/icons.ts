// Hand-authored inline SVG icon set. Original geometry (not copied from any
// icon library or product) -- 24x24 viewbox, 1.75px stroke, round joins, in
// the spirit of a modern outline icon set without reusing anyone else's
// actual paths. Rendered via <Icon name="..."/> so markup lives in one place.
export type IconName =
  | "dashboard"
  | "dns"
  | "security"
  | "operations"
  | "system"
  | "blocklists"
  | "localdns"
  | "chevron"
  | "menu"
  | "close"
  | "sun"
  | "moon"
  | "logout"
  | "spinner"
  | "filters"
  | "settings"
  | "guide"
  | "clients"
  | "cache"
  | "audit"
  | "advanced";

// Each entry is the inner markup of an <svg viewBox="0 0 24 24">.
export const ICONS: Record<IconName, string> = {
  dashboard: `<rect x="3" y="3" width="7.5" height="7.5" rx="1.5"/><rect x="13.5" y="3" width="7.5" height="4.5" rx="1.5"/><rect x="13.5" y="9.5" width="7.5" height="11" rx="1.5"/><rect x="3" y="12.5" width="7.5" height="8" rx="1.5"/>`,
  dns: `<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.5 2.5 3.8 5.7 3.8 9s-1.3 6.5-3.8 9c-2.5-2.5-3.8-5.7-3.8-9S9.5 5.5 12 3z"/>`,
  security: `<path d="M12 3l7 3v5.2c0 4.6-3 8.4-7 9.8-4-1.4-7-5.2-7-9.8V6l7-3z"/><path d="M9 12l2 2 4-4"/>`,
  operations: `<path d="M12 3l8 4.5-8 4.5-8-4.5L12 3z"/><path d="M4 12l8 4.5 8-4.5M4 16.5l8 4.5 8-4.5"/>`,
  system: `<circle cx="12" cy="12" r="3"/><path d="M12 3v2.2M12 18.8V21M21 12h-2.2M5.2 12H3M18.1 5.9l-1.55 1.55M7.45 16.55L5.9 18.1M18.1 18.1l-1.55-1.55M7.45 7.45L5.9 5.9"/>`,
  blocklists: `<circle cx="12" cy="12" r="9"/><path d="M6 6l12 12"/>`,
  localdns: `<rect x="3.5" y="4" width="17" height="4.5" rx="1.2"/><rect x="3.5" y="10" width="17" height="4.5" rx="1.2"/><rect x="3.5" y="16" width="17" height="4.5" rx="1.2"/><circle cx="7" cy="6.25" r="0.9" fill="currentColor" stroke="none"/><circle cx="7" cy="12.25" r="0.9" fill="currentColor" stroke="none"/><circle cx="7" cy="18.25" r="0.9" fill="currentColor" stroke="none"/>`,
  chevron: `<path d="M7 9.5l5 5 5-5"/>`,
  menu: `<path d="M4 6.5h16M4 12h16M4 17.5h16"/>`,
  close: `<path d="M6 6l12 12M18 6L6 18"/>`,
  sun: `<circle cx="12" cy="12" r="4.2"/><path d="M12 2.5v2.4M12 19.1v2.4M4.6 4.6l1.7 1.7M17.7 17.7l1.7 1.7M2.5 12h2.4M19.1 12h2.4M4.6 19.4l1.7-1.7M17.7 6.3l1.7-1.7"/>`,
  moon: `<path d="M20 14.5A8.5 8.5 0 1 1 9.5 4a7 7 0 0 0 10.5 10.5z"/>`,
  logout: `<path d="M9 4H5.8A1.8 1.8 0 0 0 4 5.8v12.4A1.8 1.8 0 0 0 5.8 20H9M15.5 16.5L20 12l-4.5-4.5M20 12H9"/>`,
  spinner: `<circle cx="12" cy="12" r="8.5" opacity="0.25"/><path d="M20.5 12a8.5 8.5 0 0 0-8.5-8.5"/>`,
  filters: `<path d="M4 5h16M7 12h10M10.5 19h3"/>`,
  settings: `<circle cx="12" cy="12" r="3.2"/><path d="M12 4v2.4M12 17.6V20M20 12h-2.4M6.4 12H4M17.3 6.7l-1.7 1.7M8.4 15.6l-1.7 1.7M17.3 17.3l-1.7-1.7M8.4 8.4L6.7 6.7"/>`,
  guide: `<path d="M4 5.5c2.5-1 5.2-1 7.5.5v13c-2.3-1.5-5-1.5-7.5-.5v-13z"/><path d="M20 5.5c-2.5-1-5.2-1-7.5.5v13c2.3-1.5 5-1.5 7.5-.5v-13z"/>`,
  clients: `<circle cx="8.5" cy="8" r="3"/><circle cx="16" cy="9.5" r="2.4"/><path d="M3 19c.4-3 2.6-5 5.5-5s5.1 2 5.5 5M14.8 14.5c2.3.2 4 1.9 4.3 4.5"/>`,
  cache: `<ellipse cx="12" cy="6" rx="8" ry="3"/><path d="M4 6v6c0 1.7 3.6 3 8 3s8-1.3 8-3V6M4 12v6c0 1.7 3.6 3 8 3s8-1.3 8-3v-6"/>`,
  audit: `<rect x="4.5" y="3" width="15" height="18" rx="1.5"/><path d="M8 8h8M8 12h8M8 16h5"/>`,
  advanced: `<path d="M4 12l3.5-8h9L20 12l-3.5 8h-9L4 12z"/><circle cx="12" cy="12" r="2.6"/>`,
};
