// Navigation structure for the Standard/Advanced profile system (see
// profile.ts). `load` is only set for pages that actually work; an item
// without `load` renders as present-but-not-yet-available rather than as a
// fake/dead page (a pattern this file already used before the redesign --
// see PARITY_MATRIX.md and the Phase-4 rule against placeholder pages).
// Route ids are unchanged from before this redesign wherever the underlying
// page is unchanged, so existing bookmarks/links keep working. Each
// `load` is a static `import("./lib/X.svelte")` (not a dynamically-built
// path) on purpose -- Vite can only code-split/rewrite a statically
// analyzable specifier; a template-literal path would resolve at dev time
// and then 404 in the production build once file names are hashed.
import type { IconName } from "./lib/icons";
import type { Component } from "svelte";

export interface NavItem {
  id: string;
  label: string;
  icon: IconName;
  load?: () => Promise<{ default: Component }>;
  advanced?: boolean;
}

export interface NavGroup {
  id: string;
  label: string;
  icon: IconName;
  items: NavItem[];
  advanced?: boolean;
}

/** Dashboard, Query Log and Clients: flat, always-visible top-level items
 * above the nav groups (both profiles) -- these are the pages an operator
 * reaches for constantly, not filed under a section. */
export const TOP_ITEMS: NavItem[] = [
  {
    id: "dashboard",
    label: "Dashboard",
    icon: "dashboard",
    load: () => import("./lib/DashboardView.svelte") as unknown as Promise<{ default: Component }>,
  },
  {
    id: "analytics",
    label: "Query Log",
    icon: "dns",
    load: () => import("./lib/QueryLogView.svelte") as unknown as Promise<{ default: Component }>,
  },
  {
    id: "clients",
    label: "Clients",
    icon: "clients",
    load: () => import("./lib/ClientsView.svelte") as unknown as Promise<{ default: Component }>,
  },
];

export const NAV_GROUPS: NavGroup[] = [
  {
    id: "filters",
    label: "Filters",
    icon: "filters",
    items: [
      {
        id: "blocklists",
        label: "Blocklists",
        icon: "blocklists",
        load: () => import("./lib/BlocklistsView.svelte") as unknown as Promise<{ default: Component }>,
      },
      // Allowlists: no allow/deny "kind" on internal/blocklists.Subscription
      // today, so there is no real backend list to point this at yet --
      // left unavailable rather than aiming "Allowlists" at the Blocklists
      // page under a second label, which would make an operator manage the
      // same rows twice under two names. See the final report.
      { id: "allowlists", label: "Allowlists", icon: "blocklists" },
      {
        id: "filtering",
        label: "Custom Rules",
        icon: "security",
        load: () => import("./lib/CustomRulesView.svelte") as unknown as Promise<{ default: Component }>,
      },
      {
        id: "localdns",
        label: "Local DNS",
        icon: "localdns",
        load: () => import("./lib/LocalDnsView.svelte") as unknown as Promise<{ default: Component }>,
      },
      // Blocked Services: internal/policyentities has real service-blocking
      // rulesets (Advanced > Policy Profiles > Service Blocking Rulesets),
      // but no Standard-facing "toggle common services on/off" grid wired
      // to a default/global ruleset yet. Left unavailable rather than
      // reusing the Advanced ruleset editor under a simplified label.
      { id: "blocked-services", label: "Blocked Services", icon: "security" },
    ],
  },
  {
    id: "settings",
    label: "Settings",
    icon: "settings",
    items: [
      // General: no single consolidated "Appliance Identity / Protection
      // Defaults / Query Log / Statistics / Interface Preferences" page
      // exists yet -- those controls are currently split across
      // Administration (Appearance/Timestamp), Statistics (collection
      // settings) and PolicyEditor (global protection defaults). Left
      // unavailable rather than shipping a half-composed page.
      { id: "settings-general", label: "General", icon: "settings" },
      {
        id: "upstreams",
        label: "DNS",
        icon: "dns",
        load: () => import("./lib/UpstreamsView.svelte") as unknown as Promise<{ default: Component }>,
      },
      {
        id: "encryption",
        label: "Encryption",
        icon: "security",
        load: () => import("./lib/EncryptionView.svelte") as unknown as Promise<{ default: Component }>,
      },
    ],
  },
  {
    id: "system",
    label: "System",
    icon: "system",
    items: [
      {
        id: "backup",
        label: "Backup & Restore",
        icon: "operations",
        load: () => import("./lib/BackupView.svelte") as unknown as Promise<{ default: Component }>,
      },
      {
        id: "updates",
        label: "Software Updates",
        icon: "system",
        load: () => import("./lib/UpdatesView.svelte") as unknown as Promise<{ default: Component }>,
      },
      {
        id: "health",
        label: "System Status",
        icon: "system",
        load: () => import("./lib/SystemStatusView.svelte") as unknown as Promise<{ default: Component }>,
      },
    ],
  },
  {
    id: "advanced-dns",
    label: "Advanced DNS",
    icon: "advanced",
    advanced: true,
    items: [
      {
        id: "policy-entities",
        label: "Policy Profiles",
        icon: "security",
        load: () => import("./lib/PolicyEntitiesView.svelte") as unknown as Promise<{ default: Component }>,
      },
      {
        id: "policies",
        label: "Scope Policies",
        icon: "dns",
        load: () => import("./lib/ClientsAccessView.svelte") as unknown as Promise<{ default: Component }>,
      },
      {
        id: "upstreams-routing",
        label: "Upstreams & Routing",
        icon: "dns",
        load: () => import("./lib/UpstreamsView.svelte") as unknown as Promise<{ default: Component }>,
      },
      {
        id: "cache",
        label: "Cache",
        icon: "cache",
        load: () => import("./lib/CacheView.svelte") as unknown as Promise<{ default: Component }>,
      },
      {
        id: "dnsruntime",
        label: "DNS Runtime",
        icon: "dns",
        load: () => import("./lib/DnsRuntimeView.svelte") as unknown as Promise<{ default: Component }>,
      },
    ],
  },
  {
    id: "operations",
    label: "Operations",
    icon: "operations",
    advanced: true,
    items: [
      {
        id: "replication",
        label: "Replication",
        icon: "operations",
        load: () => import("./lib/ReplicationView.svelte") as unknown as Promise<{ default: Component }>,
      },
      {
        id: "network",
        label: "Network Configuration",
        icon: "system",
        load: () => import("./lib/NetworkView.svelte") as unknown as Promise<{ default: Component }>,
      },
      {
        id: "administration",
        label: "Administration",
        icon: "settings",
        load: () => import("./lib/AdministrationView.svelte") as unknown as Promise<{ default: Component }>,
      },
      {
        id: "audit",
        label: "Audit Log",
        icon: "audit",
        load: () => import("./lib/AuditLogView.svelte") as unknown as Promise<{ default: Component }>,
      },
      {
        id: "logs",
        label: "System Logs",
        icon: "audit",
        load: () => import("./lib/LogsView.svelte") as unknown as Promise<{ default: Component }>,
      },
      {
        id: "notifications",
        label: "Notifications",
        icon: "system",
        load: () => import("./lib/NotificationsView.svelte") as unknown as Promise<{ default: Component }>,
      },
      {
        id: "importexport",
        label: "Import & Migration",
        icon: "operations",
        load: () => import("./lib/ImportView.svelte") as unknown as Promise<{ default: Component }>,
      },
      {
        id: "statistics",
        label: "Advanced Analytics",
        icon: "dns",
        load: () => import("./lib/StatisticsView.svelte") as unknown as Promise<{ default: Component }>,
      },
    ],
  },
];

/** Setup Guide: pinned at the very bottom of the sidebar/drawer, alongside
 * theme/account/logout -- not filed under any group, both profiles. */
export const BOTTOM_ITEMS: NavItem[] = [
  {
    id: "setup-guide",
    label: "Setup Guide",
    icon: "guide",
    load: () => import("./lib/SetupGuideView.svelte") as unknown as Promise<{ default: Component }>,
  },
];

export const ALL_ITEMS: NavItem[] = [...TOP_ITEMS, ...NAV_GROUPS.flatMap((g) => g.items), ...BOTTOM_ITEMS];

/** The first real (implemented) route -- used as the post-login landing
 * page until Dashboard itself is built. */
export function defaultRouteId(): string {
  return ALL_ITEMS.find((i) => i.load)?.id ?? TOP_ITEMS[0].id;
}

export function findItem(id: string): NavItem | undefined {
  return ALL_ITEMS.find((i) => i.id === id);
}

export function groupOf(itemId: string): NavGroup | undefined {
  return NAV_GROUPS.find((g) => g.items.some((i) => i.id === itemId));
}

/** True when `id` only appears in nav while the Advanced profile is
 * selected -- i.e. its own group is Advanced-only, or it's an Advanced-only
 * flat item. Reaching it by direct link while Standard is selected must
 * still work (see App.svelte); this only drives the "Advanced page" label
 * and Nav.svelte's own visibility filter. */
export function isAdvancedRoute(id: string): boolean {
  const item = findItem(id);
  if (item?.advanced) return true;
  return groupOf(id)?.advanced === true;
}
