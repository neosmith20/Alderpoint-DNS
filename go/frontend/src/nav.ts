// Complete V2 navigation structure -- every section and page from
// PARITY_MATRIX.md, so the shell's information architecture is honest and
// complete from day one. `load` is only set for pages that actually work;
// an item without `load` renders as present-but-not-yet-available rather
// than as a fake/dead page (see PARITY_MATRIX.md and the Phase-4 rule
// against placeholder pages). Route ids match app/v2/ui/app.js's ids 1:1
// so the parity matrix, this file, and the Python source all name the same
// thing the same way.
import type { IconName } from "./lib/icons";
import type { Component } from "svelte";

export interface NavItem {
  id: string;
  label: string;
  icon: IconName;
  load?: () => Promise<{ default: Component }>;
}

export interface NavGroup {
  id: string;
  label: string;
  icon: IconName;
  items: NavItem[];
}

export const TOP_LEVEL: NavItem = {
  id: "dashboard",
  label: "Dashboard",
  icon: "dashboard",
  load: () => import("./lib/DashboardView.svelte") as unknown as Promise<{ default: Component }>,
};

export const NAV_GROUPS: NavGroup[] = [
  {
    id: "dns",
    label: "DNS",
    icon: "dns",
    items: [
      {
        id: "analytics",
        label: "Query Log",
        icon: "dns",
        load: () => import("./lib/QueryLogView.svelte") as unknown as Promise<{ default: Component }>,
      },
      {
        id: "clients",
        label: "Clients",
        icon: "dns",
        load: () => import("./lib/ClientsView.svelte") as unknown as Promise<{ default: Component }>,
      },
      {
        id: "policies",
        label: "Clients & Access",
        icon: "dns",
        load: () => import("./lib/ClientsAccessView.svelte") as unknown as Promise<{ default: Component }>,
      },
      {
        id: "localdns",
        label: "Local DNS",
        icon: "localdns",
        load: () => import("./lib/LocalDnsView.svelte") as unknown as Promise<{ default: Component }>,
      },
      {
        id: "upstreams",
        label: "DNS Settings",
        icon: "dns",
        load: () => import("./lib/UpstreamsView.svelte") as unknown as Promise<{ default: Component }>,
      },
      {
        id: "cache",
        label: "Cache",
        icon: "dns",
        load: () => import("./lib/CacheView.svelte") as unknown as Promise<{ default: Component }>,
      },
    ],
  },
  {
    id: "security",
    label: "Security",
    icon: "security",
    items: [
      {
        id: "filtering",
        label: "Filters",
        icon: "security",
        load: () => import("./lib/CustomRulesView.svelte") as unknown as Promise<{ default: Component }>,
      },
      {
        id: "blocklists",
        label: "Blocklists",
        icon: "blocklists",
        load: () => import("./lib/BlocklistsView.svelte") as unknown as Promise<{ default: Component }>,
      },
      {
        id: "encryption",
        label: "Encryption",
        icon: "security",
        load: () => import("./lib/EncryptionView.svelte") as unknown as Promise<{ default: Component }>,
      },
      {
        id: "policy-entities",
        label: "Policy Profiles",
        icon: "security",
        load: () => import("./lib/PolicyEntitiesView.svelte") as unknown as Promise<{ default: Component }>,
      },
    ],
  },
  {
    id: "operations",
    label: "Operations",
    icon: "operations",
    items: [
      {
        id: "importexport",
        label: "Import",
        icon: "operations",
        load: () => import("./lib/ImportView.svelte") as unknown as Promise<{ default: Component }>,
      },
      {
        id: "backup",
        label: "Backup & Restore",
        icon: "operations",
        load: () => import("./lib/BackupView.svelte") as unknown as Promise<{ default: Component }>,
      },
      {
        id: "replication",
        label: "Replication",
        icon: "operations",
        load: () => import("./lib/ReplicationView.svelte") as unknown as Promise<{ default: Component }>,
      },
    ],
  },
  {
    id: "system",
    label: "System",
    icon: "system",
    items: [
      {
        id: "statistics",
        label: "Statistics",
        icon: "system",
        load: () => import("./lib/StatisticsView.svelte") as unknown as Promise<{ default: Component }>,
      },
      {
        id: "health",
        label: "System Status",
        icon: "system",
        load: () => import("./lib/SystemStatusView.svelte") as unknown as Promise<{ default: Component }>,
      },
      {
        id: "administration",
        label: "Administration",
        icon: "system",
        load: () => import("./lib/AdministrationView.svelte") as unknown as Promise<{ default: Component }>,
      },
      {
        id: "network",
        label: "Network Configuration",
        icon: "system",
        load: () => import("./lib/NetworkView.svelte") as unknown as Promise<{ default: Component }>,
      },
      {
        id: "notifications",
        label: "Notifications",
        icon: "system",
        load: () => import("./lib/NotificationsView.svelte") as unknown as Promise<{ default: Component }>,
      },
      {
        id: "updates",
        label: "Software Updates",
        icon: "system",
        load: () => import("./lib/UpdatesView.svelte") as unknown as Promise<{ default: Component }>,
      },
      {
        id: "logs",
        label: "Logs",
        icon: "system",
        load: () => import("./lib/LogsView.svelte") as unknown as Promise<{ default: Component }>,
      },
      {
        id: "dnsruntime",
        label: "DNS Runtime",
        icon: "system",
        load: () => import("./lib/DnsRuntimeView.svelte") as unknown as Promise<{ default: Component }>,
      },
    ],
  },
];

export const ALL_ITEMS: NavItem[] = [TOP_LEVEL, ...NAV_GROUPS.flatMap((g) => g.items)];

/** The first real (implemented) route -- used as the post-login landing page
 * until Dashboard itself is built. */
export function defaultRouteId(): string {
  return ALL_ITEMS.find((i) => i.load)?.id ?? TOP_LEVEL.id;
}

export function findItem(id: string): NavItem | undefined {
  return ALL_ITEMS.find((i) => i.id === id);
}

export function groupOf(itemId: string): NavGroup | undefined {
  return NAV_GROUPS.find((g) => g.items.some((i) => i.id === itemId));
}
