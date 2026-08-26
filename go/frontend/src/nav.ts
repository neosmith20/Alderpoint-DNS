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
      { id: "analytics", label: "Query Log", icon: "dns" },
      { id: "clients", label: "Clients", icon: "dns" },
      { id: "policies", label: "Clients & Access", icon: "dns" },
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
      { id: "cache", label: "Cache", icon: "dns" },
    ],
  },
  {
    id: "security",
    label: "Security",
    icon: "security",
    items: [
      { id: "filtering", label: "Filters", icon: "security" },
      {
        id: "blocklists",
        label: "Blocklists",
        icon: "blocklists",
        load: () => import("./lib/BlocklistsView.svelte") as unknown as Promise<{ default: Component }>,
      },
      { id: "encryption", label: "Encryption", icon: "security" },
    ],
  },
  {
    id: "operations",
    label: "Operations",
    icon: "operations",
    items: [
      { id: "importexport", label: "Import", icon: "operations" },
      { id: "backup", label: "Backup & Restore", icon: "operations" },
      { id: "replication", label: "Replication", icon: "operations" },
    ],
  },
  {
    id: "system",
    label: "System",
    icon: "system",
    items: [
      { id: "statistics", label: "Statistics", icon: "system" },
      { id: "health", label: "System Status", icon: "system" },
      {
        id: "administration",
        label: "Administration",
        icon: "system",
        load: () => import("./lib/AdministrationView.svelte") as unknown as Promise<{ default: Component }>,
      },
      { id: "network", label: "Network Configuration", icon: "system" },
      { id: "notifications", label: "Notifications", icon: "system" },
      { id: "updates", label: "Software Updates", icon: "system" },
      { id: "logs", label: "Logs", icon: "system" },
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
