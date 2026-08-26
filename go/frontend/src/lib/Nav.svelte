<script lang="ts">
  import Icon from "./Icon.svelte";
  import { NAV_GROUPS, TOP_LEVEL, type NavGroup } from "../nav";
  import { router } from "../router.svelte";
  import { loadKeepMultipleOpen } from "../navPrefs";

  let { mobileOpen = $bindable(false) }: { mobileOpen?: boolean } = $props();

  const OPEN_GROUPS_KEY = "apdns-go-nav-open-groups";
  const COLLAPSED_KEY = "apdns-go-nav-collapsed";

  function loadOpenGroups(): Set<string> {
    try {
      const raw = localStorage.getItem(OPEN_GROUPS_KEY);
      if (raw) return new Set(JSON.parse(raw));
    } catch {
      /* fall through to default */
    }
    // Default: every group open (the existing multiple-open preference).
    return new Set(NAV_GROUPS.map((g) => g.id));
  }

  let openGroups = $state<Set<string>>(loadOpenGroups());
  let collapsed = $state(localStorage.getItem(COLLAPSED_KEY) === "1");
  let flyoutGroup = $state<string | null>(null);
  let navEl: HTMLElement | undefined;

  function persistOpenGroups() {
    try {
      localStorage.setItem(OPEN_GROUPS_KEY, JSON.stringify([...openGroups]));
    } catch {
      /* best-effort */
    }
  }

  function toggleGroup(id: string) {
    if (collapsed) {
      flyoutGroup = flyoutGroup === id ? null : id;
      return;
    }
    const next = new Set(openGroups);
    const wasOpen = next.has(id);
    if (!loadKeepMultipleOpen() && !wasOpen) {
      // Single-open accordion: opening one group closes every other.
      next.clear();
    }
    if (wasOpen) next.delete(id);
    else next.add(id);
    openGroups = next;
    persistOpenGroups();
  }

  function toggleCollapsed() {
    collapsed = !collapsed;
    flyoutGroup = null;
    try {
      localStorage.setItem(COLLAPSED_KEY, collapsed ? "1" : "0");
    } catch {
      /* best-effort */
    }
  }

  function go(id: string) {
    router.navigate(id);
    flyoutGroup = null;
    mobileOpen = false;
  }

  function onWindowClick(e: MouseEvent) {
    if (flyoutGroup && navEl && !navEl.contains(e.target as Node)) flyoutGroup = null;
  }

  function onKeydown(e: KeyboardEvent) {
    if (e.key === "Escape") {
      flyoutGroup = null;
      mobileOpen = false;
    }
  }

  function groupHasActive(g: NavGroup): boolean {
    return g.items.some((i) => i.id === router.current);
  }
</script>

<svelte:window onclick={onWindowClick} onkeydown={onKeydown} />

{#if mobileOpen}
  <button class="scrim" aria-label="Close navigation" onclick={() => (mobileOpen = false)}></button>
{/if}

<nav
  bind:this={navEl}
  class="sidebar"
  class:collapsed
  class:mobile-open={mobileOpen}
  aria-label="Main"
>
  <button
    class="item top-level"
    class:active={router.current === TOP_LEVEL.id}
    onclick={() => go(TOP_LEVEL.id)}
    aria-current={router.current === TOP_LEVEL.id ? "page" : undefined}
  >
    <Icon name={TOP_LEVEL.icon} />
    <span class="label">{TOP_LEVEL.label}</span>
  </button>

  <ul class="groups">
    {#each NAV_GROUPS as group (group.id)}
      <li class="group" class:flyout-open={flyoutGroup === group.id}>
        <button
          class="group-toggle"
          class:active={groupHasActive(group)}
          aria-expanded={collapsed ? flyoutGroup === group.id : openGroups.has(group.id)}
          onclick={() => toggleGroup(group.id)}
        >
          <Icon name={group.icon} />
          <span class="label">{group.label}</span>
          {#if !collapsed}
            <span class="chevron" class:open={openGroups.has(group.id)}>
              <Icon name="chevron" size={14} />
            </span>
          {/if}
        </button>

        {#if collapsed}
          {#if flyoutGroup === group.id}
            <ul class="flyout" role="menu">
              <li class="flyout-label">{group.label}</li>
              {#each group.items as item (item.id)}
                <li>
                  <button
                    class="item"
                    class:active={router.current === item.id}
                    class:unavailable={!item.load}
                    disabled={!item.load}
                    onclick={() => item.load && go(item.id)}
                  >
                    {item.label}
                    {#if !item.load}<span class="soon">Coming soon</span>{/if}
                  </button>
                </li>
              {/each}
            </ul>
          {/if}
        {:else if openGroups.has(group.id)}
          <ul class="panel">
            {#each group.items as item (item.id)}
              <li>
                <button
                  class="item"
                  class:active={router.current === item.id}
                  class:unavailable={!item.load}
                  disabled={!item.load}
                  onclick={() => item.load && go(item.id)}
                  aria-current={router.current === item.id ? "page" : undefined}
                >
                  <span class="label">{item.label}</span>
                  {#if !item.load}<span class="soon">Coming soon</span>{/if}
                </button>
              </li>
            {/each}
          </ul>
        {/if}
      </li>
    {/each}
  </ul>

  <button class="rail-toggle" onclick={toggleCollapsed} aria-label={collapsed ? "Expand navigation" : "Collapse navigation"}>
    <Icon name="menu" size={16} />
    {#if !collapsed}<span class="label">Collapse</span>{/if}
  </button>
</nav>

<style>
  .scrim {
    display: none;
  }
  .sidebar {
    display: flex;
    flex-direction: column;
    gap: 0.2rem;
    width: 15.5rem;
    flex-shrink: 0;
    padding: 0.75rem 0.5rem;
    border-right: 1px solid var(--border);
    background: var(--card-bg);
    overflow-y: auto;
  }
  .sidebar.collapsed {
    width: 3.75rem;
  }
  .sidebar.collapsed .label,
  .sidebar.collapsed .chevron {
    display: none;
  }

  .item {
    display: flex;
    align-items: center;
    gap: 0.65rem;
    width: 100%;
    background: transparent;
    color: var(--fg);
    border: none;
    border-radius: 6px;
    padding: 0.5rem 0.6rem;
    text-align: left;
    font-size: 0.88rem;
    cursor: pointer;
  }
  .item:hover:not(:disabled) {
    background: var(--nav-hover-bg);
  }
  .item.active {
    background: var(--accent);
    color: var(--accent-fg);
  }
  .item.unavailable,
  .item:disabled {
    opacity: 0.45;
    cursor: default;
  }
  .item .soon {
    margin-left: auto;
    font-size: 0.65rem;
    opacity: 0.85;
    white-space: nowrap;
  }
  .top-level {
    font-weight: 600;
    margin-bottom: 0.4rem;
  }

  .groups {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 0.15rem;
    flex: 1;
  }
  .group {
    position: relative;
  }
  .group-toggle {
    display: flex;
    align-items: center;
    gap: 0.65rem;
    width: 100%;
    background: transparent;
    color: var(--fg);
    border: none;
    border-radius: 6px;
    padding: 0.5rem 0.6rem;
    font-size: 0.78rem;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    opacity: 0.8;
    cursor: pointer;
  }
  .group-toggle:hover {
    background: var(--nav-hover-bg);
  }
  .group-toggle.active {
    opacity: 1;
    color: var(--accent);
  }
  .chevron {
    margin-left: auto;
    display: inline-flex;
    transition: transform 0.15s ease;
  }
  .chevron.open {
    transform: rotate(180deg);
  }
  .panel {
    list-style: none;
    margin: 0 0 0.3rem;
    padding: 0 0 0 0.4rem;
    display: flex;
    flex-direction: column;
    gap: 0.05rem;
  }

  .flyout {
    position: absolute;
    left: calc(100% + 0.4rem);
    top: 0;
    z-index: 30;
    min-width: 13rem;
    background: var(--card-bg);
    border: 1px solid var(--border);
    border-radius: 8px;
    box-shadow: 0 8px 24px rgba(0, 0, 0, 0.18);
    padding: 0.4rem;
    list-style: none;
  }
  .flyout-label {
    font-size: 0.72rem;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    opacity: 0.7;
    padding: 0.3rem 0.6rem;
  }

  .rail-toggle {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    background: transparent;
    color: var(--fg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.45rem 0.6rem;
    font-size: 0.8rem;
    cursor: pointer;
    margin-top: 0.5rem;
  }

  @media (max-width: 1120px) {
    .sidebar:not(.mobile-open) {
      width: 3.75rem;
    }
    .sidebar:not(.mobile-open) .label,
    .sidebar:not(.mobile-open) .chevron {
      display: none;
    }
  }

  @media (max-width: 760px) {
    .sidebar {
      position: fixed;
      inset: 0 auto 0 0;
      z-index: 40;
      width: 16rem;
      transform: translateX(-100%);
      transition: transform 0.18s ease;
      box-shadow: 0 0 0 100vmax rgba(0, 0, 0, 0);
    }
    .sidebar.mobile-open {
      transform: translateX(0);
    }
    .sidebar.mobile-open .label,
    .sidebar.mobile-open .chevron {
      display: inline;
    }
    .rail-toggle {
      display: none;
    }
    .scrim {
      display: block;
      position: fixed;
      inset: 0;
      z-index: 35;
      background: rgba(0, 0, 0, 0.4);
      border: none;
      padding: 0;
    }
  }
</style>
