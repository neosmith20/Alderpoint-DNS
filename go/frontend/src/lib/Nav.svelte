<script lang="ts">
  import Icon from "./Icon.svelte";
  import { TOP_ITEMS, NAV_GROUPS, BOTTOM_ITEMS, groupOf, type NavGroup, type NavItem } from "../nav";
  import { router } from "../router.svelte";
  import type { NavProfile } from "../profile";
  import type { Theme } from "../theme";

  let {
    mobileOpen = $bindable(false),
    profile,
    onProfileChange,
    theme,
    onToggleTheme,
    username,
    onLogout,
  }: {
    mobileOpen?: boolean;
    profile: NavProfile;
    onProfileChange: (p: NavProfile) => void;
    theme: Theme;
    onToggleTheme: () => void;
    username: string;
    onLogout: () => void;
  } = $props();

  const COLLAPSED_KEY = "apdns-go-nav-collapsed";

  // Single-open accordion: at most one main section is open at a time,
  // desktop or mobile (the collapsed rail's flyout is already naturally
  // single-open via flyoutGroup below, so this only governs the expanded
  // sidebar/drawer). Not persisted -- the route itself is the source of
  // truth for which section should be open (see the $effect below), so
  // there is nothing meaningful to remember across a reload beyond that.
  let openGroupId = $state<string | null>(groupOf(router.current)?.id ?? null);
  let collapsed = $state(localStorage.getItem(COLLAPSED_KEY) === "1");
  let flyoutGroup = $state<string | null>(null);
  let navEl: HTMLElement | undefined;

  // Groups the current profile actually shows in nav -- an Advanced-only
  // group stays fully reachable by direct link/route even while hidden
  // here (see nav.ts's isAdvancedRoute doc comment and App.svelte's own
  // "Advanced page" label for a route that isn't in this filtered list).
  const visibleGroups = $derived(NAV_GROUPS.filter((g) => profile === "advanced" || !g.advanced));

  // Navigating directly to a child route (a sidebar click is one case,
  // but also a Dashboard card link, browser back/forward, or a deep
  // link) must open exactly that child's own parent section and no
  // other -- keeps the open section and the active route from ever
  // disagreeing, regardless of how the route changed.
  $effect(() => {
    const group = groupOf(router.current);
    if (group) openGroupId = group.id;
  });

  function toggleGroup(id: string) {
    if (collapsed) {
      flyoutGroup = flyoutGroup === id ? null : id;
      return;
    }
    // Opening a different section closes whichever was open; clicking
    // the already-open section's own toggle collapses it.
    openGroupId = openGroupId === id ? null : id;
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
  <div class="brand">
    <span class="brand-mark" aria-hidden="true">
      <svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linejoin="round">
        <path d="M12 2.5l8 3.2v6c0 5.1-3.3 8.8-8 9.8-4.7-1-8-4.7-8-9.8v-6l8-3.2z" />
        <path d="M8.3 12.2l2.6 2.6 4.8-5.1" />
      </svg>
    </span>
    <span class="brand-name">Alderpoint DNS</span>
  </div>

  <div class="profile-switch" role="group" aria-label="Navigation profile">
    <button
      type="button"
      class:active={profile === "standard"}
      title="Standard navigation"
      onclick={() => onProfileChange("standard")}
    >
      <span class="profile-full">Standard</span>
      <span class="profile-short">Std</span>
    </button>
    <button
      type="button"
      class:active={profile === "advanced"}
      title="Advanced navigation"
      onclick={() => onProfileChange("advanced")}
    >
      <span class="profile-full">Advanced</span>
      <span class="profile-short">Adv</span>
    </button>
  </div>

  <ul class="top-items">
    {#each TOP_ITEMS as item (item.id)}
      <li>
        <button
          class="item top-level"
          class:active={router.current === item.id}
          title={item.label}
          onclick={() => item.load && go(item.id)}
          disabled={!item.load}
          aria-current={router.current === item.id ? "page" : undefined}
        >
          <Icon name={item.icon} />
          <span class="label">{item.label}</span>
        </button>
      </li>
    {/each}
  </ul>

  <ul class="groups">
    {#each visibleGroups as group (group.id)}
      <li class="group" class:flyout-open={flyoutGroup === group.id}>
        <button
          class="group-toggle"
          class:active={groupHasActive(group)}
          title={group.label}
          aria-expanded={collapsed ? flyoutGroup === group.id : openGroupId === group.id}
          onclick={() => toggleGroup(group.id)}
        >
          <Icon name={group.icon} />
          <span class="label">{group.label}</span>
          {#if !collapsed}
            <span class="chevron" class:open={openGroupId === group.id}>
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
                    {#if !item.load}<span class="soon">Not built</span>{/if}
                  </button>
                </li>
              {/each}
            </ul>
          {/if}
        {:else if openGroupId === group.id}
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
                  {#if !item.load}<span class="soon">Not built</span>{/if}
                </button>
              </li>
            {/each}
          </ul>
        {/if}
      </li>
    {/each}
  </ul>

  <div class="spacer"></div>

  <div class="bottom-section">
    {#each BOTTOM_ITEMS as item (item.id)}
      <button
        class="item bottom-item"
        class:active={router.current === item.id}
        class:unavailable={!item.load}
        disabled={!item.load}
        title={item.label}
        onclick={() => item.load && go(item.id)}
      >
        <Icon name={item.icon} />
        <span class="label">{item.label}{#if !item.load} <span class="soon">Not built</span>{/if}</span>
      </button>
    {/each}

    <button class="item bottom-item" title={theme === "light" ? "Switch to dark theme" : "Switch to light theme"} onclick={onToggleTheme}>
      <Icon name={theme === "light" ? "moon" : "sun"} size={17} />
      <span class="label">{theme === "light" ? "Dark theme" : "Light theme"}</span>
    </button>

    <div class="account-row">
      <span class="whoami" title={username}>{username}</span>
      <button class="logout-btn" onclick={onLogout} title="Log out" aria-label="Log out">
        <Icon name="logout" size={16} />
      </button>
    </div>

    <button class="rail-toggle" onclick={toggleCollapsed} aria-label={collapsed ? "Expand navigation" : "Collapse navigation"} title={collapsed ? "Expand navigation" : "Collapse navigation"}>
      <Icon name="menu" size={16} />
      {#if !collapsed}<span class="label">Collapse</span>{/if}
    </button>
  </div>
</nav>

<style>
  .scrim {
    display: none;
  }
  .sidebar {
    display: flex;
    flex-direction: column;
    gap: 0.2rem;
    width: 15rem;
    flex-shrink: 0;
    padding: 0.75rem 0.5rem;
    border-right: 1px solid var(--border);
    background: var(--card-bg);
    overflow-y: auto;
  }
  .sidebar.collapsed {
    width: 4.25rem;
  }
  .sidebar.collapsed .label,
  .sidebar.collapsed .chevron,
  .sidebar.collapsed .brand-name,
  .sidebar.collapsed .profile-full,
  .sidebar.collapsed .whoami {
    display: none;
  }
  .sidebar:not(.collapsed) .profile-short {
    display: none;
  }
  /* Collapsed rail: only the icon remains once its label is hidden --
     center it in the narrow rail instead of leaving it flush against
     the button's own left padding, which read as visibly off-center. */
  .sidebar.collapsed .item,
  .sidebar.collapsed .group-toggle,
  .sidebar.collapsed .brand,
  .sidebar.collapsed .account-row {
    justify-content: center;
    padding-left: 0;
    padding-right: 0;
  }
  .sidebar.collapsed .account-row {
    flex-direction: column;
    gap: 0.3rem;
  }

  .brand {
    display: flex;
    align-items: center;
    gap: 0.55rem;
    padding: 0.35rem 0.6rem 0.6rem;
    color: var(--fg);
  }
  .brand-mark {
    color: var(--accent);
    flex-shrink: 0;
    display: inline-flex;
  }
  .brand-name {
    font-weight: 700;
    font-size: 0.95rem;
    letter-spacing: 0.01em;
  }

  .profile-switch {
    display: flex;
    gap: 0.2rem;
    padding: 0.15rem;
    margin: 0 0.1rem 0.6rem;
    background: var(--bg-soft);
    border: 1px solid var(--border);
    border-radius: 999px;
  }
  .profile-switch button {
    flex: 1;
    background: transparent;
    color: var(--muted);
    border: none;
    padding: 0.32rem 0.4rem;
    min-height: auto;
    border-radius: 999px;
    font-size: 0.76rem;
    font-weight: 650;
    cursor: pointer;
  }
  .profile-switch button.active {
    background: var(--accent);
    color: var(--accent-fg);
  }

  .top-items {
    list-style: none;
    margin: 0 0 0.4rem;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 0.1rem;
  }

  .item {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 0.65rem;
    width: 100%;
    background: transparent;
    color: var(--fg);
    border: none;
    border-radius: 6px;
    padding: 0.5rem 0.6rem;
    text-align: center;
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
    margin-left: 0.4rem;
    font-size: 0.65rem;
    opacity: 0.85;
    white-space: nowrap;
  }
  .top-level {
    font-weight: 600;
  }

  .groups {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 0.15rem;
    flex: 0 0 auto;
  }
  .spacer {
    flex: 1;
  }
  .bottom-section {
    display: flex;
    flex-direction: column;
    gap: 0.15rem;
    padding-top: 0.5rem;
    margin-top: 0.4rem;
    border-top: 1px solid var(--border);
  }
  .bottom-item {
    justify-content: flex-start;
  }
  .account-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 0.4rem;
    padding: 0.4rem 0.6rem;
  }
  .whoami {
    font-size: 0.82rem;
    opacity: 0.8;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .logout-btn {
    background: transparent;
    color: var(--fg);
    padding: 0.35rem;
    min-height: auto;
    border: none;
    border-radius: 6px;
    flex-shrink: 0;
  }
  .logout-btn:hover {
    background: var(--nav-hover-bg);
  }

  .group {
    position: relative;
  }
  .group-toggle {
    position: relative;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 0.65rem;
    width: 100%;
    background: transparent;
    color: var(--fg);
    border: none;
    border-radius: 6px;
    /* Reserve room on the right for the absolutely-positioned chevron
       (below) so the icon+label pair centers in the remaining space
       rather than under it. */
    padding: 0.5rem 1.8rem 0.5rem 0.6rem;
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
    position: absolute;
    right: 0.6rem;
    top: 50%;
    transform: translateY(-50%);
    display: inline-flex;
    transition: transform 0.15s ease;
  }
  .chevron.open {
    transform: translateY(-50%) rotate(180deg);
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
    margin-top: 0.4rem;
  }

  @media (max-width: 1120px) {
    .sidebar:not(.mobile-open) {
      width: 4.25rem;
    }
    .sidebar:not(.mobile-open) .label,
    .sidebar:not(.mobile-open) .chevron,
    .sidebar:not(.mobile-open) .brand-name,
    .sidebar:not(.mobile-open) .profile-full,
    .sidebar:not(.mobile-open) .whoami {
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
    .sidebar.mobile-open .chevron,
    .sidebar.mobile-open .brand-name,
    .sidebar.mobile-open .profile-full,
    .sidebar.mobile-open .whoami {
      display: inline;
    }
    .sidebar.mobile-open .brand-name {
      display: block;
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
