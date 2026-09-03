<script lang="ts">
  import { onMount } from "svelte";
  import { api, setCsrfToken, ApiError } from "./api";
  import { loadTheme, applyTheme, type Theme } from "./theme";
  import { loadColors, applyColors } from "./colors";
  import { loadProfile, saveProfile, type NavProfile } from "./profile";
  import { router } from "./router.svelte";
  import { defaultRouteId, findItem, groupOf, isAdvancedRoute } from "./nav";
  import Nav from "./lib/Nav.svelte";
  import RouteLoader from "./lib/RouteLoader.svelte";
  import Icon from "./lib/Icon.svelte";
  import ToastHost from "./lib/ui/ToastHost.svelte";

  type Phase = "loading" | "bootstrap" | "setup" | "login" | "app";
  let phase = $state<Phase>("loading");
  let phaseError = $state("");

  let bootstrapToken = $state("");
  let bootstrapBusy = $state(false);

  let username = $state("");
  let password = $state("");
  let confirmPassword = $state("");
  let createLocalDNS = $state(true);
  let serverHostname = $state("alderpointdns");
  let authedUsername = $state("");
  let busy = $state(false);

  let theme = $state<Theme>("light");
  let mobileNavOpen = $state(false);
  let profile = $state<NavProfile>(loadProfile());

  function setProfile(p: NavProfile) {
    profile = p;
    saveProfile(p);
  }

  onMount(async () => {
    theme = loadTheme();
    applyTheme(theme);
    applyColors(loadColors());

    // Immediate shell: the login/setup form below renders instantly while
    // this resolves in the background, rather than a blank page.
    try {
      const status = await api.setupStatus();
      if (status.setup_required) {
        phase = "bootstrap";
        return;
      }
      const sess = await api.session();
      if (sess.authenticated) {
        setCsrfToken(sess.csrf);
        authedUsername = sess.username;
        enterApp();
        return;
      }
    } catch {
      /* fall through to login */
    }
    phase = "login";
  });

  function enterApp() {
    phase = "app";
    // router.current was resolved at module load (before we knew whether
    // this visit would even reach the app) from whatever location.pathname
    // was at the time -- typically "/" right after login, which
    // routeIdFromPath() already defaults to defaultRouteId() in memory,
    // but the URL bar itself was never updated to match. Sync it now via
    // a history *replace* (not a new entry): landing at "/" or an
    // unknown/not-yet-built route sends the operator to the first
    // implemented page instead of a blank/coming-soon landing, and in
    // every case the address bar ends up agreeing with what's on screen
    // (bookmarking, reload, and back/forward all need this to be true).
    const item = findItem(router.current);
    const target = item?.load ? router.current : defaultRouteId();
    router.navigate(target, true);
  }

  const activeLabel = $derived(findItem(router.current)?.label ?? "");
  const activeGroupLabel = $derived(groupOf(router.current)?.label);
  // A direct link/bookmark to an Advanced-only page must still render
  // normally while Standard is selected -- see nav.ts's isAdvancedRoute
  // doc comment. This only adds a label; it never redirects or 404s.
  const currentIsAdvanced = $derived(isAdvancedRoute(router.current));

  function toggleTheme() {
    theme = theme === "light" ? "dark" : "light";
    applyTheme(theme);
  }

  async function doBootstrap(e: Event) {
    e.preventDefault();
    phaseError = "";
    bootstrapBusy = true;
    try {
      const resp = await api.setupBootstrap(bootstrapToken.trim());
      setCsrfToken(resp.csrf);
      bootstrapToken = "";
      phase = "setup";
    } catch (err) {
      phaseError = err instanceof ApiError ? err.message : String(err);
    } finally {
      bootstrapBusy = false;
    }
  }

  async function doSetup(e: Event) {
    e.preventDefault();
    phaseError = "";
    busy = true;
    try {
      await api.setup({
        username, password, confirm_password: confirmPassword,
        create_local_dns: createLocalDNS, server_hostname: serverHostname,
      });
      password = "";
      confirmPassword = "";
      phase = "login";
    } catch (err) {
      phaseError = err instanceof ApiError ? err.message : String(err);
      // The bootstrap-issued setup session expires after 15 minutes --
      // if it lapsed while this form was open, send the operator back
      // to re-enter a token rather than leaving them stuck resubmitting
      // a form that can never succeed again.
      if (err instanceof ApiError && err.code === "setup_session_required") {
        phase = "bootstrap";
      }
    } finally {
      busy = false;
    }
  }

  async function doLogin(e: Event) {
    e.preventDefault();
    phaseError = "";
    busy = true;
    try {
      const resp = await api.login(username, password);
      setCsrfToken(resp.csrf);
      authedUsername = username;
      password = "";
      enterApp();
    } catch (err) {
      phaseError = err instanceof ApiError ? err.message : String(err);
    } finally {
      busy = false;
    }
  }

  async function doLogout() {
    try {
      await api.logout();
    } finally {
      phase = "login";
      username = "";
    }
  }

</script>

<div class="shell" class:app-shell={phase === "app"}>
  <ToastHost />
  {#if phase !== "app"}
    <header>
      <h1>Alderpoint DNS</h1>
      <button class="theme-toggle" onclick={toggleTheme} aria-label="Toggle color theme">
        <Icon name={theme === "light" ? "moon" : "sun"} size={17} />
      </button>
    </header>
  {/if}

  {#if phase === "loading"}
    <main class="centered"><p>Loading…</p></main>
  {:else if phase === "bootstrap"}
    <main class="centered">
      <form onsubmit={doBootstrap} class="auth-form" aria-labelledby="bootstrap-heading">
        <h2 id="bootstrap-heading">First-run setup</h2>
        <p>
          This appliance has not been claimed yet. Enter the one-time setup code printed to this
          appliance's own startup log (e.g. <code>podman logs</code> or the systemd journal) to
          begin creating the first administrator account.
        </p>
        <label>Setup code <input required bind:value={bootstrapToken} autocomplete="off" spellcheck="false" /></label>
        <button type="submit" disabled={bootstrapBusy}>{bootstrapBusy ? "Checking…" : "Continue"}</button>
        {#if phaseError}<p class="error" role="alert">{phaseError}</p>{/if}
      </form>
    </main>
  {:else if phase === "setup"}
    <main class="centered">
      <form onsubmit={doSetup} class="auth-form" aria-labelledby="setup-heading">
        <h2 id="setup-heading">First-run setup</h2>
        <p>Create the first administrator account for this appliance.</p>
        <label>Username <input required bind:value={username} autocomplete="username" /></label>
        <label>Password (12+ characters) <input required minlength="12" type="password" bind:value={password} autocomplete="new-password" /></label>
        <label>Confirm password <input required type="password" bind:value={confirmPassword} autocomplete="new-password" /></label>
        <label class="checkbox"><input type="checkbox" bind:checked={createLocalDNS} /> Create a Local DNS record for this appliance</label>
        {#if createLocalDNS}
          <label>Hostname <input bind:value={serverHostname} /></label>
        {/if}
        <button type="submit" disabled={busy}>{busy ? "Creating…" : "Create administrator account"}</button>
        {#if phaseError}<p class="error" role="alert">{phaseError}</p>{/if}
      </form>
    </main>
  {:else if phase === "login"}
    <main class="centered">
      <form onsubmit={doLogin} class="auth-form" aria-labelledby="login-heading">
        <h2 id="login-heading">Log in</h2>
        <label>Username <input required bind:value={username} autocomplete="username" /></label>
        <label>Password <input required type="password" bind:value={password} autocomplete="current-password" /></label>
        <button type="submit" disabled={busy}>{busy ? "Logging in…" : "Log in"}</button>
        {#if phaseError}<p class="error" role="alert">{phaseError}</p>{/if}
      </form>
    </main>
  {:else}
    <div class="app-layout">
      <Nav
        bind:mobileOpen={mobileNavOpen}
        {profile}
        onProfileChange={setProfile}
        {theme}
        onToggleTheme={toggleTheme}
        username={authedUsername}
        onLogout={doLogout}
      />
      <div class="content-col">
        <header class="topbar">
          <button
            class="menu-btn"
            onclick={() => (mobileNavOpen = !mobileNavOpen)}
            aria-label="Toggle navigation menu"
            aria-expanded={mobileNavOpen}
          >
            <Icon name="menu" />
          </button>
          <span class="topbar-brand" aria-hidden="true">Alderpoint DNS</span>
          <div class="crumb">
            {#if activeGroupLabel}<span class="crumb-group">{activeGroupLabel}</span>{/if}
            <span class="crumb-page">{activeLabel}</span>
            {#if currentIsAdvanced}<span class="advanced-tag" title="This page lives under Advanced navigation.">Advanced page</span>{/if}
          </div>
        </header>
        <main>
          {#if currentIsAdvanced && profile === "standard"}
            <p class="advanced-banner" role="status">
              This is an Advanced page. It isn't shown in Standard navigation, but it works the same
              either way -- nothing about switching profiles changes what it does.
            </p>
          {/if}
          {#key router.current}
            <RouteLoader routeId={router.current} />
          {/key}
        </main>
      </div>
    </div>
  {/if}
</div>

<style>
  /* Alderpoint DNS product theme: a navy/teal identity carried through
     both a real dark mode and a real light mode. V1.1.1 only ever
     shipped the dark navy/teal look, so the dark block below still
     starts from that palette (refined for contrast/less flat-gray
     repetition); the light block is new -- previously :root[data-theme
     ="light"] didn't exist at all, so toggling themes only flipped the
     `data-theme` attribute with no CSS reacting to it. --card-bg/--nav-
     hover-bg/--accent-fg/--badge-*-bg/--attention-bg/--field-bg are
     this app's own token names, defined for both themes so every view
     that reads them renders correctly either way. See frontend/src/lib
     /ui/index.ts's shared components for the panel/page-header/segment
     -control/status-badge classes that consume these same tokens. */
  :global(:root),
  :global(:root[data-theme="dark"]) {
    color-scheme: dark;
    --bg: #08121f; --bg-soft: #0c1a2b; --fg: #eef4fa;
    --border: #24384d; --border-strong: #37536f;
    --card-bg: #112238; --panel-elevated: #17293f;
    --muted: #a3b7c9; --faint: #74899d;
    --accent: #2dd9b9; --accent-strong: #6ee7f2; --accent-fg: #05121c;
    --success: #3ddb9d; --warning: #fbbf24; --danger: #f87171;
    --attention-bg: #3f1d1d;
    --badge-ok-bg: #123b2c; --badge-ok-fg: #7be8c4;
    --badge-warn-bg: #4a3510; --badge-warn-fg: #fbbf24;
    --badge-danger-bg: #4a1620; --badge-danger-fg: #f87171;
    --nav-hover-bg: rgba(255, 255, 255, 0.08);
    --field-bg: #0b1626;
    --btn-bg: #0e7d73; --btn-bg-hover: #14988c;
    --radius: 12px; --radius-sm: 8px; --shadow: 0 18px 44px rgba(0, 0, 0, 0.28);
  }
  :global(:root[data-theme="light"]) {
    color-scheme: light;
    --bg: #f3f7fa; --bg-soft: #e8eef3; --fg: #10202f;
    --border: #d7e1e9; --border-strong: #b7c6d1;
    --card-bg: #ffffff; --panel-elevated: #f6f9fb;
    --muted: #4a5f70; --faint: #7891a0;
    --accent: #0d9488; --accent-strong: #0a7d8f; --accent-fg: #ffffff;
    --success: #15803d; --warning: #b45309; --danger: #b91c1c;
    --attention-bg: #fde9e9;
    --badge-ok-bg: #dcfce7; --badge-ok-fg: #166534;
    --badge-warn-bg: #fef3c7; --badge-warn-fg: #92400e;
    --badge-danger-bg: #fee2e2; --badge-danger-fg: #991b1b;
    --nav-hover-bg: rgba(16, 32, 47, 0.06);
    --field-bg: #ffffff;
    --btn-bg: #0d9488; --btn-bg-hover: #0b7d8f;
    --radius: 12px; --radius-sm: 8px; --shadow: 0 10px 26px rgba(16, 32, 47, 0.1);
  }
  :global(body) {
    margin: 0; background: var(--bg); color: var(--fg);
    font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  }
  :global(input, select) { padding: 0.5rem 0.6rem; border-radius: var(--radius-sm); border: 1px solid var(--border-strong); background: var(--field-bg); color: inherit; }
  :global(button) {
    padding: 9px 12px; min-height: 40px; border-radius: var(--radius-sm); border: 1px solid rgba(45, 217, 185, 0.3);
    background: var(--btn-bg); color: var(--accent-fg); font-weight: 650; cursor: pointer;
  }
  :global(button:hover) { background: var(--btn-bg-hover); }
  :global(button.secondary) { background: var(--panel-elevated); border-color: var(--border-strong); color: var(--fg); }
  :global(button.danger) { background: #9f1239; border-color: rgba(251, 113, 133, 0.36); color: #fff; }
  :global(button:disabled) { opacity: 0.6; cursor: progress; }
  :global(.error) { color: #dc2626; }
  :global(.add-form) { display: flex; flex-wrap: wrap; gap: 0.75rem; align-items: end; margin: 1rem 0; }
  :global(.add-form label) { display: flex; flex-direction: column; font-size: 0.85rem; gap: 0.25rem; }
  :global(.hidden) { display: none; }

  .shell:not(.app-shell) { max-width: 72rem; margin: 0 auto; padding: 0 1rem 2rem; }
  .shell.app-shell { height: 100vh; overflow: hidden; }
  header { display: flex; justify-content: space-between; align-items: center; padding: 1rem 0; }
  h1 { font-size: 1.2rem; display: flex; align-items: center; gap: 0.6rem; }
  /* color: var(--fg) overrides the global button rule's accent-fg default
     (meant for text on a filled accent-colored button) -- this button is
     transparent, and accent-fg is near-black in dark mode, rendering the
     sun/moon icon all but invisible against the dark navy page background
     (a real, screenshot-caught regression from swapping emoji for the SVG
     icon: emoji carried their own color, this button's default text color
     never did). */
  .theme-toggle { background: transparent; color: var(--fg); display: inline-flex; align-items: center; justify-content: center; }
  .centered { display: flex; justify-content: center; padding-top: 3rem; }
  .auth-form { display: flex; flex-direction: column; gap: 0.75rem; width: 22rem; max-width: 90vw; background: var(--card-bg); padding: 1.5rem; border-radius: 8px; border: 1px solid var(--border); }
  .auth-form label { display: flex; flex-direction: column; gap: 0.25rem; font-size: 0.85rem; }
  .checkbox { flex-direction: row !important; align-items: center; gap: 0.5rem !important; }

  .app-layout { display: flex; height: 100%; }
  .content-col { flex: 1; min-width: 0; display: flex; flex-direction: column; height: 100%; }
  /* The app shell's own top bar is the mobile/tablet replacement for the
     sidebar (hamburger + brand + current page) -- theme/account/logout
     now live in Nav.svelte's own bottom section instead, both desktop and
     drawer, so they aren't duplicated up here. On desktop this bar
     collapses to just the current-page crumb: a slim orientation aid, not
     a second controls row. */
  .topbar {
    display: flex; align-items: center; gap: 0.75rem;
    padding: 0.6rem 1rem; border-bottom: 1px solid var(--border);
    background: var(--card-bg); flex-shrink: 0;
  }
  .menu-btn { display: none; background: transparent; color: var(--fg); padding: 0.35rem; }
  .topbar-brand { display: none; font-weight: 700; font-size: 0.95rem; }
  .crumb { display: flex; align-items: baseline; gap: 0.5rem; font-size: 0.95rem; min-width: 0; flex-wrap: wrap; }
  .crumb-group { font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.04em; opacity: 0.65; }
  .crumb-page { font-weight: 600; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .advanced-tag {
    font-size: 0.68rem; font-weight: 650; text-transform: uppercase; letter-spacing: 0.03em;
    padding: 0.12rem 0.5rem; border-radius: 999px; background: var(--badge-warn-bg); color: var(--badge-warn-fg);
  }
  .advanced-banner {
    margin: 0 0 1rem; padding: 0.6rem 0.85rem; border-radius: 8px;
    background: var(--panel-elevated); border: 1px solid var(--border); font-size: 0.85rem; color: var(--muted);
  }
  .app-layout main { flex: 1; overflow-y: auto; padding: 1.25rem; }

  @media (max-width: 760px) {
    .menu-btn { display: inline-flex; }
    .topbar-brand { display: inline; }
  }
</style>
