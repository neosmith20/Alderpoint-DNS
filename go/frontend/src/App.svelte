<script lang="ts">
  import { onMount } from "svelte";
  import { api, setCsrfToken, ApiError } from "./api";
  import { loadTheme, applyTheme, type Theme } from "./theme";
  import { router } from "./router.svelte";
  import { defaultRouteId, findItem, groupOf } from "./nav";
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

  onMount(async () => {
    theme = loadTheme();
    applyTheme(theme);

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
        {theme === "light" ? "🌙" : "☀️"}
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
      <Nav bind:mobileOpen={mobileNavOpen} />
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
          <div class="crumb">
            {#if activeGroupLabel}<span class="crumb-group">{activeGroupLabel}</span>{/if}
            <span class="crumb-page">{activeLabel}</span>
          </div>
          <span class="spacer"></span>
          <button class="theme-toggle" onclick={toggleTheme} aria-label="Toggle color theme">
            {theme === "light" ? "🌙" : "☀️"}
          </button>
          <span class="whoami">{authedUsername}</span>
          <button class="logout-btn" onclick={doLogout} aria-label="Log out">
            <Icon name="logout" size={16} />
          </button>
        </header>
        <main>
          {#key router.current}
            <RouteLoader routeId={router.current} />
          {/key}
        </main>
      </div>
    </div>
  {/if}
</div>

<style>
  /* Alderpoint's real navy/teal theme, ported from the V1.1.1 reference
     (web/static/app.css's :root token block, read directly) rather than
     invented -- V1.1.1 only ever shipped this one dark, navy/teal look
     (no separate light theme), so both the light-mode and dark-mode
     blocks below resolve to the same real palette; --card-bg/--nav-
     hover-bg/--accent-fg/--badge-*-bg/--attention-bg are this app's own
     pre-existing token names, mapped onto the closest real V1.1.1
     color rather than dropped, so every view that already reads them
     keeps working unchanged. See frontend/src/lib/ui/index.ts's shared
     components for the panel/page-header/segment-control/status-badge
     classes that consume these same tokens. */
  :global(:root),
  :global(:root[data-theme="dark"]) {
    color-scheme: dark;
    --bg: #07111f; --bg-soft: #0b1828; --fg: #ecf4fb;
    --border: #26384e; --border-strong: #36516d;
    --card-bg: #101f32; --panel-elevated: #15283e;
    --muted: #9cafc1; --faint: #6d8295;
    --accent: #20d6b5; --accent-strong: #67e8f9; --accent-fg: #07111f;
    --success: #36d399; --warning: #fbbf24; --danger: #f87171;
    --attention-bg: #3f1d1d;
    --badge-ok-bg: #123b2c; --badge-ok-fg: #7be8c4;
    --badge-warn-bg: #4a3510; --badge-warn-fg: #fbbf24;
    --badge-danger-bg: #4a1620; --badge-danger-fg: #f87171;
    --nav-hover-bg: rgba(255, 255, 255, 0.075);
    --radius: 12px; --radius-sm: 8px; --shadow: 0 18px 44px rgba(0, 0, 0, 0.22);
  }
  :global(body) {
    margin: 0; background: var(--bg); color: var(--fg);
    font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  }
  :global(input, select) { padding: 0.5rem 0.6rem; border-radius: var(--radius-sm); border: 1px solid var(--border-strong); background: #0a1423; color: inherit; }
  :global(button) {
    padding: 9px 12px; min-height: 40px; border-radius: var(--radius-sm); border: 1px solid rgba(32, 214, 181, 0.28);
    background: #0e6f68; color: var(--fg); font-weight: 650; cursor: pointer;
  }
  :global(button:hover) { background: #12887f; }
  :global(button.secondary) { background: #17283c; border-color: var(--border-strong); color: var(--fg); }
  :global(button.danger) { background: #9f1239; border-color: rgba(251, 113, 133, 0.36); }
  :global(button:disabled) { opacity: 0.6; cursor: progress; }
  :global(.error) { color: #dc2626; }
  :global(.add-form) { display: flex; flex-wrap: wrap; gap: 0.75rem; align-items: end; margin: 1rem 0; }
  :global(.add-form label) { display: flex; flex-direction: column; font-size: 0.85rem; gap: 0.25rem; }
  :global(.hidden) { display: none; }

  .shell:not(.app-shell) { max-width: 72rem; margin: 0 auto; padding: 0 1rem 2rem; }
  .shell.app-shell { height: 100vh; overflow: hidden; }
  header { display: flex; justify-content: space-between; align-items: center; padding: 1rem 0; }
  h1 { font-size: 1.2rem; display: flex; align-items: center; gap: 0.6rem; }
  .theme-toggle { background: transparent; font-size: 1.1rem; }
  .centered { display: flex; justify-content: center; padding-top: 3rem; }
  .auth-form { display: flex; flex-direction: column; gap: 0.75rem; width: 22rem; max-width: 90vw; background: var(--card-bg); padding: 1.5rem; border-radius: 8px; border: 1px solid var(--border); }
  .auth-form label { display: flex; flex-direction: column; gap: 0.25rem; font-size: 0.85rem; }
  .checkbox { flex-direction: row !important; align-items: center; gap: 0.5rem !important; }
  .spacer { flex: 1; }
  .whoami { font-size: 0.85rem; opacity: 0.8; }

  .app-layout { display: flex; height: 100%; }
  .content-col { flex: 1; min-width: 0; display: flex; flex-direction: column; height: 100%; }
  .topbar {
    display: flex; align-items: center; gap: 0.75rem;
    padding: 0.6rem 1rem; border-bottom: 1px solid var(--border);
    background: var(--card-bg); flex-shrink: 0;
  }
  .menu-btn { display: none; background: transparent; color: var(--fg); padding: 0.35rem; }
  .crumb { display: flex; align-items: baseline; gap: 0.45rem; font-size: 0.95rem; min-width: 0; }
  .crumb-group { font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.04em; opacity: 0.65; }
  .crumb-page { font-weight: 600; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .logout-btn { background: transparent; color: var(--fg); padding: 0.4rem; border-radius: 6px; }
  .logout-btn:hover { background: var(--nav-hover-bg); }
  .app-layout main { flex: 1; overflow-y: auto; padding: 1.25rem; }

  @media (max-width: 760px) {
    .menu-btn { display: inline-flex; }
  }
</style>
