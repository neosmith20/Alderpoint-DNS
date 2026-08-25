<script lang="ts">
  import { onMount } from "svelte";
  import { api, setCsrfToken, ApiError } from "./api";
  import { loadTheme, applyTheme, type Theme } from "./theme";
  import BlocklistsView from "./lib/BlocklistsView.svelte";
  import LocalDnsView from "./lib/LocalDnsView.svelte";

  type Phase = "loading" | "setup" | "login" | "app";
  let phase = $state<Phase>("loading");
  let phaseError = $state("");

  let username = $state("");
  let password = $state("");
  let confirmPassword = $state("");
  let createLocalDNS = $state(true);
  let serverHostname = $state("alderpointdns");
  let authedUsername = $state("");
  let busy = $state(false);

  let theme = $state<Theme>("light");
  let tab = $state<"blocklists" | "local-dns">("blocklists");

  let blocklistsView = $state<BlocklistsView>();
  let localDnsView = $state<LocalDnsView>();

  onMount(async () => {
    theme = loadTheme();
    applyTheme(theme);

    // Immediate shell: the login/setup form below renders instantly while
    // this resolves in the background, rather than a blank page.
    try {
      const status = await api.setupStatus();
      if (status.setup_required) {
        phase = "setup";
        return;
      }
      const sess = await api.session();
      if (sess.authenticated) {
        setCsrfToken(sess.csrf);
        authedUsername = sess.username;
        phase = "app";
        return;
      }
    } catch {
      /* fall through to login */
    }
    phase = "login";
  });

  function toggleTheme() {
    theme = theme === "light" ? "dark" : "light";
    applyTheme(theme);
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
      phase = "app";
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

  $effect(() => {
    if (phase === "app") {
      if (tab === "blocklists") blocklistsView?.refresh();
      if (tab === "local-dns") localDnsView?.refresh();
    }
  });
</script>

<div class="shell">
  <header>
    <h1>Alderpoint DNS <span class="badge-preview">Go Migration Preview</span></h1>
    <button class="theme-toggle" onclick={toggleTheme} aria-label="Toggle color theme">
      {theme === "light" ? "🌙" : "☀️"}
    </button>
  </header>

  {#if phase === "loading"}
    <main class="centered"><p>Loading…</p></main>
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
    <nav aria-label="Main">
      <button class:active={tab === "blocklists"} onclick={() => (tab = "blocklists")}>Blocklists</button>
      <button class:active={tab === "local-dns"} onclick={() => (tab = "local-dns")}>Local DNS</button>
      <span class="spacer"></span>
      <span class="whoami">{authedUsername}</span>
      <button onclick={doLogout}>Log out</button>
    </nav>
    <main>
      <div class:hidden={tab !== "blocklists"}>
        <BlocklistsView bind:this={blocklistsView} />
      </div>
      <div class:hidden={tab !== "local-dns"}>
        <LocalDnsView bind:this={localDnsView} />
      </div>
    </main>
  {/if}
</div>

<style>
  :global(:root) {
    --bg: #f8fafc; --fg: #0f172a; --border: #e2e8f0; --card-bg: #ffffff;
    --accent: #2563eb; --accent-fg: #ffffff;
    --attention-bg: #fef2f2;
    --badge-ok-bg: #dcfce7; --badge-ok-fg: #166534;
    --badge-warn-bg: #fef9c3; --badge-warn-fg: #854d0e;
    --badge-danger-bg: #fecaca; --badge-danger-fg: #991b1b;
  }
  :global(:root[data-theme="dark"]) {
    --bg: #0f172a; --fg: #e2e8f0; --border: #334155; --card-bg: #1e293b;
    --accent: #3b82f6; --accent-fg: #ffffff;
    --attention-bg: #3f1d1d;
    --badge-ok-bg: #14532d; --badge-ok-fg: #bbf7d0;
    --badge-warn-bg: #713f12; --badge-warn-fg: #fef08a;
    --badge-danger-bg: #7f1d1d; --badge-danger-fg: #fecaca;
  }
  :global(body) { margin: 0; background: var(--bg); color: var(--fg); font-family: system-ui, sans-serif; }
  :global(input, select) { padding: 0.4rem; border-radius: 4px; border: 1px solid var(--border); background: var(--card-bg); color: inherit; }
  :global(button) { padding: 0.45rem 0.9rem; border-radius: 4px; border: none; background: var(--accent); color: var(--accent-fg); cursor: pointer; }
  :global(button:disabled) { opacity: 0.6; cursor: progress; }
  :global(.error) { color: #dc2626; }
  :global(.add-form) { display: flex; flex-wrap: wrap; gap: 0.75rem; align-items: end; margin: 1rem 0; }
  :global(.add-form label) { display: flex; flex-direction: column; font-size: 0.85rem; gap: 0.25rem; }
  :global(.hidden) { display: none; }

  .shell { max-width: 72rem; margin: 0 auto; padding: 0 1rem 2rem; }
  header { display: flex; justify-content: space-between; align-items: center; padding: 1rem 0; }
  h1 { font-size: 1.2rem; display: flex; align-items: center; gap: 0.6rem; }
  .badge-preview { font-size: 0.7rem; font-weight: normal; background: var(--badge-warn-bg); color: var(--badge-warn-fg); padding: 0.15rem 0.5rem; border-radius: 999px; }
  .theme-toggle { background: transparent; font-size: 1.1rem; }
  .centered { display: flex; justify-content: center; padding-top: 3rem; }
  .auth-form { display: flex; flex-direction: column; gap: 0.75rem; width: 22rem; max-width: 90vw; background: var(--card-bg); padding: 1.5rem; border-radius: 8px; border: 1px solid var(--border); }
  .auth-form label { display: flex; flex-direction: column; gap: 0.25rem; font-size: 0.85rem; }
  .checkbox { flex-direction: row !important; align-items: center; gap: 0.5rem !important; }
  nav { display: flex; align-items: center; gap: 0.5rem; padding: 0.5rem 0; border-bottom: 1px solid var(--border); margin-bottom: 1rem; }
  nav button { background: transparent; color: var(--fg); }
  nav button.active { background: var(--accent); color: var(--accent-fg); }
  .spacer { flex: 1; }
  .whoami { font-size: 0.85rem; opacity: 0.8; }

  @media (max-width: 480px) {
    nav { flex-wrap: wrap; }
  }
</style>
