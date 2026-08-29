// Real-Chromium smoke coverage for the Go/Svelte shell + whatever pages
// are wired in nav.ts. Run against a fresh instance (setup_required=true)
// -- see go/tests/browser/README.md. Not a mock: drives an actual
// headless Chromium via CDP (puppeteer-core, pointed at the system
// /usr/bin/chromium -- no bundled download).
//
// Before running: seed 3 real rows into the fixture's -analytics-db via
// `sh go/tests/fixtures/seed_query_events.sh <path-to-analytics.db>` --
// this replaces the old make_query_log_fixture.py/-query-log-dir setup
// (internal/rawquerylog's Python-Parquet compatibility boundary is gone
// as of the 2026-08-28 cutover; -query-log-dir is not even a flag on
// cmd/alderpointdns-go any more -- RawQueryLog and Analytics are the
// same internal/dnsanalytics.Reader over the same -analytics-db now).
//
// A real fresh instance's first screen is now bootstrap-token-gated
// (internal/bootstrap -- cmd/alderpointdns-go's own -bootstrap-token-path
// always has a real default, so this step cannot be skipped on any
// genuinely fresh instance), a step this script did not originally
// handle -- see setup_bootstrap_smoke.mjs for the dedicated coverage of
// that gate itself. Pass the token file path as a 4th argument so this
// suite can still drive setup end-to-end from a true fresh instance;
// omit it only when running against an instance that has ALREADY had
// setup completed (this script then goes straight to the login screen,
// same as before this fix).
//
// Usage: node chromium_smoke.mjs <base-url> <username> <password> [bootstrap-token-path]
import fs from "node:fs";
import puppeteer from "puppeteer-core";

const [, , baseUrl, username, password, bootstrapTokenPath] = process.argv;
if (!baseUrl || !username || !password) {
  console.error("usage: node chromium_smoke.mjs <base-url> <username> <password> [bootstrap-token-path]");
  process.exit(2);
}

const results = [];
function check(name, cond, detail) {
  results.push({ name, pass: !!cond, detail });
  console.log(`[${cond ? "PASS" : "FAIL"}] ${name}${!cond && detail ? " -- " + detail : ""}`);
}

const consoleErrors = [];
const pageErrors = [];

// Single-open sidebar accordion: an item is only in the DOM while its
// own section is the one open. Tries the currently-open section first
// (the common case -- most nav sequences below stay within one section
// for several steps); if the target isn't there, cycles through each
// section's own toggle (each click closes whichever was open, per the
// accordion) until it appears.
async function clickNavItem(page, predicate) {
  const tryFind = async () => {
    for (const btn of await page.$$(".sidebar .item")) {
      const text = await btn.evaluate((el) => el.textContent?.trim());
      if (predicate(text)) {
        await btn.click();
        return true;
      }
    }
    return false;
  };
  if (await tryFind()) return true;
  for (const toggle of await page.$$(".sidebar .group-toggle")) {
    await toggle.click();
    await new Promise((r) => setTimeout(r, 40));
    if (await tryFind()) return true;
  }
  return false;
}

async function main() {
  const browser = await puppeteer.launch({
    executablePath: process.env.CHROMIUM_PATH || "/usr/bin/chromium",
    headless: true,
    args: ["--no-sandbox", "--disable-dev-shm-usage", "--ignore-certificate-errors"],
  });

  // Wires the console/pageerror listeners a fresh page needs -- factored
  // out so the viewport sweep (below) can periodically recycle the page
  // without duplicating this setup. A real fix, not a workaround: this
  // suite's single Chromium tab was accumulating 150+ full navigations
  // over one run (it has grown a lot this session), and Chromium's own
  // renderer process really can run into internal resource exhaustion
  // (net::ERR_INSUFFICIENT_RESOURCES / navigation timeouts) after that
  // many navigations in one page -- confirmed not a memory/fd/disk
  // shortage on this host (checked directly: plenty free), and not tied
  // to any specific route, so recycling the page periodically is the
  // right fix, not silently retrying past it.
  function wirePage(p) {
    p.on("console", (msg) => {
      if (msg.type() === "error") consoleErrors.push(msg.text());
    });
    p.on("pageerror", (err) => {
      pageErrors.push(String(err));
      console.error("PAGE ERROR at", new Date().toISOString(), "url=", p.url(), "\n", err.stack || err);
    });
    // Several destructive actions (delete client, revoke/regenerate a
    // Strong ClientID identifier) use a real, deliberate native
    // window.confirm() -- this app's own established pattern for a
    // simple yes/no destructive gate, distinct from the richer inline
    // dialogs Upstreams' last-enabled guard and Backup's typed-filename
    // confirm use where more context needs to be shown. A native
    // confirm() blocks the renderer's main thread until dismissed, so
    // Puppeteer's own click() promise never resolves without a real
    // handler -- a real bug this suite hit live: a one-off
    // `window.confirm = () => true` injected via a single page.evaluate()
    // call does not survive a later page.reload() (a real full
    // navigation resets the whole JS context), so a native confirm()
    // dialog reached AFTER any reload hung the click that triggered it
    // for the full protocolTimeout, aborting the entire run before
    // later sections (Filters, Blocklists, Encryption, etc.) ever ran.
    // Puppeteer's own dialog handler is registered once per page here
    // and, unlike a script injection, is not undone by navigation.
    p.on("dialog", (dialog) => {
      dialog.accept().catch(() => {});
    });
  }

  try {
    let page = await browser.newPage();
    wirePage(page);

    await page.setViewport({ width: 1440, height: 900 });
    await page.goto(baseUrl, { waitUntil: "networkidle0" });

    // --- Bootstrap (real fresh instance only -- see the header comment) ---
    await page.waitForSelector("#bootstrap-heading, #setup-heading, #login-heading", { timeout: 5000 });
    if (await page.$("#bootstrap-heading")) {
      check("bootstrap-token-path was given for a fresh instance landing on the bootstrap gate", !!bootstrapTokenPath);
      const token = fs.readFileSync(bootstrapTokenPath, "utf8").trim();
      await page.type('input[autocomplete="off"]', token);
      await Promise.all([
        page.waitForSelector("#setup-heading", { timeout: 5000 }),
        page.click('button[type="submit"]'),
      ]);
      check("real bootstrap token advances to the setup/account-creation form", (await page.$("#setup-heading")) !== null);
    }

    // --- Setup ---
    await page.waitForSelector("#setup-heading, #login-heading", { timeout: 5000 });
    const onSetup = (await page.$("#setup-heading")) !== null;
    check("landed on setup screen for a fresh instance", onSetup);
    if (onSetup) {
      await page.type('input[autocomplete="username"]', username);
      await page.type('input[autocomplete="new-password"]', password);
      const confirmInputs = await page.$$('input[autocomplete="new-password"]');
      await confirmInputs[1].type(password);
      await Promise.all([
        page.waitForSelector("#login-heading", { timeout: 5000 }),
        page.click('button[type="submit"]'),
      ]);
      check("setup submission reaches the login screen", true);
    }

    // --- Login ---
    // The username field is intentionally pre-filled (carried over from
    // setup, a real product convenience) -- clear it first so we don't
    // append and log in with a garbled username.
    await page.$eval('input[autocomplete="username"]', (el) => (el.value = ""));
    await page.type('input[autocomplete="username"]', username);
    await page.type('input[autocomplete="current-password"]', password);
    await Promise.all([
      page.waitForSelector(".app-layout", { timeout: 5000 }),
      page.click('button[type="submit"]'),
    ]);
    check("login reaches the app shell", true);

    // --- Lands on the URL-synced default route with real rendered content ---
    await page.waitForFunction(() => location.pathname.startsWith("/ui/"), { timeout: 3000 });
    let path = new URL(page.url()).pathname;
    check("post-login URL is synced to a /ui/ route (not left at /)", path.startsWith("/ui/"), path);
    check("post-login landing route renders a real heading, not a coming-soon panel", (await page.$("h2")) !== null);

    // --- Dashboard: real (not fake) summary cards ---
    check("landed on Dashboard by default", path === "/ui/dashboard", path);
    await page.waitForSelector(".card .big", { timeout: 3000 }).catch(() => {});
    const cardCount = (await page.$$(".card")).length;
    check("Dashboard renders summary cards", cardCount >= 2, `found ${cardCount}`);
    // 2026-08-29: this check is retired, not just updated -- the P0/P1
    // live-defect pass (commit 39e455f, defect 7) removed Dashboard's
    // own developer-disclosure paragraph entirely per an explicit owner
    // instruction ("Owner UI should not contain internal implementation
    // essays"), so there is no longer any `.scope-note` element on this
    // page to assert text against at all. Confirmed by direct code read
    // (DashboardView.svelte has no `.scope-note` markup, only an
    // orphaned CSS rule -- removed alongside this fix) plus this
    // check's own real failure the first time this suite ran against a
    // build made after that removal.
    check("Dashboard has no leftover developer-disclosure paragraph (removed per P0 defect 7)", (await page.$(".scope-note")) === null);

    // --- Dashboard: Clients and Upstreams mini-panels (real data, not
    // placeholders -- these were previously disclosed as blocked on "the
    // policy boundary", which now exists natively in Go) ---
    await page.waitForFunction(
      () => [...document.querySelectorAll("h3")].some((h) => h.textContent?.trim() === "Clients"),
      { timeout: 3000 },
    ).catch(() => {});
    const clientsCardRowsFn = () => {
      const h3 = [...document.querySelectorAll("h3")].find((e) => e.textContent?.trim() === "Clients");
      const card = h3?.closest(".card");
      return card ? card.querySelectorAll(".mini-table tbody tr").length : -1;
    };
    await page.waitForFunction(clientsCardRowsFn, { timeout: 3000 }).catch(() => {});
    const clientsCardRows = await page.evaluate(clientsCardRowsFn);
    check("Dashboard Clients mini-panel renders (managed + observed rows, real data)", clientsCardRows >= 0, `rows=${clientsCardRows}`);
    const upstreamsCardRowsFn = () => {
      const h3 = [...document.querySelectorAll("h3")].find((e) => e.textContent?.trim() === "Upstreams");
      const card = h3?.closest(".card");
      return card ? card.querySelectorAll(".mini-table tbody tr").length : -1;
    };
    await page.waitForFunction(upstreamsCardRowsFn, { timeout: 3000 }).catch(() => {});
    const upstreamsCardRows = await page.evaluate(upstreamsCardRowsFn);
    // This early in the flow (right after login, before DNS Settings
    // ever runs below) a genuinely fresh instance has zero upstream
    // profiles -- >0 here was a real test bug, unconditionally
    // unsatisfiable on a true fresh run, not a product gap. The honest
    // empty state is the correct assertion now; the real "shows a row
    // once one actually exists" proof is a separate, properly-timed
    // check after DNS Settings creates one (search this file for
    // "Dashboard Upstreams mini-panel reflects a just-created profile").
    check("Dashboard Upstreams mini-panel renders its honest empty state on a true fresh instance", upstreamsCardRows === 0, `rows=${upstreamsCardRows}`);

    // --- Dashboard: DNS Activity chart, range switching, degraded states ---
    await page.waitForSelector(".range-select button", { timeout: 3000 }).catch(() => {});
    const rangeButtons = await page.$$(".range-select button");
    check("DNS Activity range selector has all 4 modes (Live/1h/24h/7d)", rangeButtons.length === 4, `found ${rangeButtons.length}`);
    // Switch to "Last 24 hours" -- the snapshot copy has real historical
    // data here, unlike Live mode against a frozen copy.
    for (const btn of rangeButtons) {
      if ((await btn.evaluate((el) => el.textContent?.trim())) === "Last 24 hours") {
        await btn.click();
        break;
      }
    }
    // A real bug in this test, not the app, found first: a fixed 400ms
    // sleep raced the real async fetch+render (chartPoints resets to []
    // on range switch, then the chart only appears once the real API
    // response lands -- see DashboardView.svelte's own chartLoading/
    // chartPoints guard). Wait for either terminal state instead.
    //
    // Once that race was fixed, the terminal state this fixture
    // actually reaches every time is the honest degraded note, not an
    // SVG -- this endpoint (like Top Domains/Top Blocked Domains/Query
    // Log, see the writer-health consistency fix elsewhere in this
    // pass) correctly reports degraded whenever no real
    // *dnsanalytics.Writer is wired, which this fixture deliberately
    // has none of. Asserting a rendered SVG here was never really
    // testable in this fixture at all -- it needs a real dnstap writer,
    // which is exactly the boundary internal/hostagentd's own fixtures
    // (not this suite) are built to exercise.
    await page.waitForFunction(
      () => document.querySelector(".wide-card svg") !== null || document.querySelector(".wide-card .degraded-note") !== null,
      { timeout: 3000 },
    ).catch(() => {});
    const chartDegradedNote = await page.$(".wide-card .degraded-note");
    check("DNS Activity chart honestly reports degraded when no writer is wired (this fixture has none)", chartDegradedNote !== null);

    // --- Dashboard: Top Domains reports the same honest degraded state
    // as its sibling cards above (this fixture has no real writer). The
    // shared DataGrid component's own sort/resize/persist mechanics
    // (previously proven right here, against this exact grid) are now
    // proven instead against the Notifications page's real
    // "notification-providers" grid, further down in this same run --
    // search for "DataGrid mechanics (sort/resize/persist)" -- a grid
    // this fixture can actually populate with real, non-degraded rows.
    await page.waitForSelector(".card .degraded-note", { timeout: 3000 }).catch(() => {});
    const topDomainsDegraded = await page.evaluate(() => {
      const h3 = [...document.querySelectorAll("h3")].find((e) => e.textContent?.includes("Top Domains") && !e.textContent.includes("Blocked"));
      const card = h3?.closest(".card");
      return card ? card.querySelector(".degraded-note") !== null : false;
    });
    check("Top Domains honestly reports degraded when no writer is wired (this fixture has none)", topDomainsDegraded);

    // --- Dashboard: Top Blocked Domains reports the same honest,
    // writer-health-aware degraded state as Top Domains/Query Log now
    // (a real app fix landed alongside this test fix: all three used to
    // disagree on whether "no *dnsanalytics.Writer wired" counts as
    // degraded -- Top Blocked Domains and Query Log didn't check it at
    // all, an inconsistency found via this exact check failing once
    // Top Domains' own already-correct behavior was compared against
    // it). This fixture has real seeded query_events rows (see
    // go/tests/fixtures/seed_query_events.sh) but deliberately no real
    // dnstap writer at all -- degraded:true is the honest, correct
    // state here, not a placeholder-shaped failure.
    const blockedDomainDegradedFn = () => {
      const h3 = [...document.querySelectorAll("h3")].find((e) => e.textContent?.includes("Top Blocked Domains"));
      const card = h3?.closest(".card");
      return card ? card.querySelector(".degraded-note") !== null : false;
    };
    const blockedDomainCards = await page.$$eval("h3", (els) => els.filter((e) => e.textContent?.includes("Top Blocked Domains")).length);
    check("Top Blocked Domains card renders on the Dashboard", blockedDomainCards === 1, `count=${blockedDomainCards}`);
    await page.waitForFunction(blockedDomainDegradedFn, { timeout: 3000 }).catch(() => {});
    const blockedDegraded = await page.evaluate(blockedDomainDegradedFn);
    check("Top Blocked Domains honestly reports degraded when no writer is wired (not a silently-stale 'real' render)", blockedDegraded);

    // --- Dashboard: card customization (hide, reorder, persistence) ---
    await page.click(".customize-btn");
    await page.waitForSelector(".customize-panel", { timeout: 2000 });
    const cardLabelsBefore = await page.$$eval(".customize-panel li label", (els) => els.map((e) => e.textContent.trim()));
    check("customize panel lists all 7 cards", cardLabelsBefore.length === 7, cardLabelsBefore.join(","));
    // Hide "Top Blocked Domains".
    const checkboxes = await page.$$(".customize-panel input[type=checkbox]");
    const labels = await page.$$eval(".customize-panel li label", (els) => els.map((e) => e.textContent.trim()));
    const hideIdx = labels.findIndex((l) => l.includes("Top Blocked Domains"));
    await checkboxes[hideIdx].click();
    await new Promise((r) => setTimeout(r, 100));
    let visibleCardHeadings = await page.$$eval(".cards .card h3", (els) => els.map((e) => e.childNodes[0].textContent.trim()));
    check("hiding a card via Customize actually removes it from the dashboard", !visibleCardHeadings.includes("Top Blocked Domains"), visibleCardHeadings.join(","));
    // Move "Local DNS" up one (it starts second, after Blocklists).
    const upButtons = await page.$$(".customize-panel .reorder-btns button:first-child");
    await upButtons[1].click(); // second card's "move up" button
    await new Promise((r) => setTimeout(r, 100));
    const orderAfterMove = await page.$$eval(".customize-panel li label", (els) => els.map((e) => e.textContent.trim()));
    check("reordering via Customize actually changes the stored order", orderAfterMove[0].includes("Local DNS"), orderAfterMove.join(","));
    // Reload the page: persistence must survive it.
    await page.reload({ waitUntil: "networkidle0" });
    await page.waitForSelector(".dashboard", { timeout: 5000 });
    await page.click(".customize-btn");
    await page.waitForSelector(".customize-panel", { timeout: 2000 });
    // The customize panel always lists every card (so a hidden one can be
    // re-shown); check its checkbox state, not list membership, for
    // whether it's actually hidden from the dashboard.
    const orderAfterReload = await page.$$eval(".customize-panel li", (els) =>
      els.map((li) => ({ label: li.querySelector("label").textContent.trim(), checked: li.querySelector("input").checked })),
    );
    const blockedEntry = orderAfterReload.find((c) => c.label.includes("Top Blocked Domains"));
    check(
      "card hide + reorder persists across a full page reload",
      blockedEntry && blockedEntry.checked === false && orderAfterReload[0].label.includes("Local DNS"),
      JSON.stringify(orderAfterReload),
    );
    const stillHiddenOnPage = (await page.$$eval(".cards .card h3", (els) => els.map((e) => e.childNodes[0].textContent.trim()))).every(
      (h) => !h.includes("Top Blocked Domains"),
    );
    check("hidden card is still hidden from the dashboard itself after reload, not just the panel", stillHiddenOnPage);
    // Restore: re-show the hidden card for a clean state before continuing.
    const checkboxesAfter = await page.$$(".customize-panel input[type=checkbox]");
    const labelsAfter = await page.$$eval(".customize-panel li label", (els) => els.map((e) => e.textContent.trim()));
    const reshowIdx = labelsAfter.findIndex((l) => l.includes("Top Blocked Domains"));
    if (reshowIdx >= 0) await checkboxesAfter[reshowIdx].click();
    await page.click(".customize-btn");

    // --- Nav: Query Log (internal/dnsanalytics -- real Go-native query_events, since the 2026-08-28 cutover) ---
    const clickedQueryLog = await clickNavItem(page, (t) => t === "Query Log");
    check("Query Log nav item exists and is clickable", clickedQueryLog);
    await page.waitForSelector("#analytics-heading", { timeout: 3000 }).catch(() => {});
    check("Query Log page content rendered", (await page.$("#analytics-heading")) !== null);

    // Real rows from the seeded fixture (go/tests/fixtures/seed_query_events.sh,
    // run against this instance's -analytics-db before this script starts),
    // not a mocked/empty grid. `:not(.empty-row)` excludes the DataGrid's
    // own pre-existing placeholder row -- the same race-condition class
    // already found and fixed for Upstreams/Backup/Filters elsewhere in
    // this file, closed more generally here since Query Log's grid has
    // no per-row .actions cell to key off of instead.
    await page.waitForFunction(() => document.querySelectorAll(".data-grid tbody tr:not(.empty-row)").length > 0, { timeout: 5000 }).catch(() => {});
    let queryLogRows = await page.$$eval(".data-grid tbody tr:not(.empty-row)", (rows) => rows.length);
    check("Query Log grid renders real seeded rows", queryLogRows === 3, `rows=${queryLogRows}`);

    // Domain filter narrows the grid to a real, server-side-filtered result.
    await page.type('input[aria-label="Filter by domain"]', "acceptance-blocked.example.com.");
    await Promise.all([
      page.waitForFunction(() => document.querySelectorAll(".data-grid tbody tr:not(.empty-row)").length === 2, { timeout: 3000 }),
      page.click('.filters button[type="submit"]'),
    ]);
    queryLogRows = await page.$$eval(".data-grid tbody tr:not(.empty-row)", (rows) => rows.length);
    check("Query Log domain filter narrows the grid server-side", queryLogRows === 2, `rows=${queryLogRows}`);
    const activeFilterBadge = await page.$eval(".filters .badge", (el) => el.textContent).catch(() => "");
    check("Query Log shows an active-filter badge while a filter is set", activeFilterBadge.includes("1 active filter"), activeFilterBadge);

    await page.click(".filters .clear-filters");
    await page.waitForFunction(() => document.querySelectorAll(".data-grid tbody tr:not(.empty-row)").length === 3, { timeout: 3000 }).catch(() => {});
    queryLogRows = await page.$$eval(".data-grid tbody tr:not(.empty-row)", (rows) => rows.length);
    check("clearing filters restores the full grid", queryLogRows === 3, `rows=${queryLogRows}`);

    // --- Nav: Local DNS ---
    let clicked = await clickNavItem(page, (t) => t?.startsWith("Local DNS"));
    check("Local DNS nav item exists and is clickable", clicked);
    await page.waitForFunction(() => location.pathname === "/ui/localdns", { timeout: 3000 }).catch(() => {});
    check("clicking Local DNS navigates to /ui/localdns", new URL(page.url()).pathname === "/ui/localdns");
    await page.waitForSelector("#localdns-heading", { timeout: 3000 });
    check("Local DNS page content rendered", true);

    // --- Sidebar: single-open accordion (A -> B closes A) ---
    // Local DNS lives in the "dns" group -- navigating to it must have
    // opened exactly that group's panel and no other.
    let openPanelCount = await page.$$eval(".sidebar .group .panel", (els) => els.length);
    check("opening the dns group leaves exactly one section panel open", openPanelCount === 1, `open=${openPanelCount}`);
    let dnsPanelOpen = await page.$$eval(".sidebar .group", (groups) =>
      groups.some((g) => g.querySelector(".panel") && g.querySelector(".group-toggle")?.textContent?.includes("DNS")),
    );
    check("the dns group specifically is the one open", dnsPanelOpen);

    // --- Nav: Administration ---
    clicked = await clickNavItem(page, (t) => t?.startsWith("Administration"));
    check("Administration nav item exists and is clickable", clicked);
    await page.waitForSelector("#admin-heading", { timeout: 3000 }).catch(() => {});
    check("Administration page content rendered", (await page.$("#admin-heading")) !== null);

    // Administration lives in the "system" group -- opening it must have
    // closed the previously-open "dns" group (A -> B closes A), leaving
    // exactly one panel open, and that one active child still visibly
    // selected.
    openPanelCount = await page.$$eval(".sidebar .group .panel", (els) => els.length);
    check("opening the system group still leaves exactly one panel open", openPanelCount === 1, `open=${openPanelCount}`);
    const systemPanelOpen = await page.$$eval(".sidebar .group", (groups) =>
      groups.some((g) => g.querySelector(".panel") && g.querySelector(".group-toggle")?.textContent?.includes("System")),
    );
    check("opening Administration switches the open section to system (dns closes)", systemPanelOpen);
    const adminActiveInPanel = await page.$$eval(".sidebar .panel .item.active", (els) => els.map((e) => e.textContent?.trim()));
    check("the active child (Administration) is visibly selected within the open panel", adminActiveInPanel.some((t) => t?.startsWith("Administration")), adminActiveInPanel.join(","));

    // --- Timestamp mode: instant reformat, no reload ---
    const previewBefore = await page.$eval(".preview strong", (el) => el.textContent).catch(() => null);
    const utcRadio = await page.$$eval('input[name="ts-mode"]', (els) => els.length);
    check("three timestamp mode radios present", utcRadio === 3, `found ${utcRadio}`);
    const radios = await page.$$('input[name="ts-mode"]');
    await radios[2].click(); // UTC
    await new Promise((r) => setTimeout(r, 50));
    const previewAfter = await page.$eval(".preview strong", (el) => el.textContent).catch(() => null);
    check("timestamp preview updates instantly on mode change", previewAfter && previewAfter.includes("UTC"), previewAfter);

    // --- Change password: wrong current password is rejected ---
    const pwInputs = await page.$$('.stack-form input[type="password"]');
    await pwInputs[0].type("not the real password");
    await pwInputs[1].type("some new password 12+");
    await pwInputs[2].type("some new password 12+");
    await page.click('.stack-form button[type="submit"]');
    await page.waitForFunction(() => document.querySelector(".stack-form .error") !== null, { timeout: 3000 }).catch(() => {});
    check(
      "change-password rejects a wrong current password",
      (await page.$eval(".stack-form .error", (el) => el.textContent).catch(() => "")).includes("incorrect"),
    );

    // --- Change password: correct flow succeeds, and the new password actually works ---
    for (const input of pwInputs) await page.evaluate((el) => (el.value = ""), input);
    await pwInputs[0].type(password);
    await pwInputs[1].type("a brand new password 12+");
    await pwInputs[2].type("a brand new password 12+");
    await page.click('.stack-form button[type="submit"]');
    await page.waitForSelector(".stack-form .success", { timeout: 3000 }).catch(() => {});
    check("change-password succeeds with the correct current password", (await page.$(".stack-form .success")) !== null);

    // Prove it by logging out and back in with the new password.
    const logoutBtn = await page.$(".logout-btn");
    await logoutBtn.click();
    await page.waitForSelector("#login-heading", { timeout: 3000 });
    await page.$eval('input[autocomplete="username"]', (el) => (el.value = ""));
    await page.type('input[autocomplete="username"]', username);
    await page.type('input[autocomplete="current-password"]', "a brand new password 12+");
    await Promise.all([
      page.waitForSelector(".app-layout", { timeout: 5000 }),
      page.click('button[type="submit"]'),
    ]);
    check("the new password actually authenticates after logout", (await page.$(".app-layout")) !== null);

    // Re-navigate to Administration for the revoke-sessions check below.
    await clickNavItem(page, (t) => t?.startsWith("Administration"));
    await page.waitForSelector("#admin-heading", { timeout: 3000 }).catch(() => {});

    // --- Revoke other sessions ---
    const revokeBtn = await page.$(".danger");
    await revokeBtn.click();
    await new Promise((r) => setTimeout(r, 300));
    const revokeText = await page.$$eval(".card p.hint[role='status']", (els) => els.map((e) => e.textContent).join(" "));
    check("revoke-other-sessions reports a result", /revoked|no other sessions/i.test(revokeText), revokeText);

    // --- Theme toggle ---
    const themeBefore = await page.$eval("html", (el) => el.getAttribute("data-theme"));
    await page.click(".theme-toggle");
    await new Promise((r) => setTimeout(r, 50));
    const themeAfter = await page.$eval("html", (el) => el.getAttribute("data-theme"));
    check("theme toggle actually flips data-theme", themeBefore !== themeAfter, `${themeBefore} -> ${themeAfter}`);

    // --- Sidebar: direct-route navigation opens only that route's own
    // parent section (not a sidebar click -- exercises the route-driven
    // $effect path directly, e.g. a deep link or browser back/forward).
    // Currently on Administration ("system" group open); navigating
    // straight to a "security"-group route must switch to exactly that
    // group, not leave "system" open alongside it. ---
    await page.goto(new URL("/ui/blocklists", baseUrl).toString(), { waitUntil: "networkidle0" });
    await page.waitForSelector(".sidebar", { timeout: 3000 });
    const securityPanelOpenOnDirectNav = await page.$$eval(".sidebar .group", (groups) =>
      groups.some((g) => g.querySelector(".panel") && g.querySelector(".group-toggle")?.textContent?.includes("Security")),
    );
    check("direct navigation to a child route opens only that child's parent section", securityPanelOpenOnDirectNav);
    const panelsAfterDirectNav = await page.$$eval(".sidebar .group .panel", (els) => els.length);
    check("direct navigation leaves exactly one section open, not the prior one too", panelsAfterDirectNav === 1, `open=${panelsAfterDirectNav}`);

    // --- Mobile viewport + drawer ---
    await page.setViewport({ width: 390, height: 844 });
    await new Promise((r) => setTimeout(r, 100));
    const menuVisible = await page.$eval(".menu-btn", (el) => getComputedStyle(el).display !== "none");
    check("menu button appears at 390px", menuVisible);
    await page.click(".menu-btn");
    await new Promise((r) => setTimeout(r, 150));
    const drawerOpen = await page.$eval(".sidebar", (el) => el.classList.contains("mobile-open"));
    check("clicking menu button opens the mobile drawer", drawerOpen);

    // --- Sidebar: single-open accordion inside the mobile drawer itself
    // (same component/state as desktop, but worth proving directly on
    // the actual mobile layout, not just inferring it from the desktop
    // checks above). Currently on /ui/blocklists, so "security" should
    // be the one open section in the drawer.
    const securityOpenInDrawer = await page.$$eval(".sidebar.mobile-open .group", (groups) =>
      groups.some((g) => g.querySelector(".panel") && g.querySelector(".group-toggle")?.textContent?.includes("Security")),
    );
    check("mobile drawer opens the current route's own section", securityOpenInDrawer);
    let dnsToggle = null;
    for (const btn of await page.$$(".sidebar.mobile-open .group-toggle")) {
      if ((await btn.evaluate((el) => el.textContent?.trim())).includes("DNS")) {
        dnsToggle = btn;
        break;
      }
    }
    if (dnsToggle) await dnsToggle.click();
    await new Promise((r) => setTimeout(r, 50));
    const panelsInDrawerAfterSwitch = await page.$$eval(".sidebar.mobile-open .group .panel", (els) => els.length);
    check("opening a different section in the mobile drawer closes the previous one", panelsInDrawerAfterSwitch === 1, `open=${panelsInDrawerAfterSwitch}`);
    const dnsOpenInDrawer = await page.$$eval(".sidebar.mobile-open .group", (groups) =>
      groups.some((g) => g.querySelector(".panel") && g.querySelector(".group-toggle")?.textContent?.includes("DNS")),
    );
    check("the newly-clicked section (dns) is the one now open in the drawer", dnsOpenInDrawer);
    const drawerStillOpenAfterGroupToggle = await page.$eval(".sidebar", (el) => el.classList.contains("mobile-open"));
    check("toggling a section in the drawer does not itself close the drawer", drawerStillOpenAfterGroupToggle);

    await page.keyboard.press("Escape");
    await new Promise((r) => setTimeout(r, 150));
    const drawerClosedAfterEscape = await page.$eval(".sidebar", (el) => !el.classList.contains("mobile-open"));
    check("Escape closes the mobile drawer", drawerClosedAfterEscape);
    const overflowX = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth);
    check("no page-level horizontal overflow at 390px", !overflowX);
    await page.setViewport({ width: 1440, height: 900 });

    // --- Nav: System Status (real health/system-status + real session-only UI perf log) ---
    const clickedHealth = await clickNavItem(page, (t) => t === "System Status");
    check("System Status nav item exists and is clickable", clickedHealth);
    await page.waitForSelector("#health-heading", { timeout: 3000 }).catch(() => {});
    check("System Status page content rendered", (await page.$("#health-heading")) !== null);
    await page.waitForFunction(() => document.querySelector(".metric-strip .value")?.textContent !== "…", { timeout: 3000 }).catch(() => {});
    // A real test bug, not the app: this used to assert status==="ok"
    // unconditionally, but this fixture's own analytics component is
    // honestly "degraded" (no real dnstap writer wired -- see the
    // writer-health checks earlier in this run), which correctly
    // demotes the overall /api/health status too (see internal/
    // pyanalytics/health.go's own doc comment: this is deliberate, the
    // real fix for "DNS kept running while the analytics writer died
    // and the page kept showing a convincing ok status"). The class is
    // `status-{health.status}`, so `.status-ok` never existed here at
    // all. Assert the real value renders as SOME real, non-placeholder
    // status instead of assuming which one.
    const statusValue = await page.$eval(".metric .value[class*='status-']", (el) => el.textContent.trim()).catch(() => null);
    check("System Status metric strip renders a real component status (honestly 'degraded' in this no-writer fixture)", statusValue === "ok" || statusValue === "degraded", statusValue);
    // A second real test bug found alongside the first: perfLog is a
    // plain in-memory, session-only log (deliberately -- matches
    // Python's own semantics, see PARITY_MATRIX), so a real
    // page.reload() earlier in this same run (Domain Routing/Clients &
    // Access persistence checks) genuinely, correctly resets it to
    // empty -- assuming a specific accumulated count across those
    // reloads was never a safe assumption. Assert real entries exist
    // (this navigation itself is one), not a specific historical count.
    const perfRowCount = await page.$$eval(".perf-table tbody tr", (rows) => rows.length).catch(() => 0);
    check("UI Performance table records real navigation latency entries", perfRowCount > 0, `rows=${perfRowCount}`);
    await page.click(".clear-perf");
    await new Promise((r) => setTimeout(r, 50));
    const perfRowCountAfterClear = await page.$$eval(".perf-table tbody tr", (rows) => rows.length).catch(() => 0);
    check("Clear Measurements actually empties the UI Performance table", perfRowCountAfterClear === 0, `rows=${perfRowCountAfterClear}`);

    // --- Blocklists: data grid sort, in-place table (real page with rows) ---
    clicked = await clickNavItem(page, (t) => t?.startsWith("Blocklists"));
    check("Blocklists nav item exists and is clickable", clicked);
    await page.waitForSelector("#blocklists-heading", { timeout: 3000 }).catch(() => {});
    const gridPresent = (await page.$(".data-grid")) !== null;
    check("shared DataGrid renders on Blocklists", gridPresent);
    const sortableHeader = await page.$(".sort-btn");
    check("Blocklists grid has at least one sortable column header", sortableHeader !== null);

    // --- Nav: DNS Settings / Upstreams ---
    const clickedUpstreams = await clickNavItem(page, (t) => t === "DNS Settings");
    check("DNS Settings nav item exists and is clickable", clickedUpstreams);
    await page.waitForSelector("#upstreams-heading", { timeout: 3000 }).catch(() => {});
    check("Upstreams page content rendered", (await page.$("#upstreams-heading")) !== null);

    // Create a profile.
    await page.type('.profile-form input[required]', "Test Upstream");
    await page.type('.endpoint-row input[placeholder^="Address"]', "9.9.9.9");
    await Promise.all([
      // A real row has an .actions cell; the grid's pre-existing
      // empty-state <tr> does not -- waiting on plain "tr count > 0"
      // would already be satisfied by that empty-state row and race
      // ahead of the actual creation response.
      page.waitForFunction(() => document.querySelectorAll(".data-grid tbody .actions").length > 0, { timeout: 3000 }),
      page.click('.profile-form button[type="submit"]'),
    ]);
    let rowCount = await page.$$eval(".data-grid tbody tr", (rows) => rows.length);
    check("creating an upstream profile adds a real row to the grid", rowCount === 1, `rows=${rowCount}`);

    // Disabling the only (last) enabled upstream must show the confirm dialog, not silently succeed.
    const actionButtons = await page.$$(".data-grid tbody .actions button");
    let disableClicked = false;
    for (const btn of actionButtons) {
      if ((await btn.evaluate((el) => el.textContent?.trim())) === "Disable") {
        await btn.click();
        disableClicked = true;
        break;
      }
    }
    check("Disable button exists for the created profile", disableClicked);
    await page.waitForSelector(".confirm-last", { timeout: 2000 }).catch(() => {});
    check("disabling the last enabled upstream shows a confirm dialog instead of silently succeeding", (await page.$(".confirm-last")) !== null);
    const stillEnabled = await page.$eval(".data-grid tbody .badge", (el) => el.textContent.trim());
    check("the profile is still shown as Enabled until the confirm dialog is accepted", stillEnabled === "Enabled", stillEnabled);
    // Accept the confirmation.
    const confirmBtn = await page.$(".confirm-last .danger");
    await confirmBtn.click();
    await new Promise((r) => setTimeout(r, 300));
    const nowDisabled = await page.$eval(".data-grid tbody .badge", (el) => el.textContent.trim());
    check("confirming disables the profile for real", nowDisabled === "Disabled");
    const infoBanner = await page.$(".info-banner");
    check("native-recursion info banner appears once zero upstreams are enabled", infoBanner !== null);

    // Dashboard Upstreams mini-panel reflects a just-created profile:
    // the real, properly-timed counterpart to this file's own earlier
    // "honest empty state" check -- an upstream profile now genuinely
    // exists (disabled, but the mini-panel shows every profile
    // regardless of enabled state, matching DashboardView.svelte's own
    // template), so the panel must show it, not still report empty.
    await clickNavItem(page, (t) => t === "Dashboard");
    await page.waitForSelector("#dashboard-heading", { timeout: 3000 }).catch(() => {});
    const upstreamsCardRowsAfterCreate = await page.evaluate(upstreamsCardRowsFn);
    check("Dashboard Upstreams mini-panel reflects a just-created profile", upstreamsCardRowsAfterCreate === 1, `rows=${upstreamsCardRowsAfterCreate}`);
    await clickNavItem(page, (t) => t === "DNS Settings");
    await page.waitForSelector("#upstreams-heading", { timeout: 3000 }).catch(() => {});

    // --- Domain Routing (same page, below the Upstream Profiles grid) ---
    // The disabled "Test Upstream" profile from above still exists and
    // is still selectable here -- routing doesn't require the target
    // profile to be enabled, only to exist.
    await page.select('.route-form select[aria-label="Match kind"]', "suffix");
    await page.type('.route-form input[aria-label="Domain"]', "corp.example.com");
    await page.select('.route-form select[aria-label="Upstream profile"]', await page.$eval(
      '.route-form select[aria-label="Upstream profile"] option:not([value=""])',
      (el) => el.value,
    ));
    await Promise.all([
      page.waitForFunction(() => document.querySelectorAll(".routes-table tbody tr td button").length > 0, { timeout: 3000 }),
      page.click('.route-form button[type="submit"]'),
    ]);
    const routeRowCount = await page.$$eval(".routes-table tbody tr", (rows) => rows.length);
    check("adding a domain route creates a real row in the routes table", routeRowCount === 1, `rows=${routeRowCount}`);
    const routeRowText = await page.$eval(".routes-table tbody tr", (el) => el.textContent);
    check("the real route's match kind/domain/upstream name all render", /suffix/.test(routeRowText) && /corp\.example\.com/.test(routeRowText) && /Test Upstream/.test(routeRowText), routeRowText);

    // Reload and confirm it persisted -- not just an optimistic client-side row.
    await page.reload({ waitUntil: "networkidle0" });
    await page.waitForSelector("#upstreams-heading", { timeout: 5000 });
    await new Promise((r) => setTimeout(r, 200));
    const routeRowCountAfterReload = await page.$$eval(".routes-table tbody tr", (rows) => rows.length).catch(() => 0);
    check("the domain route survives a full page reload (real persistence)", routeRowCountAfterReload === 1, `rows=${routeRowCountAfterReload}`);

    // Delete it.
    await page.click(".routes-table tbody tr td button");
    await page.waitForFunction(() => document.querySelector(".routes-table tbody .empty-row") !== null, { timeout: 3000 }).catch(() => {});
    const routeEmptyAfterDelete = (await page.$(".routes-table tbody .empty-row")) !== null;
    check("deleting the domain route removes it for real (honest empty state, not a leftover row)", routeEmptyAfterDelete);

    // --- Nav: Clients ---
    const clickedClients = await clickNavItem(page, (t) => t === "Clients");
    check("Clients nav item exists and is clickable", clickedClients);
    await page.waitForSelector("#clients-heading", { timeout: 3000 }).catch(() => {});
    check("Clients page content rendered", (await page.$("#clients-heading")) !== null);

    // Add client/Add group now open a real modal (see ClientsView.svelte's
    // Modal-based rebuild) -- click the toolbar button by its exact text,
    // fill and submit the form inside `.modal-form`, same pattern
    // clients_access_smoke.mjs already established. The Managed Clients
    // grid is scoped via [data-grid-id="managed-clients"] rather than
    // the bare .data-grid class, since the page also now has a separate
    // Client analytics grid (real seeded rows from
    // seed_query_events.sh would otherwise be double-counted).
    async function openModalByButtonText(label) {
      for (const btn of await page.$$("button")) {
        if ((await btn.evaluate((el) => el.textContent?.trim())) === label) {
          await btn.click();
          await page.waitForSelector(".modal-form", { timeout: 2000 });
          return true;
        }
      }
      return false;
    }

    // Create a managed client first (Add group is disabled until at
    // least one client or group exists).
    check("Add client button opens a real modal", await openModalByButtonText("Add client"));
    await page.type(".modal-form input[required]", "Test Client");
    await Promise.all([
      page.waitForFunction(
        () => document.querySelectorAll('[data-grid-id="managed-clients"] tbody tr').length > 0 && document.querySelector('[data-grid-id="managed-clients"] tbody .actions'),
        { timeout: 3000 },
      ),
      page.click(".modal-form button[type=submit]"),
    ]);
    await new Promise((r) => setTimeout(r, 200));
    const clientRows = await page.$$eval('[data-grid-id="managed-clients"] tbody tr', (rows) => rows.length);
    check("creating a managed client adds a real row to the grid", clientRows === 1, `rows=${clientRows}`);

    // Create a group (needed for the "assign group" workflow below).
    check("Add group button opens a real modal", await openModalByButtonText("Add group"));
    await page.type(".modal-form input[required]", "Kids");
    await Promise.all([
      page.waitForFunction(() => document.querySelector(".group-list") !== null || /No groups/.test(document.body.textContent), { timeout: 3000 }),
      page.click(".modal-form button[type=submit]"),
    ]);
    await new Promise((r) => setTimeout(r, 300));
    const groupListText = await page.$eval(".group-list", (el) => el.textContent).catch(() => "");
    check("creating a group adds a real entry to the group list", groupListText.includes("Kids"), groupListText);

    // Add an identifier: invalid first (must be rejected), then valid.
    // Looked up by its actual label rather than array index -- action
    // button order isn't a stable contract.
    async function clickActionButton(label) {
      for (const btn of await page.$$("[data-grid-id='managed-clients'] tbody .actions button")) {
        if ((await btn.evaluate((el) => el.textContent?.trim())) === label) {
          await btn.click();
          return true;
        }
      }
      return false;
    }
    check("Add IP identifier button exists", await clickActionButton("Add IP identifier"));
    await page.waitForSelector(".inline-form input", { timeout: 2000 });
    await page.type(".inline-form input", "not-an-ip");
    await page.click(".inline-form button[type=submit]");
    await new Promise((r) => setTimeout(r, 200));
    const idError = await page.$eval(".inline-form .error", (el) => el.textContent).catch(() => "");
    check("adding an invalid IPv4 identifier is rejected client-visibly", idError.length > 0, idError);
    await page.$eval(".inline-form input", (el) => (el.value = ""));
    await page.type(".inline-form input", "10.0.0.5");
    await Promise.all([
      page.waitForFunction(() => /10\.0\.0\.5/.test(document.querySelector("[data-grid-id='managed-clients'] tbody")?.textContent ?? ""), { timeout: 3000 }),
      page.click(".inline-form button[type=submit]"),
    ]);
    // IP/CIDR identifiers render in the "identifiers" column's own
    // `.id-list` (a plain `.chip` per identifier, no wrapping `.chips`
    // container -- that class is used by the separate overrides/groups
    // columns instead), so scope the read there specifically rather
    // than the first `.chips` element in the row, which would grab an
    // unrelated column.
    const chipsText = await page.$eval("[data-grid-id='managed-clients'] tbody .id-list", (el) => el.textContent);
    check("a valid identifier actually appears on the client row after saving", chipsText.includes("10.0.0.5"), chipsText);

    // --- Full managed-client lifecycle: edit, enable/disable, remove
    // from group, delete identifier, delete client ---
    check("Assign group button exists", await clickActionButton("Assign group"));
    await page.waitForSelector(".inline-form select", { timeout: 2000 });
    await Promise.all([
      // Waits for a real rendered chip, not just "Kids" appearing anywhere
      // (the still-open assign-group <select>'s own <option> already
      // contains the text "Kids" before the mutation completes).
      page.waitForFunction(() => [...document.querySelectorAll("[data-grid-id='managed-clients'] tbody .chips .chip")].some((c) => c.textContent.includes("Kids")), { timeout: 3000 }),
      page.click(".inline-form button[type=submit]"),
    ]);
    const groupsChipText = await page.$eval("[data-grid-id='managed-clients'] tbody", (el) => el.textContent);
    check("assigning a group actually shows it on the client row", groupsChipText.includes("Kids"), groupsChipText);

    check("Edit button exists", await clickActionButton("Edit"));
    await page.waitForSelector(".edit-name-form input", { timeout: 2000 });
    const editInputs = await page.$$(".edit-name-form input");
    await editInputs[0].click({ clickCount: 3 });
    await editInputs[0].type("Test Client Renamed");
    await Promise.all([
      page.waitForFunction(() => /Test Client Renamed/.test(document.querySelector("[data-grid-id='managed-clients'] tbody").textContent), { timeout: 3000 }),
      page.click(".edit-name-form button[type=submit]"),
    ]);
    const renamedText = await page.$eval("[data-grid-id='managed-clients'] tbody", (el) => el.textContent);
    check("editing a client's name actually persists and re-renders", renamedText.includes("Test Client Renamed"), renamedText);

    check("Disable button exists on a managed client", await clickActionButton("Disable"));
    await page.waitForSelector(".disabled-badge", { timeout: 3000 }).catch(() => {});
    check("disabling a client shows a real disabled badge", (await page.$(".disabled-badge")) !== null);
    check("Enable button exists after disabling", await clickActionButton("Enable"));
    await new Promise((r) => setTimeout(r, 200));
    check("re-enabling removes the disabled badge", (await page.$(".disabled-badge")) === null);

    // Remove the IPv4 identifier added above (its own chip-x, not the
    // Strong ClientID rows). The real native confirm() this triggers is
    // handled by wirePage's own page.on("dialog") handler, registered
    // once for the whole page's lifetime -- not a one-off script
    // injection that a later reload would silently undo.
    const removedIdentifier = await page.evaluate(() => {
      const chip = [...document.querySelectorAll("[data-grid-id='managed-clients'] tbody .id-list .chip")].find((c) => c.textContent.includes("10.0.0.5"));
      const btn = chip?.querySelector(".chip-x");
      if (!btn) return false;
      btn.click();
      return true;
    });
    check("identifier remove control exists and is clickable", removedIdentifier);
    await new Promise((r) => setTimeout(r, 300));
    const afterIdentifierRemoveText = await page.$eval("[data-grid-id='managed-clients'] tbody", (el) => el.textContent);
    check("removing an IP identifier actually removes it from the row", !afterIdentifierRemoveText.includes("10.0.0.5"), afterIdentifierRemoveText);

    // Remove from group (chip-x on the group chip).
    const removedFromGroup = await page.evaluate(() => {
      const chip = [...document.querySelectorAll("[data-grid-id='managed-clients'] tbody .chips .chip")].find((c) => c.textContent.includes("Kids"));
      const btn = chip?.querySelector(".chip-x");
      if (!btn) return false;
      btn.click();
      return true;
    });
    check("group remove control exists and is clickable", removedFromGroup);
    await new Promise((r) => setTimeout(r, 300));
    const afterGroupRemoveText = await page.$eval("[data-grid-id='managed-clients'] tbody", (el) => el.textContent);
    check("removing a client from a group actually removes it from the row", !afterGroupRemoveText.includes("Kids"), afterGroupRemoveText);

    // --- Observed Clients (real traffic-derived, honest empty state on
    // a fresh instance with no query history) ---
    const observedSectionText = await page.evaluate(() => {
      // Observed Clients is now the shared Panel component (ClientsView's
      // design-system rebuild), whose heading renders as <h2>, not the
      // page's old bespoke <h3>.
      const headings = [...document.querySelectorAll("h2, h3")];
      const target = headings.find((h) => h.textContent.trim() === "Observed Clients");
      return target ? (target.closest(".panel") ?? target.parentElement)?.textContent ?? "" : null;
    });
    check("Observed Clients section renders on the Clients page", observedSectionText !== null, String(observedSectionText));

    // --- Per-client policy editor (shared PolicyEditor) ---
    const policyButtons = await page.$$("[data-grid-id='managed-clients'] tbody .actions button");
    let policyClicked = false;
    for (const btn of policyButtons) {
      if ((await btn.evaluate((el) => el.textContent?.trim())) === "Policy") {
        await btn.click();
        policyClicked = true;
        break;
      }
    }
    check("Policy button opens the per-client policy editor", policyClicked);
    await page.waitForSelector(".policy-editor select", { timeout: 2000 }).catch(() => {});
    check("policy editor renders its field grid", (await page.$(".policy-editor .grid")) !== null);
    // Change Safesearch to "Strict" and save; verify it actually persisted.
    const selects = await page.$$(".policy-editor select");
    await selects[0].select("strict");
    await Promise.all([
      page.waitForSelector(".policy-editor .ok", { timeout: 3000 }),
      page.click(".policy-editor button[type=submit]"),
    ]);
    // Reload the whole page -- the saved value must survive a real
    // server round trip, not just be a local echo.
    await page.reload({ waitUntil: "networkidle0" });
    await page.waitForSelector("#clients-heading", { timeout: 5000 });
    const reopenButtons = await page.$$("[data-grid-id='managed-clients'] tbody .actions button");
    for (const btn of reopenButtons) {
      if ((await btn.evaluate((el) => el.textContent?.trim())) === "Policy") {
        await btn.click();
        break;
      }
    }
    await page.waitForSelector(".policy-editor select", { timeout: 2000 });
    const persistedValue = await page.$eval(".policy-editor select", (el) => el.value);
    check("saved policy field actually persisted server-side (survives a full page reload)", persistedValue === "strict", persistedValue);

    // --- Delete client (real destructive action; native confirm() handled by wirePage's dialog handler) ---
    check("Delete button exists", await clickActionButton("Delete"));
    await new Promise((r) => setTimeout(r, 300));
    const clientRowsAfterDelete = await page.$$eval("[data-grid-id='managed-clients'] tbody tr:not(.empty-row)", (rows) => rows.length);
    check("deleting a client actually removes its row", clientRowsAfterDelete === 0, `rows=${clientRowsAfterDelete}`);

    // --- Nav: Clients & Access (global policy + networks) ---
    const clickedPolicies = await clickNavItem(page, (t) => t === "Clients & Access");
    check("Clients & Access nav item exists and is clickable", clickedPolicies);
    await page.waitForSelector("#clients-access-heading", { timeout: 3000 }).catch(() => {});
    check("Clients & Access page content rendered (not a Coming Soon placeholder)", (await page.$("#clients-access-heading")) !== null);
    check("Global Policy editor renders on Clients & Access", (await page.$(".clients-access .policy-editor")) !== null);

    await page.type(".add-form input[required]", "192.168.50.0/24");
    await Promise.all([
      page.waitForFunction(() => document.querySelector(".networks-list") !== null, { timeout: 3000 }),
      page.click(".add-form button[type=submit]"),
    ]);
    const networkListText = await page.$eval(".networks-list", (el) => el.textContent);
    check("adding a network adds a real entry to the network list", networkListText.includes("192.168.50.0/24"), networkListText);

    await page.click(".networks-list .scope-row button");
    await page.waitForSelector(".networks-list .policy-editor select", { timeout: 2000 }).catch(() => {});
    check("a network's own Policy button opens its per-network policy editor", (await page.$(".networks-list .policy-editor")) !== null);

    // --- Nav: Filters (custom rules + global policy) ---
    const clickedFilters = await clickNavItem(page, (t) => t === "Filters");
    check("Filters nav item exists and is clickable", clickedFilters);
    await page.waitForSelector("#filtering-heading", { timeout: 3000 }).catch(() => {});
    check("Filters page content rendered", (await page.$("#filtering-heading")) !== null);
    check("Global Answer Policy editor renders on Filters", (await page.$(".policy-editor")) !== null);

    // Add a block rule, then a rewrite rule (exercises the conditional field).
    await page.select(".add-form select", "block");
    await page.type('.add-form input[placeholder*="example.com"]', "ads.example.com");
    await Promise.all([
      page.waitForFunction(() => document.querySelectorAll(".data-grid tbody .actions").length > 0, { timeout: 3000 }),
      page.click(".add-form button[type=submit]"),
    ]);
    let ruleRows = await page.$$eval(".data-grid tbody tr", (rows) => rows.length);
    check("adding a custom rule adds a real row", ruleRows === 1, `rows=${ruleRows}`);

    await page.select(".add-form select", "rewrite");
    await page.waitForSelector('.add-form input[placeholder="10.0.0.5"]', { timeout: 2000 });
    const patternInputs = await page.$$(".add-form input");
    await patternInputs[0].type("internal.example.com");
    await patternInputs[1].type("10.0.0.9");
    await Promise.all([
      page.waitForFunction(() => document.querySelectorAll(".data-grid tbody tr").length > 1, { timeout: 3000 }),
      page.click(".add-form button[type=submit]"),
    ]);
    const rowsText = await page.$eval(".data-grid tbody", (el) => el.textContent);
    check("rewrite rule shows its target inline (pattern -> target)", rowsText.includes("internal.example.com") && rowsText.includes("10.0.0.9"), rowsText);

    // Bulk select both rules and disable them.
    const ruleCheckboxes = await page.$$(".data-grid tbody input[type=checkbox]");
    for (const cb of ruleCheckboxes) await cb.click();
    await page.waitForSelector(".bulk-bar", { timeout: 2000 });
    const bulkButtons = await page.$$(".bulk-bar button");
    for (const btn of bulkButtons) {
      if ((await btn.evaluate((el) => el.textContent?.trim())) === "Disable") {
        await btn.click();
        break;
      }
    }
    await new Promise((r) => setTimeout(r, 300));
    const disabledCount = await page.$$eval(".data-grid tbody tr.row-pending", (rows) => rows.length);
    check("bulk-disable actually disabled both selected rules", disabledCount === 2, `disabled=${disabledCount}`);

    // --- Nav: Encryption (internal/dnstransports + internal/tlscert) ---
    const clickedEncryption = await clickNavItem(page, (t) => t === "Encryption");
    check("Encryption nav item exists and is clickable", clickedEncryption);
    await page.waitForSelector("#encryption-heading", { timeout: 3000 }).catch(() => {});
    check("Encryption page content rendered", (await page.$("#encryption-heading")) !== null);

    // TLS status renders real data (harness always starts the server with
    // -tls-cert-status-path pointed at a real certificate -- see main()).
    await page.waitForSelector(".cert-info", { timeout: 3000 }).catch(() => {});
    const certSubject = await page.$eval(".cert-info dd", (el) => el.textContent).catch(() => "");
    check("TLS status renders a real certificate subject, not the unavailable placeholder", certSubject.includes("CN="), certSubject);

    // DoT toggle + port round-trip through a real save.
    const dotCheckbox = await page.$(".transports fieldset:nth-of-type(1) input[type=checkbox]");
    await dotCheckbox.click();
    const dotPortInput = await page.$(".transports fieldset:nth-of-type(1) input[type=number]");
    // Triple-click-to-select-all is unreliable on a number input in
    // headless Chromium -- a real bug this caught: it left "853" in
    // place and typing appended "8853" after it, producing "8538853",
    // which silently failed the input's max="65535" constraint and
    // blocked the native form submission with no visible error. Clear
    // the value directly instead, same pattern already used elsewhere
    // in this file for text inputs.
    await page.$eval(".transports fieldset:nth-of-type(1) input[type=number]", (el) => (el.value = ""));
    await dotPortInput.type("8853");
    await Promise.all([
      page.waitForSelector(".transports .success", { timeout: 3000 }),
      page.click(".transports button[type=submit]"),
    ]);
    const saveText = await page.$eval(".transports .success", (el) => el.textContent);
    check("saving DNS Transport settings reports success", saveText.includes("Saved"), saveText);

    await page.reload({ waitUntil: "networkidle0" });
    await page.waitForSelector(".transports", { timeout: 3000 });
    const dotPortAfterReload = await page.$eval(".transports fieldset:nth-of-type(1) input[type=number]", (el) => el.value);
    const dotCheckedAfterReload = await page.$eval(".transports fieldset:nth-of-type(1) input[type=checkbox]", (el) => el.checked);
    check("DNS Transport settings actually persisted server-side (survive a full page reload)", dotPortAfterReload === "8853" && dotCheckedAfterReload === true, `port=${dotPortAfterReload} checked=${dotCheckedAfterReload}`);

    // --- Nav: Statistics (internal/pyanalytics.ExportAll) ---
    const clickedStatistics = await clickNavItem(page, (t) => t === "Statistics");
    check("Statistics nav item exists and is clickable", clickedStatistics);
    await page.waitForSelector("#statistics-heading", { timeout: 3000 }).catch(() => {});
    check("Statistics page content rendered", (await page.$("#statistics-heading")) !== null);
    const exportHref = await page.$eval(".export-link", (el) => el.getAttribute("href")).catch(() => null);
    check("Statistics export link points at the real export endpoint", exportHref === "/api/statistics/export", exportHref);

    // --- Nav: Notifications (internal/notifications, native storage, no secrets) ---
    const clickedNotifications = await clickNavItem(page, (t) => t === "Notifications");
    check("Notifications nav item exists and is clickable", clickedNotifications);
    await page.waitForSelector("#notifications-heading", { timeout: 3000 }).catch(() => {});
    check("Notifications page content rendered", (await page.$("#notifications-heading")) !== null);

    // Stale test note: this form used to have a plain "Endpoint" field
    // with no privileged dependency; the real 2026-08-28 Credentials
    // rework moved the secret into a SEPARATE, second API call
    // (createProvider() creates the provider, then a follow-up
    // setNotificationSecret() call seals the credential) that runs
    // entirely inside apdns-hostagent -- this suite deliberately has no
    // hostagent (see its own header comment: it targets the app.js/
    // nav.ts shell, not the host-control boundary; Cache/Replication/
    // Network/Logs/Software-Updates are already correctly left to the
    // dedicated `hostagent_smoke.mjs`, and Notifications' credential
    // path is the same boundary, covered by the dedicated
    // `notifications_smoke.mjs` instead). Typing into the credential
    // field here would make createProvider's own second call throw
    // (hostagent unavailable) and swallow the whole submit's success
    // silently -- a real trap this test used to walk straight into,
    // not a product bug: a provider legitimately can, and here should,
    // exist with no credential set yet.
    await page.select(".add-form select", "slack");
    await page.type('.add-form input[aria-label="Display name"]', "Ops Slack");
    await Promise.all([
      page.waitForFunction(() => document.querySelectorAll(".data-grid tbody .actions").length > 0, { timeout: 3000 }),
      page.click(".add-form button[type=submit]"),
    ]);
    let notificationRows = await page.$$eval(".data-grid tbody tr", (rows) => rows.length);
    check("adding a notification provider adds a real row", notificationRows === 1, `rows=${notificationRows}`);
    const providerRowText = await page.$eval(".data-grid tbody", (el) => el.textContent);
    check("notification provider row shows the real display name and an honest 'Not set' credential state (no hostagent in this fixture)", providerRowText.includes("Ops Slack") && providerRowText.includes("Not set"), providerRowText);

    await page.click(".data-grid tbody .actions button"); // "Disable"
    await new Promise((r) => setTimeout(r, 200));
    const enabledCellText = await page.$eval(".data-grid tbody tr", (el) => el.textContent);
    check("disabling a notification provider updates its Enabled cell to No", enabledCellText.includes("No"), enabledCellText);

    // A real fix proven here: creating a provider WITH a credential in
    // this hostagent-less fixture makes the secret-seal call genuinely
    // fail, but the provider row itself was still really created --
    // the grid must still show it (not silently keep the pre-creation
    // list) alongside a clear error explaining exactly what failed.
    await page.type('.add-form input[aria-label="Display name"]', "No Hostagent Here");
    await page.type(".add-form [data-secret-input]", "https://hooks.slack.example/will-fail");
    await Promise.all([
      page.waitForFunction(() => document.querySelectorAll(".data-grid tbody tr").length === 2, { timeout: 3000 }),
      page.click(".add-form button[type=submit]"),
    ]);
    const rowsAfterFailedSecret = await page.$$eval(".data-grid tbody tr", (rows) => rows.length);
    check("a provider whose credential-seal call fails still shows its real, already-created row (not silently dropped)", rowsAfterFailedSecret === 2, `rows=${rowsAfterFailedSecret}`);
    const createErrorText = await page.$eval(".notifications .error", (el) => el.textContent).catch(() => "");
    check("the real partial-failure is explained, not hidden behind a generic error", createErrorText.includes("No Hostagent Here") && createErrorText.includes("credential"), createErrorText);

    // --- DataGrid mechanics (sort/resize/persist), proven here against
    // this page's real "notification-providers" grid -- moved off
    // Dashboard's Top Domains grid, which this fixture cannot populate
    // without a real dnstap writer (see the honest-degraded checks
    // above). DataGrid is one shared component used by every table in
    // this app, so proving its own sort/resize/persist mechanics here,
    // against 2 real, distinctly-named rows, is the same proof. ---
    const notifGrid = '[data-grid-id="notification-providers"]';
    const firstNameBefore = await page.$eval(`${notifGrid} tbody tr:first-child td:first-child`, (el) => el.textContent).catch(() => null);
    const nameHeaderBtn = await page.$(`${notifGrid} thead .sort-btn`);
    if (nameHeaderBtn) await nameHeaderBtn.click();
    await new Promise((r) => setTimeout(r, 80));
    const firstNameAfterAsc = await page.$eval(`${notifGrid} tbody tr:first-child td:first-child`, (el) => el.textContent).catch(() => null);
    if (nameHeaderBtn) await nameHeaderBtn.click(); // toggle to descending
    await new Promise((r) => setTimeout(r, 80));
    const firstNameAfterDesc = await page.$eval(`${notifGrid} tbody tr:first-child td:first-child`, (el) => el.textContent).catch(() => null);
    check(
      "clicking a DataGrid sortable header actually changes row order (asc, then desc)",
      firstNameBefore !== null && firstNameAfterAsc !== null && firstNameAfterDesc !== null && (firstNameAfterAsc !== firstNameBefore || firstNameAfterAsc !== firstNameAfterDesc),
      `before=${firstNameBefore} asc=${firstNameAfterAsc} desc=${firstNameAfterDesc}`,
    );

    const notifTh = await page.$(`${notifGrid} thead th`);
    const notifHandle = await page.$(`${notifGrid} thead th .resize-handle`);
    if (notifTh && notifHandle) {
      const widthBefore = await notifTh.evaluate((el) => el.getBoundingClientRect().width);
      const box = await notifHandle.boundingBox();
      await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
      await page.mouse.down();
      await page.mouse.move(box.x + box.width / 2 + 120, box.y + box.height / 2, { steps: 5 });
      await page.mouse.up();
      await new Promise((r) => setTimeout(r, 80));
      const widthAfter = await notifTh.evaluate((el) => el.getBoundingClientRect().width);
      check("dragging a DataGrid column's resize handle actually changes its width", widthAfter > widthBefore + 50, `before=${widthBefore} after=${widthAfter}`);

      // Reload and confirm the resized width persisted (localStorage, per gridId).
      await page.reload({ waitUntil: "networkidle0" });
      await page.waitForSelector(`${notifGrid} thead th`, { timeout: 3000 });
      const notifThAfterReload = await page.$(`${notifGrid} thead th`);
      const widthAfterReload = await notifThAfterReload.evaluate((el) => el.getBoundingClientRect().width);
      check("resized column width persists across a full page reload", widthAfterReload > widthBefore + 50, `original=${widthBefore} afterReload=${widthAfterReload}`);
    } else {
      check("DataGrid resize handle present to test drag-resize", false, "th or handle not found");
    }

    // --- Nav: Import (internal/importer -- real preview/select/apply/rollback job workflow) ---
    const clickedImport = await clickNavItem(page, (t) => t === "Import");
    check("Import nav item exists and is clickable", clickedImport);
    await page.waitForSelector("#importexport-heading", { timeout: 3000 }).catch(() => {});
    check("Import page content rendered", (await page.$("#importexport-heading")) !== null);

    await page.type('textarea[aria-label="Hosts file contents"]', "10.0.0.42 chromium-import-test.lan");
    await Promise.all([
      page.waitForSelector(".plan-table tbody tr", { timeout: 3000 }),
      page.click('.card button[type=submit]'),
    ]);
    const planRowText = await page.$eval(".plan-table tbody", (el) => el.textContent);
    check("previewing a hosts file shows a real planned row before anything is written", planRowText.includes("chromium-import-test.lan"), planRowText);

    await Promise.all([
      page.waitForSelector(".success[role=status]", { timeout: 3000 }),
      page.click('.card .actions button:not(.danger)'),
    ]);
    const importResultText = await page.$eval(".success[role=status]", (el) => el.textContent);
    check("applying the import job reports a real imported count", importResultText.includes("1") && importResultText.includes("imported"), importResultText);
    check("the applied job shows a rollback option (a real pre-apply snapshot was taken)", (await page.$(".card .danger")) !== null);

    // The imported record should now be a real row on Local DNS.
    await clickNavItem(page, (t) => t === "Local DNS");
    await page.waitForSelector("#localdns-heading", { timeout: 3000 });
    await page.waitForFunction(() => document.querySelector(".data-grid tbody")?.textContent?.includes("chromium-import-test.lan"), { timeout: 3000 }).catch(() => {});
    const localDnsText = await page.$eval(".data-grid tbody", (el) => el.textContent);
    check("the hosts-file import created a real Local DNS record", localDnsText.includes("chromium-import-test.lan"), localDnsText);

    // --- Nav: Backup & Restore ---
    const clickedBackup = await clickNavItem(page, (t) => t === "Backup & Restore");
    check("Backup & Restore nav item exists and is clickable", clickedBackup);
    await page.waitForSelector("#backup-heading", { timeout: 3000 }).catch(() => {});
    check("Backup & Restore page content rendered", (await page.$("#backup-heading")) !== null);

    // Create a real backup. Waiting for "any .actions cell exists" is
    // not enough here, and not just for the empty-state-<tr> reason
    // already found and fixed for Upstreams earlier in this file: this
    // fixture's own earlier Import section (hosts-file apply) already
    // created ONE real pre-existing backup of its own (internal/
    // importer's real pre-apply safety snapshot, s.Backup.Create -- see
    // main.go's "Backup: backupSvc" wiring into importerSvc) before
    // this section ever runs. A real bug this found: waiting for "any
    // row with .actions" is satisfied immediately by that pre-existing
    // row, racing ahead of this click's own real POST and asserting
    // "rows===1" as if only the fixture's start state existed -- fixed
    // by waiting for the count to genuinely increase from its own
    // captured baseline instead of assuming what that baseline is.
    // Scoped to [data-grid-id="appliance-backups"] specifically -- this
    // page has a SECOND, separate DataGrid (Secret Backups) with its
    // own empty-state <tr>, and a bare ".data-grid" selector counts
    // rows across BOTH grids at once, a real test bug found live (an
    // appliance-backup create reported "rows=2": 1 real row plus Secret
    // Backups' own unrelated empty-state row).
    const applianceBackupsGrid = '[data-grid-id="appliance-backups"]';
    const rowsBeforeCreate = await page.$$eval(`${applianceBackupsGrid} tbody tr:not(.empty-row)`, (rows) => rows.length);
    const createBackupBtn = await page.$(".card button");
    await Promise.all([
      page.waitForFunction(
        (sel, before) => document.querySelectorAll(`${sel} tbody tr:not(.empty-row)`).length > before,
        { timeout: 5000 }, applianceBackupsGrid, rowsBeforeCreate,
      ),
      createBackupBtn.click(),
    ]);
    const backupRows = await page.$$eval(`${applianceBackupsGrid} tbody tr:not(.empty-row)`, (rows) => rows.length);
    check("creating a backup adds a real row to the list", backupRows === rowsBeforeCreate + 1, `before=${rowsBeforeCreate} after=${backupRows}`);

    // Restore requires typing the exact filename to confirm -- the button
    // must stay disabled until the typed text matches exactly.
    await page.click(`${applianceBackupsGrid} tbody .actions button`); // "Restore…"
    await page.waitForSelector(".restore-confirm", { timeout: 2000 });
    const filenameText = await page.$eval(".restore-confirm code", (el) => el.textContent.trim());
    const confirmBtnDisabledBefore = await page.$eval(".restore-confirm .danger", (el) => el.disabled);
    check("restore confirm button is disabled before typing the filename", confirmBtnDisabledBefore);
    await page.type(".restore-confirm input.filename-confirm", "wrong-filename.tar");
    const stillDisabled = await page.$eval(".restore-confirm .danger", (el) => el.disabled);
    check("restore confirm button stays disabled for a non-matching filename", stillDisabled);
    await page.$eval(".restore-confirm input.filename-confirm", (el) => (el.value = ""));
    await page.type(".restore-confirm input.filename-confirm", filenameText);
    const nowEnabled = await page.$eval(".restore-confirm .danger", (el) => !el.disabled);
    check("restore confirm button enables once the typed filename matches exactly", nowEnabled);

    // Selective restore: the category picker defaults to every category
    // checked; unchecking all of them must re-disable the confirm button
    // even though the filename still matches, and rechecking restores it.
    const categoryCheckboxes = await page.$$(".category-picker input[type=checkbox]");
    check("restore dialog renders a per-category picker", categoryCheckboxes.length > 0, `count=${categoryCheckboxes.length}`);
    const allCheckedInitially = await page.$$eval(".category-picker input[type=checkbox]", (els) => els.every((el) => el.checked));
    check("every category is checked by default (full restore)", allCheckedInitially);
    for (const cb of categoryCheckboxes) await cb.click(); // uncheck every category
    const disabledWithNoCategories = await page.$eval(".restore-confirm .danger", (el) => el.disabled);
    check("restore confirm button disables again when no category is selected", disabledWithNoCategories);
    for (const cb of categoryCheckboxes) await cb.click(); // recheck every category
    const enabledAgain = await page.$eval(".restore-confirm .danger", (el) => !el.disabled);
    check("restore confirm button re-enables once at least one category is selected", enabledAgain);

    await Promise.all([
      page.waitForSelector(".success", { timeout: 5000 }),
      page.click(".restore-confirm .danger"),
    ]);
    const successText = await page.$eval(".success", (el) => el.textContent);
    check("restoring reports the automatic safety backup by name", successText.includes("safety backup"), successText);
    const rowsAfterRestore = await page.$$eval(`${applianceBackupsGrid} tbody tr:not(.empty-row)`, (rows) => rows.length);
    check("the safety backup taken during restore appears in the list too", rowsAfterRestore === backupRows + 1, `before-restore=${backupRows} after-restore=${rowsAfterRestore}`);

    // --- Systematic viewport sweep: every implemented route x desktop/tablet/mobile x light/dark ---
    const VIEWPORTS = [
      { name: "desktop-1440", width: 1440, height: 900 },
      { name: "tablet-1024", width: 1024, height: 900 },
      { name: "mobile-390", width: 390, height: 844 },
    ];
    const ROUTES = [
      { path: "/ui/dashboard", heading: "#dashboard-heading" },
      { path: "/ui/analytics", heading: "#analytics-heading" },
      { path: "/ui/blocklists", heading: "#blocklists-heading" },
      { path: "/ui/localdns", heading: "#localdns-heading" },
      { path: "/ui/upstreams", heading: "#upstreams-heading" },
      { path: "/ui/clients", heading: "#clients-heading" },
      { path: "/ui/policies", heading: "#clients-access-heading" },
      { path: "/ui/filtering", heading: "#filtering-heading" },
      { path: "/ui/encryption", heading: "#encryption-heading" },
      { path: "/ui/backup", heading: "#backup-heading" },
      { path: "/ui/statistics", heading: "#statistics-heading" },
      { path: "/ui/health", heading: "#health-heading" },
      { path: "/ui/notifications", heading: "#notifications-heading" },
      { path: "/ui/importexport", heading: "#importexport-heading" },
      { path: "/ui/administration", heading: "#admin-heading" },
    ];
    for (const theme of ["light", "dark"]) {
      const currentTheme = await page.$eval("html", (el) => el.getAttribute("data-theme"));
      if (currentTheme !== theme) {
        await page.click(".theme-toggle");
        await new Promise((r) => setTimeout(r, 50));
      }
      for (const vp of VIEWPORTS) {
        // Recycle the page every viewport block (8 navigations each,
        // well short of whatever this host's real ceiling is) instead
        // of letting one tab accumulate the whole sweep's navigations.
        // The new page shares the same browser context, so both the
        // login session's cookies AND the theme choice (persisted in
        // localStorage, same origin) carry over automatically -- no
        // re-auth, no re-toggle needed.
        await page.close();
        page = await browser.newPage();
        wirePage(page);
        await page.goto(baseUrl, { waitUntil: "networkidle0" });
        await page.setViewport({ width: vp.width, height: vp.height });
        for (const route of ROUTES) {
          await page.goto(`${baseUrl}${route.path}`, { waitUntil: "networkidle0" });
          await page.waitForSelector(route.heading, { timeout: 3000 }).catch(() => {});
          const hasHeading = (await page.$(route.heading)) !== null;
          const overflowX = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth + 1);
          check(`${route.path} @ ${vp.name} / ${theme}: real content renders, no horizontal overflow`, hasHeading && !overflowX, `heading=${hasHeading} overflow=${overflowX}`);
        }
      }
    }
    await page.setViewport({ width: 1440, height: 900 });

    // --- Console/runtime errors across the whole pass ---
    // Chromium itself (not app code) logs a "Failed to load resource:
    // ... status of 4xx/5xx" console entry for every non-2xx fetch --
    // unavoidable browser behavior, not something the app controls, and
    // *expected* here because this pass deliberately exercises negative
    // paths (wrong password, missing CSRF elsewhere). Only a real
    // application console.error (anything else) counts as a defect.
    const unexpectedConsoleErrors = consoleErrors.filter((e) => !/Failed to load resource: the server responded with a status of/.test(e));
    check("zero unexpected browser console errors across the whole pass", unexpectedConsoleErrors.length === 0, unexpectedConsoleErrors.join(" | "));
    check("zero uncaught page errors across the whole pass", pageErrors.length === 0, pageErrors.join(" | "));
  } finally {
    await browser.close();
  }

  const failed = results.filter((r) => !r.pass);
  console.log(`\n${results.length - failed.length}/${results.length} checks passed.`);
  process.exit(failed.length > 0 ? 1 : 0);
}

main().catch((err) => {
  console.error("HARNESS ERROR:", err);
  process.exit(1);
});
