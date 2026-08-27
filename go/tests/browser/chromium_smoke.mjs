// Real-Chromium smoke coverage for the Go/Svelte shell + whatever pages
// are wired in nav.ts. Run against a fresh instance (setup_required=true)
// -- see go/tests/browser/README.md. Not a mock: drives an actual
// headless Chromium via CDP (puppeteer-core, pointed at the system
// /usr/bin/chromium -- no bundled download).
//
// Usage: node chromium_smoke.mjs <base-url> <username> <password>
import puppeteer from "puppeteer-core";

const [, , baseUrl, username, password] = process.argv;
if (!baseUrl || !username || !password) {
  console.error("usage: node chromium_smoke.mjs <base-url> <username> <password>");
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
  }

  try {
    let page = await browser.newPage();
    wirePage(page);

    await page.setViewport({ width: 1440, height: 900 });
    await page.goto(baseUrl, { waitUntil: "networkidle0" });

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
    const scopeNote = await page.$eval(".scope-note", (el) => el.textContent).catch(() => "");
    check(
      "Dashboard discloses its own incomplete scope rather than implying full parity",
      scopeNote.replace(/\s+/g, " ").includes("compatibility boundaries"),
      scopeNote,
    );

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
    check("Dashboard Upstreams mini-panel renders real upstream profile rows", upstreamsCardRows > 0, `rows=${upstreamsCardRows}`);

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
    await new Promise((r) => setTimeout(r, 400));
    const chartSvg = await page.$(".wide-card svg");
    check("DNS Activity chart renders an SVG after selecting a real historical range", chartSvg !== null);
    const chartPathCount = chartSvg ? await page.$$eval(".wide-card svg path.line", (els) => els.length) : 0;
    check("chart draws both the total and blocked line series", chartPathCount === 2, `found ${chartPathCount}`);

    // --- Dashboard: Top Domains (real data from the snapshot) ---
    await page.waitForSelector(".card .data-grid", { timeout: 3000 }).catch(() => {});
    const topDomainRows = await page.$$eval(".card .data-grid tbody tr", (rows) => rows.length).catch(() => 0);
    check("Top Domains grid renders real rows from the analytics boundary", topDomainRows > 0, `found ${topDomainRows}`);

    // --- DataGrid: clicking a sortable header actually reorders rows (not just cosmetic) ---
    const firstDomainBefore = await page.$eval(".card .data-grid tbody tr:first-child td:first-child", (el) => el.textContent).catch(() => null);
    const domainHeaderBtn = await page.$(".card .data-grid thead .sort-btn");
    if (domainHeaderBtn) await domainHeaderBtn.click();
    await new Promise((r) => setTimeout(r, 80));
    const firstDomainAfterAsc = await page.$eval(".card .data-grid tbody tr:first-child td:first-child", (el) => el.textContent).catch(() => null);
    if (domainHeaderBtn) await domainHeaderBtn.click(); // toggle to descending
    await new Promise((r) => setTimeout(r, 80));
    const firstDomainAfterDesc = await page.$eval(".card .data-grid tbody tr:first-child td:first-child", (el) => el.textContent).catch(() => null);
    check(
      "clicking a DataGrid sortable header actually changes row order (asc, then desc)",
      firstDomainBefore !== null && firstDomainAfterAsc !== null && firstDomainAfterDesc !== null && (firstDomainAfterAsc !== firstDomainBefore || firstDomainAfterAsc !== firstDomainAfterDesc),
      `before=${firstDomainBefore} asc=${firstDomainAfterAsc} desc=${firstDomainAfterDesc}`,
    );

    // --- DataGrid: column drag-resize actually changes the column's width ---
    const th = await page.$(".card .data-grid thead th");
    const handle = await page.$(".card .data-grid thead th .resize-handle");
    if (th && handle) {
      const widthBefore = await th.evaluate((el) => el.getBoundingClientRect().width);
      const box = await handle.boundingBox();
      await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
      await page.mouse.down();
      await page.mouse.move(box.x + box.width / 2 + 120, box.y + box.height / 2, { steps: 5 });
      await page.mouse.up();
      await new Promise((r) => setTimeout(r, 80));
      const widthAfter = await th.evaluate((el) => el.getBoundingClientRect().width);
      check("dragging a DataGrid column's resize handle actually changes its width", widthAfter > widthBefore + 50, `before=${widthBefore} after=${widthAfter}`);

      // Reload and confirm the resized width persisted (localStorage, per gridId).
      await page.reload({ waitUntil: "networkidle0" });
      await page.waitForSelector(".card .data-grid thead th", { timeout: 3000 });
      const thAfterReload = await page.$(".card .data-grid thead th");
      const widthAfterReload = await thAfterReload.evaluate((el) => el.getBoundingClientRect().width);
      check("resized column width persists across a full page reload", widthAfterReload > widthBefore + 50, `original=${widthBefore} afterReload=${widthAfterReload}`);
    } else {
      check("DataGrid resize handle present to test drag-resize", false, "th or handle not found");
    }

    // --- Dashboard: Top Blocked Domains is real when -query-log-dir is
    // configured (this harness always starts the server that way -- see
    // main()). The honest-degraded path for when it's NOT configured is
    // exercised by acceptance.py instead (no browser needed for that
    // shape), so this isn't duplicated here.
    const blockedDomainRowsFn = () => {
      const h3 = [...document.querySelectorAll("h3")].find((e) => e.textContent?.includes("Top Blocked Domains"));
      const card = h3?.closest(".card");
      return card ? card.querySelectorAll(".data-grid tbody tr:not(.empty-row)").length : -1;
    };
    const blockedDomainCards = await page.$$eval("h3", (els) => els.filter((e) => e.textContent?.includes("Top Blocked Domains")).length);
    check("Top Blocked Domains card renders on the Dashboard", blockedDomainCards === 1, `count=${blockedDomainCards}`);
    await page.waitForFunction(blockedDomainRowsFn, { timeout: 3000 }).catch(() => {});
    const blockedRows = await page.evaluate(blockedDomainRowsFn);
    check("Top Blocked Domains renders real rows, not the honest-unavailable placeholder", blockedRows > 0, `rows=${blockedRows}`);

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

    // --- Nav: Query Log (internal/rawquerylog -- raw Parquet compatibility boundary) ---
    const clickedQueryLog = await clickNavItem(page, (t) => t === "Query Log");
    check("Query Log nav item exists and is clickable", clickedQueryLog);
    await page.waitForSelector("#analytics-heading", { timeout: 3000 }).catch(() => {});
    check("Query Log page content rendered", (await page.$("#analytics-heading")) !== null);

    // Real rows from the seeded fixture (started with -query-log-dir
    // pointed at go/tests/fixtures/make_query_log_fixture.py's output),
    // not a mocked/empty grid. `:not(.empty-row)` excludes the DataGrid's
    // own pre-existing placeholder row -- the same race-condition class
    // already found and fixed for Upstreams/Backup/Filters elsewhere in
    // this file, closed more generally here since Query Log's grid has
    // no per-row .actions cell to key off of instead.
    await page.waitForFunction(() => document.querySelectorAll(".data-grid tbody tr:not(.empty-row)").length > 0, { timeout: 5000 }).catch(() => {});
    let queryLogRows = await page.$$eval(".data-grid tbody tr:not(.empty-row)", (rows) => rows.length);
    check("Query Log grid renders real rows from the raw Parquet fixture", queryLogRows === 3, `rows=${queryLogRows}`);

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
    const statusValue = await page.$eval(".metric .status-ok", (el) => el.textContent).catch(() => null);
    check("System Status metric strip renders a real component status", statusValue === "ok", statusValue);
    // Navigating here at all is itself a route change perfLog should have
    // recorded -- plus every route visited earlier in this run.
    const perfRowCount = await page.$$eval(".perf-table tbody tr", (rows) => rows.length).catch(() => 0);
    check("UI Performance table records real navigation latency entries", perfRowCount > 3, `rows=${perfRowCount}`);
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

    // --- Nav: Clients ---
    const clickedClients = await clickNavItem(page, (t) => t === "Clients");
    check("Clients nav item exists and is clickable", clickedClients);
    await page.waitForSelector("#clients-heading", { timeout: 3000 }).catch(() => {});
    check("Clients page content rendered", (await page.$("#clients-heading")) !== null);

    // Create a group first (needed for the "assign group" workflow below).
    const groupForms = await page.$$(".add-form");
    await (await groupForms[1].$("input[required]")).type("Kids");
    await Promise.all([
      page.waitForFunction(() => document.querySelector(".group-list") !== null || /No groups/.test(document.body.textContent), { timeout: 3000 }),
      groupForms[1].$eval("button[type=submit]", (el) => el.click()),
    ]);
    await new Promise((r) => setTimeout(r, 300));
    const groupListText = await page.$eval(".group-list", (el) => el.textContent).catch(() => "");
    check("creating a group adds a real entry to the group list", groupListText.includes("Kids"), groupListText);

    // Create a managed client.
    const clientForm = (await page.$$(".add-form"))[0];
    await (await clientForm.$("input[required]")).type("Test Client");
    await Promise.all([
      page.waitForFunction(() => document.querySelectorAll(".data-grid tbody tr").length > 0 && document.querySelector(".data-grid tbody .actions"), { timeout: 3000 }),
      clientForm.$eval("button[type=submit]", (el) => el.click()),
    ]);
    await new Promise((r) => setTimeout(r, 200));
    const clientRows = await page.$$eval(".data-grid tbody tr", (rows) => rows.length);
    check("creating a managed client adds a real row to the grid", clientRows === 1, `rows=${clientRows}`);

    // Add an identifier: invalid first (must be rejected), then valid.
    // Looked up by its actual label rather than array index -- action
    // button order isn't a stable contract.
    async function clickActionButton(label) {
      for (const btn of await page.$$(".data-grid tbody .actions button")) {
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
      page.waitForFunction(() => document.querySelector(".chips") && /10\.0\.0\.5/.test(document.querySelector(".data-grid tbody").textContent), { timeout: 3000 }),
      page.click(".inline-form button[type=submit]"),
    ]);
    const chipsText = await page.$eval(".data-grid tbody .chips", (el) => el.textContent);
    check("a valid identifier actually appears on the client row after saving", chipsText.includes("10.0.0.5"), chipsText);

    // --- Full managed-client lifecycle: edit, enable/disable, remove
    // from group, delete identifier, delete client ---
    check("Assign group button exists", await clickActionButton("Assign group"));
    await page.waitForSelector(".inline-form select", { timeout: 2000 });
    await Promise.all([
      // Waits for a real rendered chip, not just "Kids" appearing anywhere
      // (the still-open assign-group <select>'s own <option> already
      // contains the text "Kids" before the mutation completes).
      page.waitForFunction(() => [...document.querySelectorAll(".data-grid tbody .chips .chip")].some((c) => c.textContent.includes("Kids")), { timeout: 3000 }),
      page.click(".inline-form button[type=submit]"),
    ]);
    const groupsChipText = await page.$eval(".data-grid tbody", (el) => el.textContent);
    check("assigning a group actually shows it on the client row", groupsChipText.includes("Kids"), groupsChipText);

    check("Edit button exists", await clickActionButton("Edit"));
    await page.waitForSelector(".edit-name-form input", { timeout: 2000 });
    const editInputs = await page.$$(".edit-name-form input");
    await editInputs[0].click({ clickCount: 3 });
    await editInputs[0].type("Test Client Renamed");
    await Promise.all([
      page.waitForFunction(() => /Test Client Renamed/.test(document.querySelector(".data-grid tbody").textContent), { timeout: 3000 }),
      page.click(".edit-name-form button[type=submit]"),
    ]);
    const renamedText = await page.$eval(".data-grid tbody", (el) => el.textContent);
    check("editing a client's name actually persists and re-renders", renamedText.includes("Test Client Renamed"), renamedText);

    check("Disable button exists on a managed client", await clickActionButton("Disable"));
    await page.waitForSelector(".disabled-badge", { timeout: 3000 }).catch(() => {});
    check("disabling a client shows a real disabled badge", (await page.$(".disabled-badge")) !== null);
    check("Enable button exists after disabling", await clickActionButton("Enable"));
    await new Promise((r) => setTimeout(r, 200));
    check("re-enabling removes the disabled badge", (await page.$(".disabled-badge")) === null);

    // Remove the IPv4 identifier added above (its own chip-x, not the
    // Strong ClientID rows).
    const removedIdentifier = await page.evaluate(() => {
      const chip = [...document.querySelectorAll(".data-grid tbody .chips .chip")].find((c) => c.textContent.includes("10.0.0.5"));
      const btn = chip?.querySelector(".chip-x");
      if (!btn) return false;
      window.__confirmOverride = window.confirm;
      window.confirm = () => true;
      btn.click();
      return true;
    });
    check("identifier remove control exists and is clickable", removedIdentifier);
    await new Promise((r) => setTimeout(r, 300));
    const afterIdentifierRemoveText = await page.$eval(".data-grid tbody", (el) => el.textContent);
    check("removing an IP identifier actually removes it from the row", !afterIdentifierRemoveText.includes("10.0.0.5"), afterIdentifierRemoveText);

    // Remove from group (chip-x on the group chip).
    const removedFromGroup = await page.evaluate(() => {
      const chip = [...document.querySelectorAll(".data-grid tbody .chips .chip")].find((c) => c.textContent.includes("Kids"));
      const btn = chip?.querySelector(".chip-x");
      if (!btn) return false;
      btn.click();
      return true;
    });
    check("group remove control exists and is clickable", removedFromGroup);
    await new Promise((r) => setTimeout(r, 300));
    const afterGroupRemoveText = await page.$eval(".data-grid tbody", (el) => el.textContent);
    check("removing a client from a group actually removes it from the row", !afterGroupRemoveText.includes("Kids"), afterGroupRemoveText);

    // --- Observed Clients (real traffic-derived, honest empty state on
    // a fresh instance with no query history) ---
    const observedSectionText = await page.evaluate(() => {
      const h3s = [...document.querySelectorAll("h3")];
      const target = h3s.find((h) => h.textContent.trim() === "Observed Clients");
      return target ? target.nextElementSibling?.parentElement?.textContent ?? "" : null;
    });
    check("Observed Clients section renders on the Clients page", observedSectionText !== null, String(observedSectionText));

    // --- Per-client policy editor (shared PolicyEditor) ---
    const policyButtons = await page.$$(".data-grid tbody .actions button");
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
    const reopenButtons = await page.$$(".data-grid tbody .actions button");
    for (const btn of reopenButtons) {
      if ((await btn.evaluate((el) => el.textContent?.trim())) === "Policy") {
        await btn.click();
        break;
      }
    }
    await page.waitForSelector(".policy-editor select", { timeout: 2000 });
    const persistedValue = await page.$eval(".policy-editor select", (el) => el.value);
    check("saved policy field actually persisted server-side (survives a full page reload)", persistedValue === "strict", persistedValue);

    // --- Delete client (real destructive action; confirm() overridden above) ---
    check("Delete button exists", await clickActionButton("Delete"));
    await new Promise((r) => setTimeout(r, 300));
    const clientRowsAfterDelete = await page.$$eval(".data-grid tbody tr:not(.empty-row)", (rows) => rows.length);
    check("deleting a client actually removes its row", clientRowsAfterDelete === 0, `rows=${clientRowsAfterDelete}`);

    // --- Nav: Clients & Access (global policy + networks) ---
    const clickedPolicies = await clickNavItem(page, (t) => t === "Clients & Access");
    check("Clients & Access nav item exists and is clickable", clickedPolicies);
    await page.waitForSelector("#clients-access-heading", { timeout: 3000 }).catch(() => {});
    check("Clients & Access page content rendered (not a Coming Soon placeholder)", (await page.$("#clients-access-heading")) !== null);
    check("Global Policy editor renders on Clients & Access", (await page.$(".clients-access .policy-editor")) !== null);

    await page.type(".add-form input[required]", "192.168.50.0/24");
    await Promise.all([
      page.waitForFunction(() => document.querySelector(".network-list") !== null, { timeout: 3000 }),
      page.click(".add-form button[type=submit]"),
    ]);
    const networkListText = await page.$eval(".network-list", (el) => el.textContent);
    check("adding a network adds a real entry to the network list", networkListText.includes("192.168.50.0/24"), networkListText);

    await page.click(".network-row button");
    await page.waitForSelector(".network-list .policy-editor select", { timeout: 2000 }).catch(() => {});
    check("a network's own Policy button opens its per-network policy editor", (await page.$(".network-list .policy-editor")) !== null);

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

    await page.select(".add-form select", "slack");
    await page.type('.add-form input[aria-label="Display name"]', "Ops Slack");
    await page.type('.add-form input[aria-label="Endpoint"]', "https://hooks.slack.example/xyz");
    await Promise.all([
      page.waitForFunction(() => document.querySelectorAll(".data-grid tbody .actions").length > 0, { timeout: 3000 }),
      page.click(".add-form button[type=submit]"),
    ]);
    let notificationRows = await page.$$eval(".data-grid tbody tr", (rows) => rows.length);
    check("adding a notification provider adds a real row", notificationRows === 1, `rows=${notificationRows}`);
    const providerEndpointText = await page.$eval(".data-grid tbody", (el) => el.textContent);
    check("notification provider row shows the real endpoint", providerEndpointText.includes("https://hooks.slack.example/xyz"), providerEndpointText);

    await page.click(".data-grid tbody .actions button"); // "Disable"
    await new Promise((r) => setTimeout(r, 200));
    const enabledCellText = await page.$eval(".data-grid tbody tr", (el) => el.textContent);
    check("disabling a notification provider updates its Enabled cell to No", enabledCellText.includes("No"), enabledCellText);

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

    // Create a real backup. Wait for a real .actions cell, not just any
    // <tr> -- the grid's pre-existing empty-state row is also a <tr> and
    // would satisfy a naive "row count > 0" wait before the real backup
    // actually lands (the exact bug already found and fixed for Upstreams
    // earlier in this file).
    const createBackupBtn = await page.$(".card button");
    await Promise.all([
      page.waitForFunction(() => document.querySelectorAll(".data-grid tbody .actions").length > 0, { timeout: 5000 }),
      createBackupBtn.click(),
    ]);
    const backupRows = await page.$$eval(".data-grid tbody tr", (rows) => rows.length);
    check("creating a backup adds a real row to the list", backupRows === 1, `rows=${backupRows}`);

    // Restore requires typing the exact filename to confirm -- the button
    // must stay disabled until the typed text matches exactly.
    await page.click(".data-grid tbody .actions button"); // "Restore…"
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
    const rowsAfterRestore = await page.$$eval(".data-grid tbody tr", (rows) => rows.length);
    check("the safety backup taken during restore appears in the list too", rowsAfterRestore === 2, `rows=${rowsAfterRestore}`);

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
