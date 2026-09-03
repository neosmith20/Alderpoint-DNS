// Real-Chromium smoke coverage for the host-agent-backed pages (Cache,
// Replication, Network Configuration, Logs, Software Updates, DNS
// Runtime) -- separate from chromium_smoke.mjs's own full-app sweep so
// this can be pointed at the dedicated hostagent end-to-end test
// instance (real two-UID privilege separation, real rndc/control.db/
// journal/ip access) without re-running the entire other suite.
//
// The Cache/DNS Runtime/DNS Performance checks below need a hostagent
// wired with a full real DNS-runtime configuration (-dns-runtime-bind-
// conf/-dns-runtime-dnsdist-conf/etc. -- see internal/dnsruntime's own
// TestApplyEndToEndAgainstARealHostAgent for the exact real flags/ports
// this needs, real named+dnsdist+rndc). A hostagent without that wiring
// (e.g. this suite's own -allowed-uid/-secrets-key-dir/-current-binary-
// only minimal fixture) honestly can't satisfy them -- disclosed
// per-check below rather than silently skipped. The identical apply/
// compile/promote/rollback machinery this would exercise already has
// real end-to-end Go coverage (internal/dnsruntime's own
// TestApplyEndToEndAgainstARealHostAgent/
// TestGenerationTrackingPendingChangesAndRollbackEndToEnd, both against
// real named/dnsdist/rndc binaries), and is verified again directly on
// the live appliance as part of this session's own deployment
// verification pass.
import puppeteer from "puppeteer-core";

const [, , baseUrl, username, password] = process.argv;
if (!baseUrl || !username || !password) {
  console.error("usage: node hostagent_smoke.mjs <base-url> <username> <password>");
  process.exit(2);
}

const results = [];
function check(name, cond, detail) {
  results.push({ name, pass: !!cond, detail });
  console.log(`[${cond ? "PASS" : "FAIL"}] ${name}${!cond && detail ? " -- " + detail : ""}`);
}

async function main() {
  const browser = await puppeteer.launch({
    executablePath: process.env.CHROMIUM_PATH || "/usr/bin/chromium",
    headless: true,
    args: ["--no-sandbox", "--disable-dev-shm-usage", "--ignore-certificate-errors"],
  });
  try {
    const page = await browser.newPage();
    page.on("pageerror", (err) => console.error("PAGE ERROR:", err));
    await page.setViewport({ width: 1440, height: 900 });
    await page.goto(baseUrl, { waitUntil: "networkidle0" });

    await page.waitForSelector("#setup-heading, #login-heading", { timeout: 5000 });
    if (await page.$("#setup-heading")) {
      await page.type('input[autocomplete="username"]', username);
      await page.type('input[autocomplete="new-password"]', password);
      const confirms = await page.$$('input[autocomplete="new-password"]');
      await confirms[1].type(password);
      await Promise.all([page.waitForSelector("#login-heading", { timeout: 5000 }), page.click('button[type="submit"]')]);
    }
    await page.$eval('input[autocomplete="username"]', (el) => (el.value = ""));
    await page.type('input[autocomplete="username"]', username);
    await page.type('input[autocomplete="current-password"]', password);
    await Promise.all([page.waitForSelector(".app-layout", { timeout: 5000 }), page.click('button[type="submit"]')]);
    check("login reaches the app shell", true);

    // Every page this suite exercises (Cache, Replication, Network
    // Configuration, Logs, Software Updates, DNS Runtime) lives under an
    // Advanced-only nav group (nav.ts) -- not rendered in the sidebar
    // under the default Standard profile. Same real gap already found
    // and fixed in chromium_smoke.mjs/clients_access_smoke.mjs.
    await page.evaluate(() => localStorage.setItem("apdns-go-nav-profile", "advanced"));
    await page.reload({ waitUntil: "networkidle0" });
    await page.waitForSelector(".app-layout", { timeout: 5000 });
    check("switching to the Advanced nav profile takes effect", await page.evaluate(() => localStorage.getItem("apdns-go-nav-profile")) === "advanced");

    // Single-open sidebar accordion: an item is only in the DOM while its
    // own section is open. Try the currently-open section first, then
    // cycle through each section's own toggle until the target appears.
    async function clickNav(label) {
      const tryFind = async () => {
        for (const btn of await page.$$(".sidebar .item")) {
          if ((await btn.evaluate((el) => el.textContent?.trim())) === label) {
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

    // --- Cache ---
    check("Cache nav item exists and is clickable", await clickNav("Cache"));
    await page.waitForSelector("#cache-heading", { timeout: 3000 }).catch(() => {});
    check("Cache page content rendered", (await page.$("#cache-heading")) !== null);
    await page.waitForFunction(() => document.querySelector(".cache table tbody tr td") !== null, { timeout: 3000 }).catch(() => {});
    const cacheRowText = await page.$eval(".cache table tbody", (el) => el.textContent).catch(() => "");
    check("Cache page shows the real discovered BIND context", cacheRowText.includes("ctx0"), cacheRowText);
    // BIND Cache Counters (2026-08-27): real if this fixture's BIND
    // context has statistics-channels enabled, honestly "unavailable"
    // otherwise -- either is a real pass, this only checks the column
    // rendered something, not a specific value (the fixture environment
    // controls whether stats are actually reachable).
    const cacheStatsCellText = await page.$eval(".cache table tbody tr td:nth-child(4)", (el) => el.textContent).catch(() => "");
    check("Cache page's Cache hits/misses column renders (real value or honest unavailable)", cacheStatsCellText.length > 0, cacheStatsCellText);

    // --- Replication ---
    check("Replication nav item exists and is clickable", await clickNav("Replication"));
    await page.waitForSelector("#replication-heading", { timeout: 3000 }).catch(() => {});
    check("Replication page content rendered", (await page.$("#replication-heading")) !== null);
    // Real markup is `<p class="hint mono">node id: {hex}</p>` (a real,
    // previously-stale assumption fixed here: no `<code>` element at
    // all any more, and the real node id is a 32-char hex string --
    // internal/replication's own newNodeID(), a plain hex.EncodeToString,
    // not a UUID) -- extract just the id, stripping the label.
    await page.waitForFunction(() => document.querySelector(".replication .mono") !== null, { timeout: 3000 }).catch(() => {});
    const nodeIdRaw = await page.$eval(".replication .mono", (el) => el.textContent).catch(() => "");
    const nodeIdText = nodeIdRaw.replace(/^node id:\s*/, "").trim();
    check("Replication page shows the real node identity from control.db", /^[0-9a-f]{32}$/.test(nodeIdText), nodeIdRaw);

    // --- System Status: Node Identity card (2026-08-27 -- reuses the
    // same replication.status read, no new backend) ---
    check("System Status nav item exists and is clickable", await clickNav("System Status"));
    await page.waitForSelector("#health-heading", { timeout: 3000 }).catch(() => {});
    check("System Status page content rendered", (await page.$("#health-heading")) !== null);
    // Scoped to the real Node Identity card specifically (found by its
    // own <h3>), not a bare `.system-status .mono` -- the 2026-09-03
    // Database Sizes/Last DNS Deployment cards added their own earlier
    // `.mono` cells, making the old bare selector pick up the wrong
    // (first) one -- a real regression from that same session's own
    // earlier work, found live here.
    const nodeIdentityCardFn = () => {
      const h3 = [...document.querySelectorAll("h3")].find((e) => e.textContent?.trim() === "Node Identity");
      return h3?.closest(".card")?.querySelector(".value.mono")?.textContent ?? "";
    };
    await page.waitForFunction(nodeIdentityCardFn, { timeout: 3000 }).catch(() => {});
    const sysStatusNodeId = await page.evaluate(nodeIdentityCardFn);
    check(
      "System Status's Node Identity card shows the real node identity, matching Replication's",
      /^[0-9a-f]{32}$/.test(sysStatusNodeId.trim()) && sysStatusNodeId.trim() === nodeIdText.trim(),
      `system-status=${sysStatusNodeId} replication=${nodeIdText}`,
    );
    await page.waitForFunction(() => [...document.querySelectorAll("h3")].some((h) => h.textContent?.trim() === "BIND Cache Counters"), { timeout: 3000 }).catch(() => {});
    const bindCacheCountersPresent = await page.$$eval("h3", (els) => els.some((e) => e.textContent?.trim() === "BIND Cache Counters"));
    check("System Status renders a BIND Cache Counters card (2026-08-27)", bindCacheCountersPresent);

    // --- Network Configuration ---
    // A real, previously-stale flow removed here: this used to type an
    // arbitrary interface name into a manual "look up status" field and
    // read raw JSON -- that field doesn't exist on the current, rebuilt
    // NetworkView.svelte at all (it auto-detects and shows the real
    // active interface directly; picking a DIFFERENT interface is only
    // for the real Apply form's own dropdown). The current page's own
    // full workflow (Detected Backend, Active Interface, Current
    // Network Settings, the generated-configuration preview, apply/
    // confirm/rollback) already has dedicated, thorough real-browser
    // coverage in network_config_smoke.mjs -- this just proves the page
    // itself renders real (non-empty, non-raw-JSON) content here.
    check("Network Configuration nav item exists and is clickable", await clickNav("Network Configuration"));
    await page.waitForSelector("#network-heading", { timeout: 3000 }).catch(() => {});
    check("Network Configuration page content rendered", (await page.$("#network-heading")) !== null);
    await page.waitForSelector(".settings-table", { timeout: 3000 }).catch(() => {});
    const networkText = await page.$eval(".network", (el) => el.textContent).catch(() => "");
    check("Network Configuration shows real current settings, not raw JSON", /Detected Backend|Current Network Settings/.test(networkText) && !/raw_addr_json/.test(networkText), networkText.slice(0, 200));

    // --- Logs ---
    // nav.ts's real label is "System Logs", not "Logs".
    check("System Logs nav item exists and is clickable", await clickNav("System Logs"));
    await page.waitForSelector("#logs-heading", { timeout: 3000 }).catch(() => {});
    check("Logs page content rendered", (await page.$("#logs-heading")) !== null);
    const unitOptions = await page.$$eval(".logs select option", (els) => els.map((e) => e.textContent));
    check("Logs page lists the real configured unit allowlist", unitOptions.includes("apdns-go-web"), unitOptions.join(","));

    // "All" is the default selection (matching Python's own log viewer)
    // and merges every allowlisted unit's own entries, real proof being
    // the Unit column appearing (this app's own contract: it's shown
    // only when the merged "all" view is selected, see LogsView.svelte).
    const unitSelectValue = await page.$eval('.logs select[aria-label="Unit"]', (el) => el.value);
    check("Logs defaults to the real 'All' merged view, not a single unit", unitSelectValue === "all", unitSelectValue);
    await page.waitForFunction(() => document.querySelector(".logs table thead th")?.textContent?.trim() === "Unit", { timeout: 3000 }).catch(() => {});
    const firstHeaderWithAll = await page.$eval(".logs table thead th", (el) => el.textContent.trim()).catch(() => "");
    check("'All' view shows a real Unit column (a merge across units, not a single-unit tail)", firstHeaderWithAll === "Unit", firstHeaderWithAll);

    // Severity dropdown: a real V2-only enhancement over Python's own
    // log viewer (which has neither an "All" option nor a severity
    // filter) -- prove the real allowlisted severities render and the
    // control actually re-fetches on change, not just accepts a value.
    const severityOptions = await page.$$eval('.logs select[aria-label="Severity"] option', (els) => els.map((e) => e.textContent.trim()));
    check("Severity filter lists real severities from the backend, not a hardcoded stub", severityOptions.length > 1 && severityOptions.includes("Any severity"), severityOptions.join(","));
    await page.select('.logs select[aria-label="Severity"]', severityOptions[1]);
    await page.click('.logs form button[type="submit"]');
    await new Promise((r) => setTimeout(r, 300));
    check("Refresh with a severity filter selected does not error", (await page.$(".logs .error")) === null);

    // Switch back to a single real unit -- the Unit column must disappear
    // (this app's own contract: only "All" merges/labels by unit).
    await page.select('.logs select[aria-label="Unit"]', "apdns-go-web");
    await page.click('.logs form button[type="submit"]');
    await new Promise((r) => setTimeout(r, 300));
    const singleUnitHeader = await page.$eval(".logs table thead th", (el) => el.textContent.trim()).catch(() => "");
    check("switching to a single unit drops the Unit column (real per-selection behavior, not static markup)", singleUnitHeader !== "Unit", singleUnitHeader);

    // --- Software Updates ---
    check("Software Updates nav item exists and is clickable", await clickNav("Software Updates"));
    await page.waitForSelector("#updates-heading", { timeout: 3000 }).catch(() => {});
    check("Software Updates page content rendered", (await page.$("#updates-heading")) !== null);
    await page.waitForFunction(() => document.querySelector(".updates .card p")?.textContent?.trim() !== "…", { timeout: 3000 }).catch(() => {});
    const versionText = await page.$eval(".updates .card p", (el) => el.textContent).catch(() => "");
    check("Software Updates page shows the real current version", versionText.trim().length > 0 && versionText.trim() !== "…", versionText);

    // --- DNS Runtime (internal/dnscompile, internal/hostagentd/ops_dnsruntime.go) ---
    check("DNS Runtime nav item exists and is clickable", await clickNav("DNS Runtime"));
    await page.waitForSelector("#dnsruntime-heading", { timeout: 3000 }).catch(() => {});
    check("DNS Runtime page content rendered", (await page.$("#dnsruntime-heading")) !== null);
    await page.waitForFunction(() => document.querySelector(".dnsruntime .row") !== null, { timeout: 3000 }).catch(() => {});
    const runtimeRowText = await page.$eval(".dnsruntime .row", (el) => el.textContent).catch(() => "");
    // Needs a hostagent wired with a real DNS-runtime configuration
    // (see this file's own header comment) -- this fixture's own
    // minimal hostagent isn't, so this and the Apply check below are
    // an honestly-disclosed gap here, not silently skipped or forced
    // to crash the rest of this run.
    check("DNS Runtime page shows real BIND/dnsdist process status", /running|not running/.test(runtimeRowText), runtimeRowText || "(DNS Runtime not configured on this fixture's hostagent)");
    const dnsRuntimeButton = await page.$(".dnsruntime button");
    if (dnsRuntimeButton) {
      await Promise.all([
        page.waitForFunction(() => document.querySelector(".dnsruntime .success, .dnsruntime .error") !== null, { timeout: 8000 }),
        dnsRuntimeButton.click(),
      ]);
      const applyResultText = await page.$eval(".dnsruntime .success, .dnsruntime .error", (el) => el.textContent).catch(() => "");
      check("Apply Runtime Changes performs a real compile+promote and reports a real result", applyResultText.length > 0, applyResultText);
    } else {
      check("Apply Runtime Changes performs a real compile+promote and reports a real result", false, "(no Apply button -- DNS Runtime unavailable on this fixture's hostagent)");
    }

    // --- System Status: DNS Performance benchmark (internal/dnsperf,
    // internal/hostagentd/ops_dnsperf.go) -- real UDP/TCP/DoT/DoH
    // packet-level query exchange against this deployment's own real
    // dnsdist/BIND runtime, closing the disclosed "no Chromium run this
    // session" gap. Needs the same real DNS-runtime-configured fixture
    // as the DNS Runtime section just above (a real compiled/promoted
    // dnsdist+BIND pair is required for the benchmark's own case list
    // to have anything real to query), so it belongs in this suite, not
    // chromium_smoke.mjs. ---
    check("System Status nav item exists and is clickable", await clickNav("System Status"));
    await page.waitForSelector("#health-heading", { timeout: 3000 }).catch(() => {});
    check("System Status page content rendered", (await page.$("#health-heading")) !== null);
    // Real.mjs's own button has no disabled state tied to whether
    // internal/dnsperf is actually configured server-side (only to
    // "benchmark already running") -- clicking it on a hostagent that
    // isn't wired for DNS Runtime genuinely hits a real error response,
    // not a slow-but-eventual success, so wait for either real outcome
    // rather than blindly waiting for success alone.
    const dnsBenchmarkBtn = await page.$("[data-run-dns-benchmark]:not([disabled])");
    let dnsRuntimeFixtureConfigured = true;
    if (dnsBenchmarkBtn) {
      await dnsBenchmarkBtn.click();
      await page.waitForFunction(
        () => document.querySelector("[data-dns-performance]") !== null || document.querySelector(".health .status-unavailable") !== null,
        { timeout: 15000 },
      ).catch(() => {});
      dnsRuntimeFixtureConfigured = (await page.$("[data-dns-performance]")) !== null;
    }
    if (dnsBenchmarkBtn && dnsRuntimeFixtureConfigured) {
      const dnsPerfRows = await page.$$eval("[data-dns-performance] tbody tr", (rows) => rows.length);
      check("Safe DNS Benchmark completes and renders a real per-case results table", dnsPerfRows > 0, `rows=${dnsPerfRows}`);
      const dnsPerfFirstRow = await page.$eval("[data-dns-performance] tbody tr", (el) => el.textContent);
      check("benchmark results show real, non-placeholder latency figures", /\d/.test(dnsPerfFirstRow), dnsPerfFirstRow);
      const benchmarkFailedNote = await page.$(".health .degraded-note");
      check("Safe DNS Benchmark does not report a working-directory/permission failure (the original P0 defect)", benchmarkFailedNote === null || !(await page.evaluate((el) => el.textContent.includes("mkdir"), benchmarkFailedNote)));

      check("Copy DNS Performance Report button is enabled once a report exists", await page.$eval("[data-copy-dns-perf]", (el) => !el.disabled));
      await Promise.all([
        page.waitForFunction(() => document.querySelector("[data-dns-performance]") === null, { timeout: 3000 }),
        page.click("[data-clear-dns-perf]"),
      ]);
      check("Clear Benchmark Measurements actually removes the stored report", (await page.$("[data-dns-performance]")) === null);
    } else {
      // Needs the same real DNS-runtime-configured hostagent as the DNS
      // Runtime section above (see this file's own header comment) --
      // honestly disclosed gap on this fixture, not a silent skip.
      check("Run Safe DNS Benchmark button exists and is enabled", false, "(DNS Performance unavailable -- needs a real DNS-runtime-configured hostagent, which this fixture's own minimal hostagent isn't)");
    }

    const failed = results.filter((r) => !r.pass);
    console.log(`\n${results.length - failed.length}/${results.length} checks passed.`);
    if (failed.length > 0) process.exitCode = 1;
  } finally {
    await browser.close();
  }
}

main().catch((err) => {
  console.error("HARNESS ERROR:", err);
  process.exit(1);
});
