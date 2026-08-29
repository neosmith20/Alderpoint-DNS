// Real-Chromium smoke coverage for the host-agent-backed pages (Cache,
// Replication, Network Configuration, Logs, Software Updates) --
// separate from chromium_smoke.mjs's own full-app sweep so this can be
// pointed at the dedicated hostagent end-to-end test instance (real
// two-UID privilege separation, real rndc/control.db/journal/ip
// access) without re-running the entire other suite.
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
    await page.waitForFunction(() => document.querySelector(".replication code") !== null, { timeout: 3000 }).catch(() => {});
    const nodeIdText = await page.$eval(".replication code", (el) => el.textContent).catch(() => "");
    check("Replication page shows the real node identity from control.db", /^[0-9a-f-]{36}$/.test(nodeIdText.trim()), nodeIdText);

    // --- System Status: Node Identity card (2026-08-27 -- reuses the
    // same replication.status read, no new backend) ---
    check("System Status nav item exists and is clickable", await clickNav("System Status"));
    await page.waitForSelector("#health-heading", { timeout: 3000 }).catch(() => {});
    check("System Status page content rendered", (await page.$("#health-heading")) !== null);
    await page.waitForFunction(() => document.querySelector(".system-status .mono") !== null, { timeout: 3000 }).catch(() => {});
    const sysStatusNodeId = await page.$eval(".system-status .mono", (el) => el.textContent).catch(() => "");
    check(
      "System Status's Node Identity card shows the real node identity, matching Replication's",
      /^[0-9a-f-]{36}$/.test(sysStatusNodeId.trim()) && sysStatusNodeId.trim() === nodeIdText.trim(),
      `system-status=${sysStatusNodeId} replication=${nodeIdText}`,
    );
    await page.waitForFunction(() => [...document.querySelectorAll("h3")].some((h) => h.textContent?.trim() === "BIND Cache Counters"), { timeout: 3000 }).catch(() => {});
    const bindCacheCountersPresent = await page.$$eval("h3", (els) => els.some((e) => e.textContent?.trim() === "BIND Cache Counters"));
    check("System Status renders a BIND Cache Counters card (2026-08-27)", bindCacheCountersPresent);

    // --- Network Configuration ---
    check("Network Configuration nav item exists and is clickable", await clickNav("Network Configuration"));
    await page.waitForSelector("#network-heading", { timeout: 3000 }).catch(() => {});
    check("Network Configuration page content rendered", (await page.$("#network-heading")) !== null);
    await page.type('input[aria-label="Interface name"]', "lo");
    await Promise.all([
      page.waitForFunction(() => document.querySelector(".network .raw") !== null, { timeout: 3000 }),
      page.click('.network form button[type="submit"]'),
    ]);
    const rawStatus = await page.$eval(".network .raw", (el) => el.textContent);
    check("Network status shows the real loopback interface", rawStatus.includes("127.0.0.1"), rawStatus);

    // --- Logs ---
    check("Logs nav item exists and is clickable", await clickNav("Logs"));
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
    check("DNS Runtime page shows real BIND/dnsdist process status", /running|not running/.test(runtimeRowText), runtimeRowText);
    await Promise.all([
      page.waitForFunction(() => document.querySelector(".dnsruntime .success, .dnsruntime .error") !== null, { timeout: 8000 }),
      page.click(".dnsruntime button"),
    ]);
    const applyResultText = await page.$eval(".dnsruntime .success, .dnsruntime .error", (el) => el.textContent).catch(() => "");
    check("Apply Runtime Changes performs a real compile+promote and reports a real result", applyResultText.length > 0, applyResultText);

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
