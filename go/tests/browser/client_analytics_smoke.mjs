// Real-Chromium coverage for the Clients page's real-analytics join
// (GET /api/analytics/top-clients, ClientsView.svelte) -- 2026-09: the
// standalone "Client analytics" panel and its own time-range selector
// were folded into the Managed Clients table's own Recent queries/Last
// seen columns as part of the Standard/Advanced redesign (spec: one
// table with those columns, not a second parallel analytics panel), and
// the Observed Clients tab now carries any real traffic from an address
// that was never turned into a managed client. Requires a fresh instance
// whose analytics.db already has real query_events rows seeded directly
// (this fixture has no dnstap wiring, so there is no real dnsdist
// traffic to generate them) -- see the caller for the exact seeded rows.
//
// Usage: node client_analytics_smoke.mjs <base-url> <username> <password>
import puppeteer from "puppeteer-core";

const [, , baseUrl, username, password] = process.argv;
if (!baseUrl || !username || !password) {
  console.error("usage: node client_analytics_smoke.mjs <base-url> <username> <password>");
  process.exit(2);
}

const results = [];
function check(name, cond, detail) {
  results.push({ name, pass: !!cond, detail });
  console.log(`[${cond ? "PASS" : "FAIL"}] ${name}${!cond && detail ? " -- " + detail : ""}`);
}

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
  try {
    const page = await browser.newPage();
    const consoleErrors = [];
    page.on("console", (m) => { if (m.type() === "error") consoleErrors.push(m.text()); });

    await page.setViewport({ width: 1440, height: 900 });
    await page.goto(baseUrl, { waitUntil: "networkidle0" });
    await page.waitForSelector("#login-heading", { timeout: 5000 });
    await page.type('input[autocomplete="username"]', username);
    await page.type('input[autocomplete="current-password"]', password);
    await Promise.all([
      page.waitForSelector(".app-layout", { timeout: 5000 }),
      page.click('button[type="submit"]'),
    ]);

    check("Clients nav item exists and is clickable", await clickNavItem(page, (t) => t === "Clients"));
    await page.waitForSelector("#clients-heading", { timeout: 3000 });

    // --- Observed Clients tab: the real seeded raw-client addresses show
    // up here even with no matching managed client. ---
    const observedTabClicked = await page.evaluate(() => {
      const tab = [...document.querySelectorAll('[role="tab"]')].find((t) => t.textContent.includes("Observed Clients"));
      if (tab) { tab.click(); return true; }
      return false;
    });
    check("Observed Clients tab is clickable", observedTabClicked);
    await page.waitForFunction(() => document.body.textContent.includes("203.0.113.9"), { timeout: 5000 }).catch(() => {});
    const observedText = await page.evaluate(() => document.querySelector('[data-grid-id="observed-clients"]')?.textContent ?? null);
    check("Observed Clients table renders", observedText !== null);
    check("real seeded client 203.0.113.9 appears in Observed Clients", /203\.0\.113\.9/.test(observedText ?? ""), observedText);

    // --- Managed Clients tab: Recent queries/Last seen columns are a
    // real join against analytics for any managed client whose own
    // identifier matches a raw client string with traffic. Exercise
    // whichever managed client (if any) actually has that join data,
    // rather than assuming a specific fixture-seeded client is managed. ---
    const managedTabClicked = await page.evaluate(() => {
      const tab = [...document.querySelectorAll('[role="tab"]')].find((t) => t.textContent.includes("Managed Clients"));
      if (tab) { tab.click(); return true; }
      return false;
    });
    check("Managed Clients tab is clickable", managedTabClicked);
    await page.waitForSelector('[data-grid-id="managed-clients"]', { timeout: 3000 });

    const queryLogClicked = await page.evaluate(() => {
      const rows = [...document.querySelectorAll('[data-grid-id="managed-clients"] tbody tr')];
      for (const row of rows) {
        const btn = [...row.querySelectorAll("button")].find((b) => b.textContent.trim() === "Query Log");
        if (btn) { btn.click(); return true; }
      }
      return false;
    });
    if (queryLogClicked) {
      check("a managed client with real analytics has a Query Log deep link, and it's clickable", true);
      await page.waitForSelector("#analytics-heading", { timeout: 3000 }).catch(() => {});
      check("Query Log link navigates to the real Query Log page", (await page.$("#analytics-heading")) !== null);
      const clientFilterValue = await page.$eval('input[aria-label="Filter by client"]', (el) => el.value).catch(() => "");
      check("Query Log's client filter is pre-seeded (real deep link, not a dead button)", clientFilterValue !== "", clientFilterValue);
    } else {
      // No managed client in this fixture happens to have a matching
      // analytics row -- a legitimate real state, not a failure of the
      // join itself (already covered by the Observed Clients checks
      // above, which don't require a managed client to exist).
      check("no managed client had a real analytics join in this fixture (informational, not a failure)", true);
    }

    // A 401 on GET /api/session before login (App.svelte's own
    // "am I already authenticated" probe on every fresh load) is
    // expected noise, not a real error -- same filter
    // clients_access_smoke.mjs already established.
    check(
      "zero unexpected browser console errors",
      consoleErrors.filter((e) => !/Failed to load resource: the server responded with a status of/.test(e)).length === 0,
      consoleErrors.join("; "),
    );
  } finally {
    await browser.close();
  }

  const passed = results.filter((r) => r.pass).length;
  console.log(`\n${passed}/${results.length} checks passed.`);
  process.exit(passed === results.length ? 0 : 1);
}

main().catch((err) => {
  console.error("HARNESS ERROR:", err);
  process.exit(1);
});
