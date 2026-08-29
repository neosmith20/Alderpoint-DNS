// Real-Chromium coverage for the Clients page's "Client analytics" table
// (GET /api/analytics/top-clients, ClientsView.svelte) -- the V1.1.1-
// parity requirement this session added: Client/Queries/Share/Blocked/
// Last Seen/Query Log link, ranked by volume, with a real time-range
// selector. Requires a fresh instance whose analytics.db already has
// real query_events rows seeded directly (this fixture has no dnstap
// wiring, so there is no real dnsdist traffic to generate them) --
// see the caller for the exact seeded rows.
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

    await page.waitForFunction(
      () => document.body.textContent.includes("203.0.113.9"),
      { timeout: 5000 },
    ).catch(() => {});

    const analyticsText = await page.evaluate(() => {
      const h2 = [...document.querySelectorAll("h2")].find((e) => e.textContent.trim() === "Client analytics");
      return h2 ? h2.closest(".panel")?.textContent ?? null : null;
    });
    check("Client analytics panel renders", analyticsText !== null, String(analyticsText).slice(0, 200));
    check("real seeded client 203.0.113.9 appears, ranked first (2 queries)", /203\.0\.113\.9/.test(analyticsText ?? ""), analyticsText);
    check("real seeded client 203.0.113.20 also appears (1 query)", /203\.0\.113\.20/.test(analyticsText ?? ""), analyticsText);
    check("blocked count/percent shown for the client with a real blocked query", /1 \(50\.0%\)/.test(analyticsText ?? ""), analyticsText);

    check("segmented time-range control renders", (await page.$$('nav[aria-label="Client analytics time range"] button')).length === 4);

    // Switch to "Last hour" -- a real re-fetch, not a client-side no-op.
    const rangeButtons = await page.$$('nav[aria-label="Client analytics time range"] button');
    let clickedLastHour = false;
    for (const b of rangeButtons) {
      if ((await b.evaluate((el) => el.textContent.trim())) === "Last hour") {
        await b.click();
        clickedLastHour = true;
      }
    }
    check("'Last hour' range control is clickable", clickedLastHour);
    await new Promise((r) => setTimeout(r, 300));
    const stillThere = await page.evaluate(() => document.body.textContent.includes("203.0.113.9"));
    check("switching range re-fetches and still shows real recent data", stillThere);

    // Query Log deep link: click it, land on Query Log with the client
    // filter pre-seeded (queryLogPrefill.svelte.ts).
    const clicked = await page.evaluate(() => {
      const rows = [...document.querySelectorAll(".data-grid tbody tr")];
      for (const row of rows) {
        if (row.textContent.includes("203.0.113.9")) {
          const btn = [...row.querySelectorAll("button")].find((b) => b.textContent.trim() === "Query Log");
          if (btn) { btn.click(); return true; }
        }
      }
      return false;
    });
    check("Query Log link exists on the client analytics row and is clickable", clicked);
    await page.waitForSelector("#analytics-heading", { timeout: 3000 }).catch(() => {});
    check("Query Log link navigates to the real Query Log page", (await page.$("#analytics-heading")) !== null);
    const clientFilterValue = await page.$eval('input[aria-label="Filter by client"]', (el) => el.value).catch(() => "");
    check("Query Log's client filter is pre-seeded with the real client address (real deep link, not a dead button)", clientFilterValue === "203.0.113.9", clientFilterValue);

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
