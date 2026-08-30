// Real-Chromium coverage for Dashboard's "Top Upstream Resolvers" panel
// (V1.1.1 dashboard.html parity -- see internal/dnsanalytics/upstreamstats.go's
// own doc comment for the V1 evidence: app/analytics.py's
// collect_upstream_resolver_aggregate against dnsdist's real per-backend
// counters). This suite deliberately runs against a fixture with NO DNS
// runtime configured (no dnsdist, no -hostagent-socket) -- it proves the
// wiring is honest end to end (real API call, real degraded-not-hidden
// UI) without needing a live dnsdist process; the dnsdist REST-API
// integration itself is already proven against a real installed dnsdist
// binary (see internal/hostagentd/ops_dnsruntime_upstreamstats.go).
//
// Usage: node dashboard_top_upstreams_smoke.mjs <base-url> <username> <password>
import puppeteer from "puppeteer-core";

const [, , baseUrl, username, password] = process.argv;
if (!baseUrl || !username || !password) {
  console.error("usage: node dashboard_top_upstreams_smoke.mjs <base-url> <username> <password>");
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
    ignoreHTTPSErrors: true,
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
    await page.waitForSelector("#dashboard-heading", { timeout: 5000 });
    await new Promise((r) => setTimeout(r, 1000));

    const cardText = await page.evaluate(() => {
      const h3 = [...document.querySelectorAll("h3")].find((e) => e.textContent.trim() === "Top Upstream Resolvers");
      return h3 ? h3.closest(".card")?.textContent ?? null : null;
    });
    check("Top Upstream Resolvers card renders on Dashboard", cardText !== null, cardText);
    check(
      "Shows an honest status (degraded reason or the real 'no data yet' hint), never fabricated resolver rows",
      /Resolver telemetry unavailable|No upstream resolver data yet/.test(cardText ?? ""),
      cardText,
    );
    const newCodeErrors = consoleErrors.filter((e) => /top-upstream/i.test(e));
    check("No JS console errors from the top-upstreams fetch itself", newCodeErrors.length === 0, consoleErrors.join(" | "));

    const apiResp = await page.evaluate(async () => {
      const r = await fetch("/api/analytics/top-upstreams?minutes=60&limit=10", { credentials: "same-origin" });
      return { status: r.status, body: await r.json() };
    });
    check("GET /api/analytics/top-upstreams returns 200", apiResp.status === 200, JSON.stringify(apiResp));
    check("Response shape has resolvers[]/degraded (real endpoint, not a stub)", Array.isArray(apiResp.body.resolvers) && typeof apiResp.body.degraded === "boolean", JSON.stringify(apiResp.body));

    await page.close();
  } finally {
    await browser.close();
  }
  const failed = results.filter((r) => !r.pass);
  console.log(`\n${results.length - failed.length}/${results.length} checks passed`);
  process.exit(failed.length ? 1 : 0);
}
main();
