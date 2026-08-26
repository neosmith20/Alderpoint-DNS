// Client-side navigation-latency measurement: real Chromium, real clicks,
// Date.now() deltas from click to the new route's heading appearing in
// the DOM -- not synthetic, not a guess. Run against a fresh instance
// (same usage as chromium_smoke.mjs).
import puppeteer from "puppeteer-core";

const [, , baseUrl, username, password] = process.argv;

async function main() {
  const browser = await puppeteer.launch({
    executablePath: process.env.CHROMIUM_PATH || "/usr/bin/chromium",
    headless: true,
    args: ["--no-sandbox", "--disable-dev-shm-usage", "--ignore-certificate-errors"],
  });
  const page = await browser.newPage();
  await page.setViewport({ width: 1440, height: 900 });

  const t0 = Date.now();
  await page.goto(baseUrl, { waitUntil: "networkidle0" });
  await page.waitForSelector("#setup-heading, #login-heading", { timeout: 5000 });
  const coldLoadMs = Date.now() - t0;

  if (await page.$("#setup-heading")) {
    await page.type('input[autocomplete="username"]', username);
    await page.type('input[autocomplete="new-password"]', password);
    const confirms = await page.$$('input[autocomplete="new-password"]');
    await confirms[1].type(password);
    await Promise.all([page.waitForSelector("#login-heading"), page.click('button[type="submit"]')]);
  }
  await page.$eval('input[autocomplete="username"]', (el) => (el.value = ""));
  await page.type('input[autocomplete="username"]', username);
  await page.type('input[autocomplete="current-password"]', password);
  await Promise.all([page.waitForSelector(".app-layout"), page.click('button[type="submit"]')]);

  const routes = [
    { label: "Blocklists", match: "Blocklists", heading: "#blocklists-heading" },
    { label: "Local DNS", match: "Local DNS", heading: "#localdns-heading" },
    { label: "Administration", match: "Administration", heading: "#admin-heading" },
    { label: "Dashboard", match: "Dashboard", heading: "#dashboard-heading" },
  ];

  const results = { coldLoadMs };
  for (const route of routes) {
    const samples = [];
    for (let i = 0; i < 8; i++) {
      const buttons = await page.$$(".sidebar .item, .top-level");
      let target = null;
      for (const btn of buttons) {
        const text = await btn.evaluate((el) => el.textContent?.trim());
        if (text?.startsWith(route.match)) {
          target = btn;
          break;
        }
      }
      if (!target) break;
      const start = Date.now();
      await target.click();
      await page.waitForSelector(route.heading, { timeout: 3000 });
      samples.push(Date.now() - start);
    }
    samples.sort((a, b) => a - b);
    results[route.label] = {
      samples,
      p50: samples[Math.floor(samples.length / 2)],
      max: samples[samples.length - 1],
    };
  }

  await browser.close();
  console.log(JSON.stringify(results, null, 2));
}

main().catch((err) => {
  console.error("PERF HARNESS ERROR:", err);
  process.exit(1);
});
