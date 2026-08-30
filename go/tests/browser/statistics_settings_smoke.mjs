// Real-Chromium coverage for Statistics settings (GET/PUT
// /api/statistics/settings, StatisticsView.svelte) -- V1.1.1 parity:
// analytics enabled/detailed query logging/privacy mode/client
// anonymization/detailed retention days/db size limit/recent query
// limit, with a real save round trip.
import puppeteer from "puppeteer-core";

const [, , baseUrl, username, password] = process.argv;
if (!baseUrl || !username || !password) {
  console.error("usage: node statistics_settings_smoke.mjs <base-url> <username> <password>");
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

    check("Statistics nav item exists and is clickable", await clickNavItem(page, (t) => t === "Statistics"));
    await page.waitForSelector("#statistics-heading", { timeout: 3000 });
    await page.waitForSelector(".settings-form", { timeout: 3000 }).catch(() => {});

    const fieldCount = await page.evaluate(() => document.querySelectorAll(".settings-form input, .settings-form select").length);
    check("Settings form renders all 7 real fields", fieldCount === 7, `found ${fieldCount}`);

    const analyticsChecked = await page.$eval(".settings-form input[type=checkbox]", (el) => el.checked);
    check("Analytics enabled defaults to checked (matching the migration's real default)", analyticsChecked === true);

    // Change privacy_mode to aggregate_only, detailed_retention_days to 3, save.
    await page.select(".settings-form select", "aggregate_only");
    const retentionInput = (await page.$$(".settings-form input[type=number]"))[0];
    await retentionInput.evaluate((el) => {
      el.value = "";
      el.dispatchEvent(new Event("input", { bubbles: true }));
    });
    await retentionInput.click();
    await retentionInput.type("3");

    await page.click('.settings-form button[type="submit"]');
    await page.waitForFunction(() => document.body.textContent.includes("Saved."), { timeout: 3000 }).catch(() => {});
    check("Save shows a real confirmation after a real PUT", await page.evaluate(() => document.body.textContent.includes("Saved.")));

    // Reload the page fresh -- the saved value must persist server-side, not just in local state.
    await page.reload({ waitUntil: "networkidle0" });
    await clickNavItem(page, (t) => t === "Statistics");
    await page.waitForSelector(".settings-form", { timeout: 3000 });
    const selectedMode = await page.$eval(".settings-form select", (el) => el.value);
    check("privacy_mode=aggregate_only persisted across reload (real backend save)", selectedMode === "aggregate_only", selectedMode);
    const retentionValue = await page.$eval(".settings-form input[type=number]", (el) => el.value);
    check("detailed_retention_days=3 persisted across reload", retentionValue === "3", retentionValue);

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
