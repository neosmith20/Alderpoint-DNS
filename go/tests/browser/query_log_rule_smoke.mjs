// Real-Chromium coverage for "Query Log -> rule creation" -- the one
// disclosed Custom Rules gap this session closes (see PARITY_MATRIX.md's
// Filters row: "Query Log -> rule creation: now buildable... but not yet
// wired"). Query Log's own Rule column ("Block"/"Allow" per row) sets a
// real prefill (customRulePrefill.svelte.ts) and navigates to Filters;
// Filters' own "Add rule" form must actually arrive pre-filled with that
// row's domain, not just land on the page.
//
// Requires a fresh instance with at least one real query_events row
// seeded directly (this fixture has no dnstap wiring, so there is no
// real dnsdist traffic path to generate one) -- see the caller for the
// exact seeded row.
//
// Usage: node query_log_rule_smoke.mjs <base-url> <username> <password>
import puppeteer from "puppeteer-core";

const [, , baseUrl, username, password] = process.argv;
if (!baseUrl || !username || !password) {
  console.error("usage: node query_log_rule_smoke.mjs <base-url> <username> <password>");
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

    check("Query Log nav item exists and is clickable", await clickNavItem(page, (t) => t === "Query Log"));
    await page.waitForSelector("#analytics-heading", { timeout: 3000 });

    await page.waitForFunction(
      () => document.body.textContent.includes("ads.example.net"),
      { timeout: 5000 },
    ).catch(() => {});
    check("real seeded query-log row (ads.example.net) renders", await page.evaluate(() => document.body.textContent.includes("ads.example.net")));

    const clicked = await page.evaluate(() => {
      const rows = [...document.querySelectorAll(".data-grid tbody tr")];
      for (const row of rows) {
        if (row.textContent.includes("ads.example.net")) {
          const btn = [...row.querySelectorAll("button.rule-action")].find((b) => b.textContent.trim() === "Block");
          if (btn) { btn.click(); return true; }
        }
      }
      return false;
    });
    check("'Block' rule action exists on the seeded row and is clickable", clicked);

    await page.waitForSelector("#filtering-heading", { timeout: 3000 }).catch(() => {});
    check("clicking Block navigates to the real Filters page", (await page.$("#filtering-heading")) !== null);

    const patternValue = await page.$eval(".add-form input", (el) => el.value).catch(() => "");
    check("Filters' Add-rule pattern field is pre-filled with the real seeded domain (real deep link, not a dead button)", patternValue === "ads.example.net", patternValue);

    const ruleTypeValue = await page.$eval(".add-form select", (el) => el.value).catch(() => "");
    check("rule type defaults to 'block' from the Query Log action clicked", ruleTypeValue === "block", ruleTypeValue);

    check("a 'Pre-filled from Query Log' notice is shown", await page.evaluate(() => document.body.textContent.includes("Pre-filled from Query Log")));

    // Submit it for real -- the deep link must actually create a real,
    // persisted rule, not just populate a form field.
    await page.click(".add-form button[type=submit]");
    await page.waitForFunction(
      () => document.body.textContent.includes("ads.example.net") && document.querySelectorAll(".data-grid tbody tr").length > 0,
      { timeout: 5000 },
    ).catch(() => {});
    await new Promise((r) => setTimeout(r, 300));
    const ruleListHasIt = await page.evaluate(() => {
      const grids = [...document.querySelectorAll(".data-grid")];
      return grids.some((g) => g.textContent.includes("ads.example.net"));
    });
    check("submitting creates a real, persisted custom rule for the seeded domain", ruleListHasIt);

    // Reload and confirm it survived -- state must persist, not just
    // reflect an optimistic client-side update.
    await page.reload({ waitUntil: "networkidle0" });
    await page.waitForSelector("#filtering-heading", { timeout: 5000 });
    await new Promise((r) => setTimeout(r, 300));
    const persistedAfterReload = await page.evaluate(() => {
      const grids = [...document.querySelectorAll(".data-grid")];
      return grids.some((g) => g.textContent.includes("ads.example.net"));
    });
    check("the created rule survives a full page reload (real persistence, not client-only state)", persistedAfterReload);

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
