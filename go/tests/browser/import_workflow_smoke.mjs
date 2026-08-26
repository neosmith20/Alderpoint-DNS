// Real-Chromium proof of the Import page's real preview -> select ->
// apply -> rollback workflow (internal/importer's job model) --
// standalone from chromium_smoke.mjs (which needs the full analytics
// fixture pipeline) so this can run against any fresh instance.
//
// Usage: node import_workflow_smoke.mjs <base-url> <username> <password>
import puppeteer from "puppeteer-core";

const [, , baseUrl, username, password] = process.argv;
if (!baseUrl || !username || !password) {
  console.error("usage: node import_workflow_smoke.mjs <base-url> <username> <password>");
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

    check("Import nav item exists and is clickable", await clickNavItem(page, (t) => t === "Import"));
    await page.waitForSelector("#importexport-heading", { timeout: 3000 });
    check("Import page content rendered", (await page.$("#importexport-heading")) !== null);

    // --- Preview: parse-only, nothing written yet ---
    await page.type('textarea[aria-label="Hosts file contents"]', "10.0.0.42 import-workflow-test.lan\nmalformed-no-ip-line");
    await Promise.all([
      page.waitForSelector(".plan-table tbody tr", { timeout: 3000 }),
      page.click('.card button[type=submit]'),
    ]);
    const planText = await page.$eval(".plan-table tbody", (el) => el.textContent);
    check("preview shows the real planned row before anything is applied", planText.includes("import-workflow-test.lan") && planText.includes("new"), planText);

    // Confirm nothing was written to Local DNS yet.
    await clickNavItem(page, (t) => t === "Local DNS");
    await page.waitForSelector("#localdns-heading", { timeout: 3000 });
    await new Promise((r) => setTimeout(r, 200));
    const localDnsBeforeApply = await page.$eval(".data-grid tbody", (el) => el.textContent).catch(() => "");
    check("preview alone writes nothing to Local DNS", !localDnsBeforeApply.includes("import-workflow-test.lan"), localDnsBeforeApply);

    // --- Back to Import, apply ---
    await clickNavItem(page, (t) => t === "Import");
    await page.waitForSelector(".plan-table", { timeout: 3000 });
    await Promise.all([
      page.waitForSelector(".success[role=status]", { timeout: 3000 }),
      page.click('.card .actions button:not(.danger)'),
    ]);
    const applyText = await page.$eval(".success[role=status]", (el) => el.textContent);
    check("apply reports a real imported count", applyText.includes("1") && applyText.includes("imported"), applyText);
    check("a rollback option appears after a real apply (a real pre-apply snapshot exists)", (await page.$(".card .danger")) !== null);

    // The record now really exists on Local DNS.
    await clickNavItem(page, (t) => t === "Local DNS");
    await page.waitForSelector("#localdns-heading", { timeout: 3000 });
    await page.waitForFunction(() => document.querySelector(".data-grid tbody")?.textContent?.includes("import-workflow-test.lan"), { timeout: 3000 }).catch(() => {});
    const localDnsAfterApply = await page.$eval(".data-grid tbody", (el) => el.textContent);
    check("the applied import created a real Local DNS record", localDnsAfterApply.includes("import-workflow-test.lan"), localDnsAfterApply);

    // --- Rollback: the record must really disappear again ---
    await clickNavItem(page, (t) => t === "Import");
    await page.waitForSelector(".card .danger", { timeout: 3000 });
    await Promise.all([
      page.waitForFunction(() => !document.querySelector(".success[role=status]") || document.body.textContent?.includes("Roll back"), { timeout: 5000 }),
      page.click(".card .danger"),
    ]);
    await new Promise((r) => setTimeout(r, 500));

    await clickNavItem(page, (t) => t === "Local DNS");
    await page.waitForSelector("#localdns-heading", { timeout: 3000 });
    await new Promise((r) => setTimeout(r, 300));
    const localDnsAfterRollback = await page.$eval(".data-grid tbody", (el) => el.textContent).catch(() => "");
    check("rolling back the import removes the real record it created", !localDnsAfterRollback.includes("import-workflow-test.lan"), localDnsAfterRollback);

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
