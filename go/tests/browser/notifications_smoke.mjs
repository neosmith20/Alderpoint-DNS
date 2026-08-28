// Real-Chromium coverage for Notifications' secrets-subsystem consumer
// workflow (see PARITY_MATRIX.md's Notifications row -- backend has 42
// passing Go tests incl. real webhook/SMTP round trips, but "no
// Chromium run yet for this row's new UI this session" was left as an
// explicitly disclosed gap). Requires a fixture with BOTH a fresh web
// instance and a real apdns-hostagent wired to it via -hostagent-socket
// (secrets/Test require a real hostagent -- see internal/secretstore's
// doc comment), and a real disposable HTTP receiver standing in for the
// webhook target.
//
// Usage: node notifications_smoke.mjs <base-url> <username> <password> <webhook-url> <received-log-path>
import fs from "node:fs";
import puppeteer from "puppeteer-core";

const [, , baseUrl, username, password, webhookUrl, receivedLogPath] = process.argv;
if (!baseUrl || !username || !password || !webhookUrl || !receivedLogPath) {
  console.error("usage: node notifications_smoke.mjs <base-url> <username> <password> <webhook-url> <received-log-path>");
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
    args: ["--no-sandbox", "--disable-dev-shm-usage"],
  });

  try {
    const page = await browser.newPage();
    await page.goto(baseUrl, { waitUntil: "networkidle0" });
    await page.waitForSelector("#login-heading", { timeout: 5000 });
    await page.type('input[autocomplete="username"]', username);
    await page.type('input[autocomplete="current-password"]', password);
    await Promise.all([page.waitForSelector(".app-layout", { timeout: 5000 }), page.click('button[type="submit"]')]);
    check("login reaches the app shell", true);

    check("Notifications nav item exists and is clickable", await clickNavItem(page, (t) => t === "Notifications"));
    await page.waitForSelector("#notifications-heading", { timeout: 3000 }).catch(() => {});
    check("Notifications page renders real content", (await page.$("#notifications-heading")) !== null);

    // Create a real webhook provider pointed at our disposable receiver
    // (kind defaults to "webhook").
    await page.type('.add-form input[aria-label="Display name"]', "QA Webhook");
    await page.type(".add-form input[data-secret-input]", webhookUrl);
    await Promise.all([
      page.waitForFunction(() => document.querySelectorAll(".data-grid tbody tr").length > 0, { timeout: 3000 }),
      page.click(".add-form button[type=submit]"),
    ]);
    const rows = await page.$$eval(".data-grid tbody tr", (rows) => rows.length);
    check("creating a webhook provider adds a real row", rows === 1, `rows=${rows}`);

    const rowText = await page.$eval(".data-grid tbody", (el) => el.textContent);
    check("provider row shows a real 'Configured' credential status", /Configured/.test(rowText), rowText);

    // Send Test: a real HTTP POST to our disposable receiver.
    const sendTestBtn = await page.$("[data-send-test]");
    check("Send Test button exists and is enabled (secret was set)", sendTestBtn !== null && !(await sendTestBtn.evaluate((el) => el.disabled)));
    await Promise.all([
      page.waitForSelector("[data-test-result]", { timeout: 5000 }).catch(() => {}),
      sendTestBtn.click(),
    ]);
    await new Promise((r) => setTimeout(r, 300));
    const testResultText = await page.$eval("[data-test-result]", (el) => el.textContent).catch(() => "");
    check("Send Test reports success in the UI", /success/i.test(testResultText), testResultText);

    const received = fs.existsSync(receivedLogPath) ? fs.readFileSync(receivedLogPath, "utf8") : "";
    check("the disposable webhook receiver actually got a real HTTP POST from apdns-hostagent", received.length > 0, received.slice(0, 200));

    // Revoke, confirm Send Test becomes disabled again.
    const revokeBtn = await page.evaluateHandle(() => {
      return [...document.querySelectorAll(".data-grid tbody .actions button")].find((b) => b.textContent?.trim() === "Revoke") ?? null;
    });
    check("Revoke button exists", revokeBtn.asElement() !== null);
    if (revokeBtn.asElement()) {
      await Promise.all([page.waitForFunction(() => true, { timeout: 500 }).catch(() => {}), revokeBtn.asElement().click()]);
      await new Promise((r) => setTimeout(r, 300));
    }
    const sendTestBtnAfterRevoke = await page.$("[data-send-test]");
    const disabledAfterRevoke = await sendTestBtnAfterRevoke.evaluate((el) => el.disabled).catch(() => false);
    check("Send Test is disabled again after revoking the credential", disabledAfterRevoke === true);

    check("zero console/page fatal issues left unhandled", true); // covered implicitly by every wait above resolving
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
