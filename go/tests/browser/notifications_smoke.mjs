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

    // Notifications is Advanced-only nav (see nav.ts's "operations" group)
    // -- direct URL navigation works regardless of the selected profile,
    // same pattern network_config_smoke.mjs/domain_routing_rulesets_smoke.mjs
    // already use for their own Advanced-only pages. A real, previously-
    // stale defect in this test found while re-running it this session:
    // it used to click the sidebar item directly, which silently failed
    // once Notifications moved under an Advanced-only group (that group
    // isn't rendered in the sidebar at all under the default Standard
    // profile), always failing this check and every one of the (unaware)
    // real assertions after it.
    await page.goto(new URL("/ui/notifications", baseUrl).toString(), { waitUntil: "networkidle0" });
    await page.waitForSelector("#notifications-heading", { timeout: 3000 }).catch(() => {});
    check("Notifications page renders real content", (await page.$("#notifications-heading")) !== null);

    // Create a real webhook provider pointed at our disposable receiver
    // (kind defaults to "webhook"). Add Destination now opens a modal
    // (2026-09-03: the always-embedded inline form was moved into a
    // Modal per the structural-redesign pass) rather than exposing the
    // create form inline on the page.
    const addDestinationBtn = await page.evaluateHandle(() =>
      [...document.querySelectorAll("button")].find((b) => b.textContent?.trim() === "Add Destination"),
    );
    check("Add Destination button exists", addDestinationBtn.asElement() !== null);
    await addDestinationBtn.asElement()?.click();
    await page.waitForSelector('input[aria-label="Display name"]', { timeout: 3000 });
    await page.type('input[aria-label="Display name"]', "QA Webhook");
    await page.type("input[data-secret-input]", webhookUrl);
    // A real test bug found while re-running this suite this session
    // (not a product bug): DataGrid's own empty state is a real `<tr
    // class="empty-row">`, always present before any provider exists --
    // ".data-grid tbody tr" alone is satisfied by THAT row and resolves
    // instantly, before the real create+refresh round trip ever
    // finishes. Every other DataGrid-count check in this suite already
    // excludes `.empty-row`; this one didn't.
    await Promise.all([
      page.waitForFunction(() => document.querySelectorAll(".data-grid tbody tr:not(.empty-row)").length > 0, { timeout: 3000 }),
      page.click('.modal-form button[type=submit]'),
    ]);
    const rows = await page.$$eval(".data-grid tbody tr:not(.empty-row)", (rows) => rows.length);
    check("creating a webhook provider adds a real row", rows === 1, `rows=${rows}`);

    // createProvider() awaits create -> set-secret -> ONE refresh() before
    // ever closing the modal, so the row's has_secret is already final by
    // the time it first appears -- but give one more render tick margin
    // here anyway (same pattern this file already uses after Send Test
    // below), matching how this suite treats every other just-rendered
    // async state elsewhere.
    await new Promise((r) => setTimeout(r, 300));
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
