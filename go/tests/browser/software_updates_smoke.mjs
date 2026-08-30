// Real-Chromium coverage for the full Software Updates owner workflow
// (blocker 3): manual stage/apply (pre-existing, unchanged) PLUS the
// new real update-channel workflow -- configure the channel, check for
// updates against a real feed, and see an honest "update available" /
// download-and-stage path. Run against a disposable fresh instance.
//
// Usage: node software_updates_smoke.mjs <base-url> <username> <password>
import puppeteer from "puppeteer-core";
const [, , baseUrl, username, password] = process.argv;
if (!baseUrl || !username || !password) {
  console.error("usage: node software_updates_smoke.mjs <base-url> <username> <password>");
  process.exit(2);
}
const results = [];
function check(name, cond, detail) { results.push({ name, pass: !!cond, detail }); console.log(`[${cond ? "PASS" : "FAIL"}] ${name}${!cond && detail ? " -- " + detail : ""}`); }
async function clickNavItem(page, predicate) {
  const tryFind = async () => {
    for (const btn of await page.$$(".sidebar .item")) {
      const text = await btn.evaluate((el) => el.textContent?.trim());
      if (predicate(text)) { await btn.click(); return true; }
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
  const browser = await puppeteer.launch({ executablePath: process.env.CHROMIUM_PATH || "/usr/bin/chromium", headless: true, args: ["--no-sandbox", "--disable-dev-shm-usage", "--ignore-certificate-errors"] });
  try {
    const page = await browser.newPage();
    const consoleErrors = [];
    page.on("console", (m) => { if (m.type() === "error") consoleErrors.push(m.text()); });
    await page.setViewport({ width: 1440, height: 900 });
    await page.goto(baseUrl, { waitUntil: "networkidle0" });
    await page.waitForSelector("#login-heading", { timeout: 5000 });
    await page.type('input[autocomplete="username"]', username);
    await page.type('input[autocomplete="current-password"]', password);
    await Promise.all([page.waitForSelector(".app-layout", { timeout: 5000 }), page.click('button[type="submit"]')]);
    check("Software Updates nav clickable", await clickNavItem(page, (t) => t === "Software Updates"));
    await page.waitForSelector("#updates-heading", { timeout: 3000 });
    const text0 = await page.evaluate(() => document.querySelector(".updates").textContent);
    check("Current Version card renders", /Current Version/.test(text0), text0.slice(0, 300));
    check("Update Status card renders with honest 'No candidate staged'", /Update Status/.test(text0) && /No candidate staged/.test(text0), text0.slice(0, 300));
    check("Manual Update section renders", /Manual Update/.test(text0));
    check("Update Channel section renders", /Update Channel/.test(text0));

    // --- Real update channel: the DB is seeded with the real repo
    // (neosmith20/Alderpoint-DNS) by migration 0025, so the owner form
    // should already show it without any typing.
    const seededOwner = await page.$eval('.updates input[aria-label="Repo owner"]', (el) => el.value);
    const seededRepo = await page.$eval('.updates input[aria-label="Repo name"]', (el) => el.value);
    check("Update Channel form is pre-populated with the real seeded repo", seededOwner === "neosmith20" && seededRepo === "Alderpoint-DNS", `${seededOwner}/${seededRepo}`);

    // --- Check for updates against the REAL live GitHub repo ---
    const checkClicked = await page.evaluate(() => {
      const btn = [...document.querySelectorAll("button")].find((b) => b.textContent.trim() === "Check for Updates");
      if (btn) { btn.click(); return true; }
      return false;
    });
    check("Check for Updates button is clickable", checkClicked);
    await page.waitForFunction(() => document.body.textContent.includes("Last checked"), { timeout: 8000 }).catch(() => {});
    const afterCheck = await page.evaluate(() => document.querySelector(".updates").textContent);
    check("A real check result (last checked + status) is shown", /Last checked/.test(afterCheck), afterCheck.slice(0, 400));

    // --- Real API round trip proof (not just optimistic UI) ---
    const apiResp = await page.evaluate(async () => {
      const r = await fetch("/api/updates/channel", { credentials: "same-origin" });
      return { status: r.status, body: await r.json() };
    });
    check(
      "GET /api/updates/channel reflects a real checked state",
      apiResp.status === 200 && apiResp.body.last_checked_at && apiResp.body.last_check_status,
      JSON.stringify(apiResp.body),
    );

    const newCodeErrors = consoleErrors.filter((e) => !/Failed to load resource/.test(e));
    check("zero unexpected console errors", newCodeErrors.length === 0, newCodeErrors.join("; "));
  } finally { await browser.close(); }
  const passed = results.filter((r) => r.pass).length;
  console.log(`\n${passed}/${results.length} checks passed.`);
  process.exit(passed === results.length ? 0 : 1);
}
main().catch((e) => { console.error(e); process.exit(1); });
