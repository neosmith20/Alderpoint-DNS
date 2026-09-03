// Real-Chromium coverage for Administration's Sessions and Recent
// Administrative Activity tables (V1.1.1 parity: administration.html).
import puppeteer from "puppeteer-core";

const [, , baseUrl, username, password] = process.argv;
if (!baseUrl || !username || !password) {
  console.error("usage: node administration_activity_smoke.mjs <base-url> <username> <password>");
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
    await Promise.all([page.waitForSelector(".app-layout", { timeout: 5000 }), page.click('button[type="submit"]')]);

    check("Administration nav item exists and is clickable", await clickNavItem(page, (t) => t === "Administration"));
    await page.waitForSelector("#admin-heading", { timeout: 3000 });
    await page.waitForSelector(".admin-table", { timeout: 3000 });

    const text = await page.evaluate(() => document.querySelector(".admin").textContent);
    check("Sessions table renders", /Sessions/.test(text));
    check("This session's own row is labeled", /This session/.test(text));
    check("Administration links out to the full Audit Log page (2026-09 redesign moved it there)", /Open Audit Log/.test(text));

    // Trigger a real audit-log-producing action (the global protection
    // on/off control, now in the Dashboard's own page header) then check
    // it on the dedicated Audit Log page (Advanced > Operations), which
    // replaced Administration's embedded "Recent Administrative Activity"
    // table in the 2026-09 redesign.
    await clickNavItem(page, (t) => t === "Dashboard");
    await page.waitForSelector("#dashboard-heading", { timeout: 3000 });
    await new Promise((r) => setTimeout(r, 500));
    const toggled = await page.evaluate(() => {
      const btn = [...document.querySelectorAll("button")].find((b) => /Disable protection|Enable protection/.test(b.textContent));
      if (btn) { btn.click(); return true; }
      return false;
    });
    check("Protection on/off control is clickable from the Dashboard header", toggled);
    await new Promise((r) => setTimeout(r, 600));

    check("Audit Log nav item exists and is clickable", await clickNavItem(page, (t) => t === "Audit Log"));
    await page.waitForSelector("#audit-log-heading", { timeout: 3000 });
    await page.waitForSelector('[data-grid-id="audit-log"]', { timeout: 3000 });
    await new Promise((r) => setTimeout(r, 500));
    const afterText = await page.evaluate(() => document.querySelector('[data-grid-id="audit-log"]').textContent);
    check("Real protection toggle appears in the Audit Log", /protection_(enabled|disabled)/.test(afterText), afterText.slice(0, 500));
    check("Audit Log row shows Success badge", /Success/.test(afterText));

    // Blocker 4 (Full Admin Audit Log): appliance-wide coverage via
    // internal/httpapi's audited() route wrapper -- not just the
    // hand-picked security-relevant actions above. Trigger a real
    // mutation on a completely different feature area (a Filtering
    // Profile, part of blocker 1's own new policy-entities surface)
    // and confirm it shows up too, proving the wrapper's coverage is
    // real and appliance-wide, not limited to what was already
    // individually instrumented.
    const created = await page.evaluate(async () => {
      const sess = await (await fetch("/api/session", { credentials: "same-origin" })).json();
      const r = await fetch("/api/policy-entities/filtering-profiles", {
        method: "POST",
        credentials: "same-origin",
        headers: { "content-type": "application/json", "X-CSRF-Token": sess.csrf },
        body: JSON.stringify({ id: "admin-audit-smoke-profile", name: "Admin Audit Smoke", categories: ["malware"] }),
      });
      return r.status;
    });
    check("a real mutation on an unrelated feature (Filtering Profiles) succeeds", created === 201, String(created));
    await page.reload({ waitUntil: "networkidle0" });
    await page.waitForSelector("#audit-log-heading", { timeout: 3000 });
    await page.waitForSelector('[data-grid-id="audit-log"]', { timeout: 3000 });
    await new Promise((r) => setTimeout(r, 500));
    const afterUnrelatedText = await page.evaluate(() => document.querySelector('[data-grid-id="audit-log"]').textContent);
    check(
      "the unrelated mutation appears in the Audit Log too -- proves appliance-wide audited() coverage, not just hand-picked actions",
      /policy_entities_filtering_profiles_create/.test(afterUnrelatedText),
      afterUnrelatedText.slice(0, 600),
    );

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
