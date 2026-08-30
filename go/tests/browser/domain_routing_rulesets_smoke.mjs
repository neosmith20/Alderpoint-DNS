// Real-Chromium coverage for the Domain Routing Rulesets owner
// workflow (blocker 1 follow-up: rulesets were backend-only until
// this UI, closing a real fake-switch risk in PolicyEditor's own
// "Domain routing ruleset" dropdown).
//
// Usage: node domain_routing_rulesets_smoke.mjs <base-url> <username> <password>
import puppeteer from "puppeteer-core";
const [, , baseUrl, username, password] = process.argv;
if (!baseUrl || !username || !password) {
  console.error("usage: node domain_routing_rulesets_smoke.mjs <base-url> <username> <password>");
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
  const browser = await puppeteer.launch({ executablePath: process.env.CHROMIUM_PATH || "/usr/bin/chromium", headless: true, args: ["--no-sandbox", "--disable-dev-shm-usage"] });
  try {
    const page = await browser.newPage();
    const consoleErrors = [];
    page.on("console", (m) => { if (m.type() === "error") consoleErrors.push(m.text()); });
    await page.goto(baseUrl, { waitUntil: "networkidle0" });
    await page.waitForSelector("#login-heading", { timeout: 5000 });
    await page.type('input[autocomplete="username"]', username);
    await page.type('input[autocomplete="current-password"]', password);
    await Promise.all([page.waitForSelector(".app-layout", { timeout: 5000 }), page.click('button[type="submit"]')]);

    check("DNS Settings nav clickable", await clickNavItem(page, (t) => t === "DNS Settings"));
    await new Promise((r) => setTimeout(r, 500));
    const text0 = await page.evaluate(() => document.body.textContent);
    check("Domain Routing section renders", /Domain Routing/.test(text0));
    check("Rulesets section renders", /Rulesets/.test(text0));

    // Create a ruleset via the real form
    const created = await page.evaluate(() => {
      const inputs = [...document.querySelectorAll('input[aria-label="Ruleset id"], input[aria-label="Ruleset name"]')];
      const idInput = document.querySelector('input[aria-label="Ruleset id"]');
      const nameInput = document.querySelector('input[aria-label="Ruleset name"]');
      if (!idInput || !nameInput) return false;
      const setVal = (el, v) => {
        const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value").set;
        setter.call(el, v);
        el.dispatchEvent(new Event("input", { bubbles: true }));
      };
      setVal(idInput, "e2e-ruleset");
      setVal(nameInput, "E2E Ruleset");
      idInput.closest("form").requestSubmit();
      return true;
    });
    check("ruleset create form submits", created);
    await new Promise((r) => setTimeout(r, 800));
    const afterCreate = await page.evaluate(() => document.body.textContent);
    check("new ruleset appears as a chip", /E2E Ruleset/.test(afterCreate));

    const apiResp = await page.evaluate(async () => {
      const r = await fetch("/api/domain-routing/rulesets", { credentials: "same-origin" });
      return { status: r.status, body: await r.json() };
    });
    check("GET /api/domain-routing/rulesets reflects the real created ruleset", apiResp.status === 200 && apiResp.body.rulesets.some((r) => r.id === "e2e-ruleset"), JSON.stringify(apiResp.body));

    // Check the ruleset now appears as a select option in the route form
    const hasOption = await page.evaluate(() => {
      const select = document.querySelector('select[aria-label="Ruleset"]');
      return [...(select?.options ?? [])].some((o) => o.value === "e2e-ruleset");
    });
    check("Ruleset dropdown in the route form lists the real created ruleset", hasOption);

    const newErrors = consoleErrors.filter((e) => !/Failed to load resource/.test(e));
    check("zero unexpected console errors", newErrors.length === 0, newErrors.join("; "));

    await page.close();
  } finally { await browser.close(); }
  const passed = results.filter((r) => r.pass).length;
  console.log(`\n${passed}/${results.length} checks passed.`);
  process.exit(passed === results.length ? 0 : 1);
}
main().catch((e) => { console.error(e); process.exit(1); });
