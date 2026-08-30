import puppeteer from "puppeteer-core";
const [, , baseUrl, username, password] = process.argv;
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
  const browser = await puppeteer.launch({ executablePath: "/usr/bin/chromium", headless: true, args: ["--no-sandbox", "--disable-dev-shm-usage", "--ignore-certificate-errors"] });
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
    const text = await page.evaluate(() => document.querySelector(".updates").textContent);
    check("Current Version card renders", /Current Version/.test(text), text.slice(0,300));
    check("Update Status card renders with honest 'No candidate staged'", /Update Status/.test(text) && /No candidate staged/.test(text), text.slice(0,300));
    check("Manual Update section renders", /Manual Update/.test(text));
    check("honest no-auto-check disclosure present", /does not yet\s+check any update server/.test(text.replace(/\s+/g," ")), text);
    check("zero unexpected console errors", consoleErrors.filter((e) => !/Failed to load resource/.test(e)).length === 0, consoleErrors.join("; "));
  } finally { await browser.close(); }
  const passed = results.filter((r) => r.pass).length;
  console.log(`\n${passed}/${results.length} checks passed.`);
  process.exit(passed === results.length ? 0 : 1);
}
main().catch((e) => { console.error(e); process.exit(1); });
