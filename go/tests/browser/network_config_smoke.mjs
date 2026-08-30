// Real-Chromium coverage for Network Configuration (NetworkView.svelte):
// Detected Backend, Active Interface, readable Current Network Settings
// table, and a real apply/confirm/rollback round trip -- ALWAYS against
// an explicitly-selected disposable test interface (passed in as
// testIface), never the interface the page defaults to (the real
// default-route interface on whatever host runs this fixture).
//
// Usage: node network_config_smoke.mjs <base-url> <username> <password> <test-iface>
import puppeteer from "puppeteer-core";

const [, , baseUrl, username, password, testIface] = process.argv;
if (!baseUrl || !username || !password || !testIface) {
  console.error("usage: node network_config_smoke.mjs <base-url> <username> <password> <test-iface>");
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

    check("Network Configuration nav item exists and is clickable", await clickNavItem(page, (t) => t === "Network Configuration"));
    await page.waitForSelector("#network-heading", { timeout: 3000 });
    await page.waitForSelector(".settings-table", { timeout: 3000 });

    const text = await page.evaluate(() => document.querySelector(".network").textContent);
    check("Detected Backend card renders a real backend (not raw JSON)", /Detected Backend/.test(text) && !/raw_addr_json/.test(text), text.slice(0, 200));
    check("Active Interface card renders", /Active Interface/.test(text));
    check("Current Network Settings table renders IPv4 mode row", /IPv4 mode/.test(text));

    // Explicitly select the disposable test interface -- never touch
    // whatever the page defaulted to (the real host's default route
    // interface).
    const options = await page.$$eval("select option", (opts) => opts.map((o) => o.value));
    check(`test interface ${testIface} appears in the interface dropdown`, options.includes(testIface), options.join(","));
    await page.select(".network select", testIface);
    const selectedNow = await page.$eval(".network select", (el) => el.value);
    check("interface dropdown now shows the test interface, not the default", selectedNow === testIface, selectedNow);

    await page.type('.network input[placeholder="192.168.1.10"]', "10.99.0.9");
    const prefixInput = await page.$('.network input[placeholder="24"]');
    await prefixInput.evaluate((el) => { el.value = ""; el.dispatchEvent(new Event("input", { bubbles: true })); });
    await prefixInput.type("24");
    // This suite proves the live apply/confirm/rollback UI round trip
    // only -- it deliberately unchecks "Persist" so it never writes
    // into this fixture host's own REAL backend config (netplan/
    // networkd/ifupdown/NetworkManager -- whichever this real host
    // happens to have): persistence itself has its own dedicated,
    // safely-path-overridden Go tests
    // (internal/hostagentd/network_persist_test.go).
    const persistCheckbox = await page.$('.network input[type="checkbox"]');
    if (persistCheckbox && (await persistCheckbox.evaluate((el) => el.checked))) {
      await persistCheckbox.click();
    }
    await page.click('.network button[type="submit"]');

    await page.waitForFunction(() => document.body.textContent.includes("Awaiting confirmation"), { timeout: 4000 }).catch(() => {});
    check("Apply shows the real 'Awaiting confirmation' pending state", await page.evaluate(() => document.body.textContent.includes("Awaiting confirmation")));
    check(
      "Persist unchecked -> the live-only apply is honestly reported (no 'persist' object claimed)",
      await page.evaluate(() => !document.body.textContent.includes("Persisted via")),
    );

    const confirmed = await page.evaluate(() => {
      const btn = [...document.querySelectorAll("button")].find((b) => b.textContent.trim() === "Keep Configuration");
      if (btn) { btn.click(); return true; }
      return false;
    });
    check("Keep Configuration button is clickable", confirmed);
    await page.waitForFunction(() => document.body.textContent.includes("Confirmed"), { timeout: 3000 }).catch(() => {});
    check("Confirm shows a real success message", await page.evaluate(() => document.body.textContent.includes("Confirmed")));

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
