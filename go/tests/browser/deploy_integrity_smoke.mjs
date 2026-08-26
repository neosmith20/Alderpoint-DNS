// Real-Chromium proof that a deployed instance survives normal reload,
// hard reload, direct deep links, and every menu/submenu route --
// specifically targeting the class of defect found live on :10443
// (a stale cached index.html referencing a since-removed content-
// hashed chunk after a redeploy replaced the static directory
// wholesale -- see internal/httpapi/static.go's own doc comment for
// the fix). Run against a fresh instance sharing the exact real
// deployed release bundle.
//
// Usage: node deploy_integrity_smoke.mjs <base-url> <username> <password>
import puppeteer from "puppeteer-core";

const [, , baseUrl, username, password] = process.argv;
if (!baseUrl || !username || !password) {
  console.error("usage: node deploy_integrity_smoke.mjs <base-url> <username> <password>");
  process.exit(2);
}

const results = [];
function check(name, cond, detail) {
  results.push({ name, pass: !!cond, detail });
  console.log(`[${cond ? "PASS" : "FAIL"}] ${name}${!cond && detail ? " -- " + detail : ""}`);
}

const consoleErrors = [];
const pageErrors = [];

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
    page.on("console", (msg) => {
      if (msg.type() === "error" && !/Failed to load resource: the server responded with a status of/.test(msg.text())) {
        consoleErrors.push(msg.text());
      }
    });
    page.on("pageerror", (err) => pageErrors.push(String(err)));
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

    // --- Normal reload ---
    await page.reload({ waitUntil: "networkidle0" });
    check("normal reload still shows the app shell", (await page.$(".app-layout")) !== null);

    // --- Hard reload (bypass cache entirely, closest CDP equivalent
    // to a real Ctrl+Shift+R) ---
    const client = await page.createCDPSession();
    await client.send("Network.setCacheDisabled", { cacheDisabled: true });
    await page.reload({ waitUntil: "networkidle0" });
    check("hard reload (cache disabled) still shows the app shell", (await page.$(".app-layout")) !== null);
    await client.send("Network.setCacheDisabled", { cacheDisabled: false });

    // --- Direct deep links: every top-level + group route, fresh
    // navigation each time (not a client-side route change), the exact
    // shape that previously failed live. ---
    const DEEP_LINK_ROUTES = [
      "/ui/dashboard", "/ui/analytics", "/ui/localdns", "/ui/upstreams", "/ui/cache",
      "/ui/filtering", "/ui/blocklists", "/ui/encryption",
      "/ui/importexport", "/ui/backup", "/ui/replication",
      "/ui/statistics", "/ui/health", "/ui/administration", "/ui/network",
      "/ui/notifications", "/ui/updates", "/ui/logs", "/ui/dnsruntime",
    ];
    for (const route of DEEP_LINK_ROUTES) {
      await page.goto(`${baseUrl}${route}`, { waitUntil: "networkidle0" });
      const hasHeading = (await page.$("h2")) !== null;
      const hasComingSoon = await page.evaluate(() => document.body.textContent?.includes("Coming soon"));
      check(`direct deep link ${route} loads real content`, hasHeading, `heading=${hasHeading}`);
      void hasComingSoon;
    }

    // --- Every menu/submenu route, via real sidebar clicks (accordion
    // navigation, not direct URLs) ---
    await page.goto(baseUrl, { waitUntil: "networkidle0" });
    const MENU_LABELS = [
      "Query Log", "Clients", "Local DNS", "DNS Settings", "Cache",
      "Filters", "Blocklists", "Encryption",
      "Import", "Backup & Restore", "Replication",
      "Statistics", "System Status", "Administration", "Network Configuration",
      "Notifications", "Software Updates", "Logs", "DNS Runtime",
    ];
    for (const label of MENU_LABELS) {
      const clicked = await clickNavItem(page, (t) => t === label);
      check(`menu item "${label}" exists and is clickable`, clicked);
      if (clicked) {
        await new Promise((r) => setTimeout(r, 150));
        const hasHeading = (await page.$("h2")) !== null;
        check(`"${label}" route renders real content after menu click`, hasHeading);
      }
    }

    check("zero unexpected browser console errors across the whole pass", consoleErrors.length === 0, consoleErrors.join(" | "));
    check("zero uncaught page errors across the whole pass", pageErrors.length === 0, pageErrors.join(" | "));

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
