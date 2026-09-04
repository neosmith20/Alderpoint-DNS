// One-off screenshot capture for the manual visual-review pass: every
// real route x desktop/tablet/mobile x light/dark, saved as PNGs for
// Claude to actually look at (not just the programmatic hasHeading/
// overflowX checks chromium_smoke.mjs's own sweep already does).
//
// Usage: node screenshot_sweep.mjs <base-url> <username> <password> <out-dir>
import puppeteer from "puppeteer-core";
import fs from "fs";

const [, , baseUrl, username, password, outDir] = process.argv;
if (!baseUrl || !username || !password || !outDir) {
  console.error("usage: node screenshot_sweep.mjs <base-url> <username> <password> <out-dir>");
  process.exit(2);
}
fs.mkdirSync(outDir, { recursive: true });

const VIEWPORTS = [
  { name: "desktop", width: 1440, height: 900 },
  { name: "tablet", width: 1024, height: 900 },
  { name: "mobile", width: 390, height: 844 },
];

const ROUTES = [
  { path: "/ui/dashboard", heading: "#dashboard-heading", name: "dashboard" },
  { path: "/ui/analytics", heading: "#analytics-heading", name: "analytics" },
  { path: "/ui/clients", heading: "#clients-heading", name: "clients" },
  { path: "/ui/blocklists", heading: "#blocklists-heading", name: "blocklists" },
  { path: "/ui/allowlists", heading: "#allowlists-heading", name: "allowlists" },
  { path: "/ui/filtering", heading: "#filtering-heading", name: "filtering" },
  { path: "/ui/localdns", heading: "#localdns-heading", name: "localdns" },
  { path: "/ui/blocked-services", heading: "#blocked-services-heading", name: "blocked-services" },
  { path: "/ui/settings-general", heading: "#general-settings-heading", name: "settings-general" },
  { path: "/ui/upstreams", heading: "#dns-settings-heading", name: "upstreams-standard" },
  { path: "/ui/encryption", heading: "#encryption-heading", name: "encryption" },
  { path: "/ui/backup", heading: "#backup-heading", name: "backup" },
  { path: "/ui/updates", heading: "#updates-heading", name: "updates" },
  { path: "/ui/health", heading: "#health-heading", name: "health" },
  { path: "/ui/policy-entities", heading: "#policy-entities-heading", name: "policy-entities" },
  { path: "/ui/policies", heading: "#clients-access-heading", name: "policies-scope" },
  { path: "/ui/upstreams-routing", heading: "#upstreams-heading", name: "upstreams-routing" },
  { path: "/ui/cache", heading: "#cache-heading", name: "cache" },
  { path: "/ui/dnsruntime", heading: "#dnsruntime-heading", name: "dnsruntime" },
  { path: "/ui/replication", heading: "#replication-heading", name: "replication" },
  { path: "/ui/network", heading: "#network-heading", name: "network" },
  { path: "/ui/administration", heading: "#admin-heading", name: "administration" },
  { path: "/ui/audit", heading: "#audit-log-heading", name: "audit" },
  { path: "/ui/logs", heading: "#logs-heading", name: "logs" },
  { path: "/ui/notifications", heading: "#notifications-heading", name: "notifications" },
  { path: "/ui/importexport", heading: "#importexport-heading", name: "importexport" },
  { path: "/ui/statistics", heading: "#statistics-heading", name: "statistics" },
  { path: "/ui/setup-guide", heading: "#setup-guide-heading", name: "setup-guide" },
];

async function main() {
  const browser = await puppeteer.launch({
    executablePath: process.env.CHROMIUM_PATH || "/usr/bin/chromium",
    headless: true,
    args: ["--no-sandbox", "--disable-dev-shm-usage", "--ignore-certificate-errors"],
  });
  let manifest = [];
  try {
    let page = await browser.newPage();
    await page.setViewport({ width: 1440, height: 900 });
    await page.goto(baseUrl, { waitUntil: "networkidle0" });
    await page.waitForSelector("#login-heading", { timeout: 5000 });
    await page.type('input[autocomplete="username"]', username);
    await page.type('input[autocomplete="current-password"]', password);
    await Promise.all([page.waitForSelector(".app-layout", { timeout: 5000 }), page.click('button[type="submit"]')]);
    // Advanced profile so every route (including Advanced-only pages) is reachable/rendered as designed.
    await page.evaluate(() => localStorage.setItem("apdns-go-nav-profile", "advanced"));
    await page.reload({ waitUntil: "networkidle0" });

    for (const theme of ["light", "dark"]) {
      await page.setViewport({ width: 1440, height: 900 });
      const currentTheme = await page.$eval("html", (el) => el.getAttribute("data-theme"));
      if (currentTheme !== theme) {
        await page.click('button.bottom-item[title*="theme"]');
        await new Promise((r) => setTimeout(r, 80));
      }
      for (const vp of VIEWPORTS) {
        await page.close();
        page = await browser.newPage();
        await page.goto(baseUrl, { waitUntil: "networkidle0" });
        await page.setViewport({ width: vp.width, height: vp.height });
        for (const route of ROUTES) {
          await page.goto(`${baseUrl}${route.path}`, { waitUntil: "networkidle0" });
          await page.waitForSelector(route.heading, { timeout: 3000 }).catch(() => {});
          await new Promise((r) => setTimeout(r, 120));
          // App.svelte's own scroll container is `.app-layout main`
          // (overflow-y: auto), NOT the document body -- the outer
          // <html>/<body> never grows past the viewport, so Puppeteer's
          // own `fullPage: true` (which measures documentElement's
          // scrollHeight) silently captures only the visible viewport
          // and nothing below the fold. Measure the REAL scrollable
          // content height and grow the viewport to fit it instead --
          // `.app-layout`/`.content-col` are both `height: 100%`, so a
          // taller viewport makes the flex column tall enough that
          // `main` never needs to scroll, and one plain screenshot
          // captures everything.
          const contentHeight = await page.evaluate(() => {
            const main = document.querySelector(".app-layout main");
            const topbar = document.querySelector(".topbar");
            return (main ? main.scrollHeight : document.documentElement.scrollHeight) + (topbar ? topbar.getBoundingClientRect().height : 0);
          });
          // CDP's Emulation.setDeviceMetricsOverride requires an int32
          // height -- getBoundingClientRect() returns fractional
          // pixels, so an un-rounded contentHeight (e.g. 900.5) is a
          // real, previously-uncaught crash here (ProtocolError:
          // "int32 value expected"), not a cosmetic rounding nit.
          const shotHeight = Math.min(Math.max(Math.ceil(contentHeight) + 20, vp.height), 12000);
          if (shotHeight !== vp.height) {
            await page.setViewport({ width: vp.width, height: shotHeight });
          }
          const fname = `${route.name}__${vp.name}__${theme}.png`;
          await page.screenshot({ path: `${outDir}/${fname}` });
          if (shotHeight !== vp.height) {
            await page.setViewport({ width: vp.width, height: vp.height });
          }
          manifest.push(fname);
          console.log(`captured ${fname} (h=${shotHeight})`);
        }
      }
    }
  } finally {
    await browser.close();
  }
  fs.writeFileSync(`${outDir}/manifest.json`, JSON.stringify(manifest, null, 2));
  console.log(`\n${manifest.length} screenshots captured to ${outDir}`);
}

main().catch((err) => {
  console.error("HARNESS ERROR:", err);
  process.exit(1);
});
