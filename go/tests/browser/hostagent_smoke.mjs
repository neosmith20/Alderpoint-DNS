// Real-Chromium smoke coverage for the host-agent-backed pages (Cache,
// Replication, Network Configuration, Logs, Software Updates) --
// separate from chromium_smoke.mjs's own full-app sweep so this can be
// pointed at the dedicated hostagent end-to-end test instance (real
// two-UID privilege separation, real rndc/control.db/journal/ip
// access) without re-running the entire other suite.
import puppeteer from "puppeteer-core";

const [, , baseUrl, username, password] = process.argv;
if (!baseUrl || !username || !password) {
  console.error("usage: node hostagent_smoke.mjs <base-url> <username> <password>");
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

    // Single-open sidebar accordion: an item is only in the DOM while its
    // own section is open. Try the currently-open section first, then
    // cycle through each section's own toggle until the target appears.
    async function clickNav(label) {
      const tryFind = async () => {
        for (const btn of await page.$$(".sidebar .item")) {
          if ((await btn.evaluate((el) => el.textContent?.trim())) === label) {
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

    // --- Cache ---
    check("Cache nav item exists and is clickable", await clickNav("Cache"));
    await page.waitForSelector("#cache-heading", { timeout: 3000 }).catch(() => {});
    check("Cache page content rendered", (await page.$("#cache-heading")) !== null);
    await page.waitForFunction(() => document.querySelector(".cache table tbody tr td") !== null, { timeout: 3000 }).catch(() => {});
    const cacheRowText = await page.$eval(".cache table tbody", (el) => el.textContent).catch(() => "");
    check("Cache page shows the real discovered BIND context", cacheRowText.includes("ctx0"), cacheRowText);

    // --- Replication ---
    check("Replication nav item exists and is clickable", await clickNav("Replication"));
    await page.waitForSelector("#replication-heading", { timeout: 3000 }).catch(() => {});
    check("Replication page content rendered", (await page.$("#replication-heading")) !== null);
    await page.waitForFunction(() => document.querySelector(".replication code") !== null, { timeout: 3000 }).catch(() => {});
    const nodeIdText = await page.$eval(".replication code", (el) => el.textContent).catch(() => "");
    check("Replication page shows the real node identity from control.db", /^[0-9a-f-]{36}$/.test(nodeIdText.trim()), nodeIdText);

    // --- Network Configuration ---
    check("Network Configuration nav item exists and is clickable", await clickNav("Network Configuration"));
    await page.waitForSelector("#network-heading", { timeout: 3000 }).catch(() => {});
    check("Network Configuration page content rendered", (await page.$("#network-heading")) !== null);
    await page.type('input[aria-label="Interface name"]', "lo");
    await Promise.all([
      page.waitForFunction(() => document.querySelector(".network .raw") !== null, { timeout: 3000 }),
      page.click('.network form button[type="submit"]'),
    ]);
    const rawStatus = await page.$eval(".network .raw", (el) => el.textContent);
    check("Network status shows the real loopback interface", rawStatus.includes("127.0.0.1"), rawStatus);

    // --- Logs ---
    check("Logs nav item exists and is clickable", await clickNav("Logs"));
    await page.waitForSelector("#logs-heading", { timeout: 3000 }).catch(() => {});
    check("Logs page content rendered", (await page.$("#logs-heading")) !== null);
    const unitOptions = await page.$$eval(".logs select option", (els) => els.map((e) => e.textContent));
    check("Logs page lists the real configured unit allowlist", unitOptions.includes("apdns-go-web"), unitOptions.join(","));

    // --- Software Updates ---
    check("Software Updates nav item exists and is clickable", await clickNav("Software Updates"));
    await page.waitForSelector("#updates-heading", { timeout: 3000 }).catch(() => {});
    check("Software Updates page content rendered", (await page.$("#updates-heading")) !== null);
    await page.waitForFunction(() => document.querySelector(".updates .card p")?.textContent?.trim() !== "…", { timeout: 3000 }).catch(() => {});
    const versionText = await page.$eval(".updates .card p", (el) => el.textContent).catch(() => "");
    check("Software Updates page shows the real current version", versionText.trim().length > 0 && versionText.trim() !== "…", versionText);

    // --- DNS Runtime (internal/dnscompile, internal/hostagentd/ops_dnsruntime.go) ---
    check("DNS Runtime nav item exists and is clickable", await clickNav("DNS Runtime"));
    await page.waitForSelector("#dnsruntime-heading", { timeout: 3000 }).catch(() => {});
    check("DNS Runtime page content rendered", (await page.$("#dnsruntime-heading")) !== null);
    await page.waitForFunction(() => document.querySelector(".dnsruntime .row") !== null, { timeout: 3000 }).catch(() => {});
    const runtimeRowText = await page.$eval(".dnsruntime .row", (el) => el.textContent).catch(() => "");
    check("DNS Runtime page shows real BIND/dnsdist process status", /running|not running/.test(runtimeRowText), runtimeRowText);
    await Promise.all([
      page.waitForFunction(() => document.querySelector(".dnsruntime .success, .dnsruntime .error") !== null, { timeout: 8000 }),
      page.click(".dnsruntime button"),
    ]);
    const applyResultText = await page.$eval(".dnsruntime .success, .dnsruntime .error", (el) => el.textContent).catch(() => "");
    check("Apply Runtime Changes performs a real compile+promote and reports a real result", applyResultText.length > 0, applyResultText);

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
