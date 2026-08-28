// Real-Chromium coverage for the first-run bootstrap-gated setup flow
// (internal/bootstrap) -- a genuinely security-relevant workflow, not
// just a UI smoke check: an unauthenticated LAN client racing to claim
// a fresh appliance is exactly the threat this proves is closed.
//
// Requires a FRESH instance (setup_required=true) whose bootstrap
// token file is readable at the path given as argv[3] -- the disposable
// fixture that drives this script controls that path directly (see the
// -bootstrap-token-path flag), the same way any real deployment would
// read it from its own startup log/console rather than a file, but a
// file is simpler for a script to read deterministically.
//
// Usage: node setup_bootstrap_smoke.mjs <base-url> <owner-password> <bootstrap-token-path> <db-path>
import fs from "node:fs";
import puppeteer from "puppeteer-core";

const [, , baseUrl, password, tokenPath, dbPath] = process.argv;
if (!baseUrl || !password || !tokenPath || !dbPath) {
  console.error("usage: node setup_bootstrap_smoke.mjs <base-url> <owner-password> <bootstrap-token-path> <db-path>");
  process.exit(2);
}

const results = [];
function check(name, cond, detail) {
  results.push({ name, pass: !!cond, detail });
  console.log(`[${cond ? "PASS" : "FAIL"}] ${name}${!cond && detail ? " -- " + detail : ""}`);
}

function readRealToken() {
  return fs.readFileSync(tokenPath, "utf8").trim();
}

async function newPage(browser) {
  const page = await browser.newPage();
  page.setDefaultTimeout(8000);
  return page;
}

async function main() {
  const browser = await puppeteer.launch({
    executablePath: process.env.CHROMIUM_PATH || "/usr/bin/chromium",
    headless: true,
    ignoreHTTPSErrors: true,
    args: ["--no-sandbox", "--disable-dev-shm-usage"],
  });

  try {
    // --- 1. Rejected invalid bootstrap token -----------------------
    {
      const page = await newPage(browser);
      await page.goto(baseUrl, { waitUntil: "networkidle0" });
      await page.waitForSelector("#bootstrap-heading", { timeout: 8000 });
      check("fresh instance lands on the bootstrap screen, not a bare setup form", (await page.$("#bootstrap-heading")) !== null);

      await page.type('input[autocomplete="off"]', "0000000000000000000000000000000000000000000000000000000000000000");
      await page.click('button[type="submit"]');
      await new Promise((r) => setTimeout(r, 500));
      check("invalid bootstrap token is rejected, stays on bootstrap screen", (await page.$("#bootstrap-heading")) !== null);
      const errText = await page.$eval(".error", (el) => el.textContent).catch(() => "");
      check("a real error is shown for the invalid token", errText.length > 0, errText);
      await page.close();
    }

    // --- 2. Clean first-run setup with the REAL token ---------------
    let realToken = readRealToken();
    {
      const page = await newPage(browser);
      await page.goto(baseUrl, { waitUntil: "networkidle0" });
      await page.waitForSelector("#bootstrap-heading", { timeout: 8000 });
      const input = await page.$('input[autocomplete="off"]');
      await input.click({ clickCount: 3 });
      await input.type(realToken);
      await page.click('button[type="submit"]');
      await page.waitForSelector("#setup-heading", { timeout: 8000 });
      check("real bootstrap token advances to the real account-creation form", (await page.$("#setup-heading")) !== null);

      await page.type('input[autocomplete="username"]', "owner");
      const pwInputs = await page.$$('input[autocomplete="new-password"]');
      await pwInputs[0].type(password);
      await pwInputs[1].type(password);
      const checkbox = await page.$('input[type="checkbox"]');
      if (checkbox) await checkbox.click(); // skip local-dns creation for this fixture
      await page.click('button[type="submit"]');
      await page.waitForSelector("#login-heading", { timeout: 8000 });
      check("setup completes and reaches the real login screen", (await page.$("#login-heading")) !== null);

      // The username field is the SAME bound value carried over from
      // the setup form above (App.svelte reuses one `username` state
      // across phases) -- it already reads "owner", so clear it first
      // rather than typing into it again (which would append, not
      // replace, producing "ownerowner" and a real login failure).
      // Triple-click-to-select-all is unreliable on inputs in headless
      // Chromium (a real, previously-documented finding elsewhere in
      // this codebase) -- clear the value directly instead.
      const userField = await page.$('input[autocomplete="username"]');
      await userField.evaluate((el) => {
        el.value = "";
        el.dispatchEvent(new Event("input", { bubbles: true }));
      });
      await userField.type("owner");
      await page.type('input[autocomplete="current-password"]', password);
      await page.click('button[type="submit"]');
      await page.waitForFunction(() => location.pathname.startsWith("/ui/"), { timeout: 8000 });
      const path = await page.evaluate(() => location.pathname);
      check("first real login reaches the app shell (not stuck on login)", path.startsWith("/ui/"), path);
      await page.close();
    }

    // --- 3. Setup route is permanently locked out after completion --
    // (plain Node fetch, not page.evaluate -- these are API-only checks,
    // no browser context/origin needed)
    {
      const statusResp = await fetch(baseUrl + "/api/setup/status");
      const status = await statusResp.json();
      check("GET /api/setup/status now reports setup_required=false", status.setup_required === false, JSON.stringify(status));

      const bootResp = await fetch(baseUrl + "/api/setup/bootstrap", {
        method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ token: realToken }),
      });
      check("re-presenting the ORIGINAL real token after completion is rejected", bootResp.status !== 200, `status=${bootResp.status}`);
    }

    // --- 4. Second-owner creation is rejected (even bypassing the UI) --
    {
      const resp = await fetch(baseUrl + "/api/setup", {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ username: "second-owner", password: "another-real-password-1", confirm_password: "another-real-password-1", create_local_dns: false }),
      });
      check("a direct POST /api/setup after completion is rejected (no bootstrap session)", resp.status !== 200, `status=${resp.status}`);
    }

    // --- 5. The owner ACCOUNT persists (real re-authentication with
    //        the same credentials succeeds again), proven against a
    //        real credential check rather than an already-valid
    //        session cookie carrying the browser through -- clear
    //        cookies first so this is a genuine fresh login, not the
    //        earlier session silently continuing. Real persistence
    //        across an actual process restart is exercised separately
    //        by the caller restarting the process between two
    //        invocations of this script against the same --db path
    //        (see AGENT_PROGRESS.md for that run's own log).
    {
      const page = await newPage(browser);
      const client = await page.createCDPSession();
      await client.send("Network.clearBrowserCookies");
      await page.goto(baseUrl, { waitUntil: "networkidle0" });
      await page.waitForSelector("#login-heading", { timeout: 8000 });
      await page.type('input[autocomplete="username"]', "owner");
      await page.type('input[autocomplete="current-password"]', password);
      await page.click('button[type="submit"]');
      await page.waitForFunction(() => location.pathname.startsWith("/ui/"), { timeout: 8000 });
      const path = await page.evaluate(() => location.pathname);
      check("owner can log in again on a fresh page load (post-restart if the caller restarted the process)", path.startsWith("/ui/"), path);
      await page.close();
    }
  } finally {
    await browser.close();
  }

  const failed = results.filter((r) => !r.pass);
  console.log(`\n${results.length - failed.length}/${results.length} checks passed`);
  if (failed.length > 0) process.exit(1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
