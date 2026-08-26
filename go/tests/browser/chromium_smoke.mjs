// Real-Chromium smoke coverage for the Go/Svelte shell + whatever pages
// are wired in nav.ts. Run against a fresh instance (setup_required=true)
// -- see go/tests/browser/README.md. Not a mock: drives an actual
// headless Chromium via CDP (puppeteer-core, pointed at the system
// /usr/bin/chromium -- no bundled download).
//
// Usage: node chromium_smoke.mjs <base-url> <username> <password>
import puppeteer from "puppeteer-core";

const [, , baseUrl, username, password] = process.argv;
if (!baseUrl || !username || !password) {
  console.error("usage: node chromium_smoke.mjs <base-url> <username> <password>");
  process.exit(2);
}

const results = [];
function check(name, cond, detail) {
  results.push({ name, pass: !!cond, detail });
  console.log(`[${cond ? "PASS" : "FAIL"}] ${name}${!cond && detail ? " -- " + detail : ""}`);
}

const consoleErrors = [];
const pageErrors = [];

async function main() {
  const browser = await puppeteer.launch({
    executablePath: process.env.CHROMIUM_PATH || "/usr/bin/chromium",
    headless: true,
    args: ["--no-sandbox", "--disable-dev-shm-usage", "--ignore-certificate-errors"],
  });

  try {
    const page = await browser.newPage();
    page.on("console", (msg) => {
      if (msg.type() === "error") consoleErrors.push(msg.text());
    });
    page.on("pageerror", (err) => pageErrors.push(String(err)));

    await page.setViewport({ width: 1440, height: 900 });
    await page.goto(baseUrl, { waitUntil: "networkidle0" });

    // --- Setup ---
    await page.waitForSelector("#setup-heading, #login-heading", { timeout: 5000 });
    const onSetup = (await page.$("#setup-heading")) !== null;
    check("landed on setup screen for a fresh instance", onSetup);
    if (onSetup) {
      await page.type('input[autocomplete="username"]', username);
      await page.type('input[autocomplete="new-password"]', password);
      const confirmInputs = await page.$$('input[autocomplete="new-password"]');
      await confirmInputs[1].type(password);
      await Promise.all([
        page.waitForSelector("#login-heading", { timeout: 5000 }),
        page.click('button[type="submit"]'),
      ]);
      check("setup submission reaches the login screen", true);
    }

    // --- Login ---
    // The username field is intentionally pre-filled (carried over from
    // setup, a real product convenience) -- clear it first so we don't
    // append and log in with a garbled username.
    await page.$eval('input[autocomplete="username"]', (el) => (el.value = ""));
    await page.type('input[autocomplete="username"]', username);
    await page.type('input[autocomplete="current-password"]', password);
    await Promise.all([
      page.waitForSelector(".app-layout", { timeout: 5000 }),
      page.click('button[type="submit"]'),
    ]);
    check("login reaches the app shell", true);

    // --- Lands on the URL-synced default route with real rendered content ---
    await page.waitForFunction(() => location.pathname.startsWith("/ui/"), { timeout: 3000 });
    let path = new URL(page.url()).pathname;
    check("post-login URL is synced to a /ui/ route (not left at /)", path.startsWith("/ui/"), path);
    check("post-login landing route renders a real heading, not a coming-soon panel", (await page.$("h2")) !== null);

    // --- Dashboard: real (not fake) summary cards ---
    check("landed on Dashboard by default", path === "/ui/dashboard", path);
    await page.waitForSelector(".card .big", { timeout: 3000 }).catch(() => {});
    const cardCount = (await page.$$(".card")).length;
    check("Dashboard renders summary cards", cardCount >= 2, `found ${cardCount}`);
    const scopeNote = await page.$eval(".scope-note", (el) => el.textContent).catch(() => "");
    check("Dashboard discloses its own incomplete scope rather than implying full parity", scopeNote.includes("not migrated yet"), scopeNote);

    // --- Nav: Local DNS (click by visible text; XPath is gone from modern Puppeteer) ---
    const navButtons = await page.$$(".sidebar .item");
    let clicked = false;
    for (const btn of navButtons) {
      const text = await btn.evaluate((el) => el.textContent?.trim());
      if (text?.startsWith("Local DNS")) {
        await btn.click();
        clicked = true;
        break;
      }
    }
    check("Local DNS nav item exists and is clickable", clicked);
    await page.waitForFunction(() => location.pathname === "/ui/localdns", { timeout: 3000 }).catch(() => {});
    check("clicking Local DNS navigates to /ui/localdns", new URL(page.url()).pathname === "/ui/localdns");
    await page.waitForSelector("#localdns-heading", { timeout: 3000 });
    check("Local DNS page content rendered", true);

    // --- Nav: Administration ---
    const navButtons2 = await page.$$(".sidebar .item");
    clicked = false;
    for (const btn of navButtons2) {
      const text = await btn.evaluate((el) => el.textContent?.trim());
      if (text?.startsWith("Administration")) {
        await btn.click();
        clicked = true;
        break;
      }
    }
    check("Administration nav item exists and is clickable", clicked);
    await page.waitForSelector("#admin-heading", { timeout: 3000 }).catch(() => {});
    check("Administration page content rendered", (await page.$("#admin-heading")) !== null);

    // --- Timestamp mode: instant reformat, no reload ---
    const previewBefore = await page.$eval(".preview strong", (el) => el.textContent).catch(() => null);
    const utcRadio = await page.$$eval('input[name="ts-mode"]', (els) => els.length);
    check("three timestamp mode radios present", utcRadio === 3, `found ${utcRadio}`);
    const radios = await page.$$('input[name="ts-mode"]');
    await radios[2].click(); // UTC
    await new Promise((r) => setTimeout(r, 50));
    const previewAfter = await page.$eval(".preview strong", (el) => el.textContent).catch(() => null);
    check("timestamp preview updates instantly on mode change", previewAfter && previewAfter.includes("UTC"), previewAfter);

    // --- Change password: wrong current password is rejected ---
    const pwInputs = await page.$$('.stack-form input[type="password"]');
    await pwInputs[0].type("not the real password");
    await pwInputs[1].type("some new password 12+");
    await pwInputs[2].type("some new password 12+");
    await page.click('.stack-form button[type="submit"]');
    await page.waitForFunction(() => document.querySelector(".stack-form .error") !== null, { timeout: 3000 }).catch(() => {});
    check(
      "change-password rejects a wrong current password",
      (await page.$eval(".stack-form .error", (el) => el.textContent).catch(() => "")).includes("incorrect"),
    );

    // --- Change password: correct flow succeeds, and the new password actually works ---
    for (const input of pwInputs) await page.evaluate((el) => (el.value = ""), input);
    await pwInputs[0].type(password);
    await pwInputs[1].type("a brand new password 12+");
    await pwInputs[2].type("a brand new password 12+");
    await page.click('.stack-form button[type="submit"]');
    await page.waitForSelector(".stack-form .success", { timeout: 3000 }).catch(() => {});
    check("change-password succeeds with the correct current password", (await page.$(".stack-form .success")) !== null);

    // Prove it by logging out and back in with the new password.
    const logoutBtn = await page.$(".logout-btn");
    await logoutBtn.click();
    await page.waitForSelector("#login-heading", { timeout: 3000 });
    await page.$eval('input[autocomplete="username"]', (el) => (el.value = ""));
    await page.type('input[autocomplete="username"]', username);
    await page.type('input[autocomplete="current-password"]', "a brand new password 12+");
    await Promise.all([
      page.waitForSelector(".app-layout", { timeout: 5000 }),
      page.click('button[type="submit"]'),
    ]);
    check("the new password actually authenticates after logout", (await page.$(".app-layout")) !== null);

    // Re-navigate to Administration for the revoke-sessions check below.
    for (const btn of await page.$$(".sidebar .item")) {
      if ((await btn.evaluate((el) => el.textContent?.trim()))?.startsWith("Administration")) {
        await btn.click();
        break;
      }
    }
    await page.waitForSelector("#admin-heading", { timeout: 3000 }).catch(() => {});

    // --- Revoke other sessions ---
    const revokeBtn = await page.$(".danger");
    await revokeBtn.click();
    await new Promise((r) => setTimeout(r, 300));
    const revokeText = await page.$$eval(".card p.hint[role='status']", (els) => els.map((e) => e.textContent).join(" "));
    check("revoke-other-sessions reports a result", /revoked|no other sessions/i.test(revokeText), revokeText);

    // --- Theme toggle ---
    const themeBefore = await page.$eval("html", (el) => el.getAttribute("data-theme"));
    await page.click(".theme-toggle");
    await new Promise((r) => setTimeout(r, 50));
    const themeAfter = await page.$eval("html", (el) => el.getAttribute("data-theme"));
    check("theme toggle actually flips data-theme", themeBefore !== themeAfter, `${themeBefore} -> ${themeAfter}`);

    // --- Mobile viewport + drawer ---
    await page.setViewport({ width: 390, height: 844 });
    await new Promise((r) => setTimeout(r, 100));
    const menuVisible = await page.$eval(".menu-btn", (el) => getComputedStyle(el).display !== "none");
    check("menu button appears at 390px", menuVisible);
    await page.click(".menu-btn");
    await new Promise((r) => setTimeout(r, 150));
    const drawerOpen = await page.$eval(".sidebar", (el) => el.classList.contains("mobile-open"));
    check("clicking menu button opens the mobile drawer", drawerOpen);
    await page.keyboard.press("Escape");
    await new Promise((r) => setTimeout(r, 150));
    const drawerClosedAfterEscape = await page.$eval(".sidebar", (el) => !el.classList.contains("mobile-open"));
    check("Escape closes the mobile drawer", drawerClosedAfterEscape);
    const overflowX = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth);
    check("no page-level horizontal overflow at 390px", !overflowX);
    await page.setViewport({ width: 1440, height: 900 });

    // --- Blocklists: data grid sort, in-place table (real page with rows) ---
    const navButtons3 = await page.$$(".sidebar .item");
    clicked = false;
    for (const btn of navButtons3) {
      const text = await btn.evaluate((el) => el.textContent?.trim());
      if (text?.startsWith("Blocklists")) {
        await btn.click();
        clicked = true;
        break;
      }
    }
    check("Blocklists nav item exists and is clickable", clicked);
    await page.waitForSelector("#blocklists-heading", { timeout: 3000 }).catch(() => {});
    const gridPresent = (await page.$(".data-grid")) !== null;
    check("shared DataGrid renders on Blocklists", gridPresent);
    const sortableHeader = await page.$(".sort-btn");
    check("Blocklists grid has at least one sortable column header", sortableHeader !== null);

    // --- Console/runtime errors across the whole pass ---
    // Chromium itself (not app code) logs a "Failed to load resource:
    // ... status of 4xx/5xx" console entry for every non-2xx fetch --
    // unavoidable browser behavior, not something the app controls, and
    // *expected* here because this pass deliberately exercises negative
    // paths (wrong password, missing CSRF elsewhere). Only a real
    // application console.error (anything else) counts as a defect.
    const unexpectedConsoleErrors = consoleErrors.filter((e) => !/Failed to load resource: the server responded with a status of/.test(e));
    check("zero unexpected browser console errors across the whole pass", unexpectedConsoleErrors.length === 0, unexpectedConsoleErrors.join(" | "));
    check("zero uncaught page errors across the whole pass", pageErrors.length === 0, pageErrors.join(" | "));
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
