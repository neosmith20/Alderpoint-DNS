// Focused, real-Chromium coverage for the sidebar's single-open
// accordion behavior specifically (open A -> open B closes A,
// direct-route navigation opens only that route's own parent section,
// desktop/collapsed-rail/mobile drawer all share the same behavior).
// Deliberately standalone from chromium_smoke.mjs (which needs a full
// analytics/query-log fixture pipeline this focused pass doesn't) --
// see that file's own equivalent inline checks for the same assertions
// exercised as part of the full suite.
//
// 2026-09: rewritten against the Standard/Advanced nav redesign -- group
// membership changed (Local DNS and Blocklists both moved into "Filters";
// Administration moved into the Advanced-only "Operations" group), so
// this now exercises Filters vs System (both Standard-visible, distinct
// groups) instead of the old dns/security/system split.
//
// Usage: node nav_accordion_smoke.mjs <base-url> <username> <password>
import puppeteer from "puppeteer-core";

const [, , baseUrl, username, password] = process.argv;
if (!baseUrl || !username || !password) {
  console.error("usage: node nav_accordion_smoke.mjs <base-url> <username> <password>");
  process.exit(2);
}

const results = [];
function check(name, cond, detail) {
  results.push({ name, pass: !!cond, detail });
  console.log(`[${cond ? "PASS" : "FAIL"}] ${name}${!cond && detail ? " -- " + detail : ""}`);
}

async function openPanelGroups(page, selector = ".sidebar .group") {
  return page.$$eval(selector, (groups) =>
    groups.filter((g) => g.querySelector(".panel")).map((g) => g.querySelector(".group-toggle")?.textContent?.trim()),
  );
}

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

    // Dashboard (top-level, not in any group) is the default landing
    // route -- no section should be open at all yet.
    let openGroups = await openPanelGroups(page);
    check("no sidebar section is open while on the top-level Dashboard route", openGroups.length === 0, JSON.stringify(openGroups));

    // --- Open A -> open B closes A (Filters vs System -- both Standard
    // nav, distinct groups) ---
    check("clicked Local DNS (Filters group)", await clickNavItem(page, (t) => t?.startsWith("Local DNS")));
    await page.waitForSelector("#localdns-heading", { timeout: 3000 });
    openGroups = await openPanelGroups(page);
    check("opening Local DNS opens exactly the Filters group", openGroups.length === 1 && openGroups[0]?.includes("Filters"), JSON.stringify(openGroups));

    check("clicked Backup & Restore (System group)", await clickNavItem(page, (t) => t?.startsWith("Backup & Restore")));
    await page.waitForSelector("#backup-heading, .backup", { timeout: 3000 });
    openGroups = await openPanelGroups(page);
    check("opening Backup & Restore closes Filters and opens exactly the System group", openGroups.length === 1 && openGroups[0]?.includes("System"), JSON.stringify(openGroups));
    const activeInPanel = await page.$$eval(".sidebar .panel .item.active", (els) => els.map((e) => e.textContent?.trim()));
    check("the active child stays visibly selected within the open section", activeInPanel.some((t) => t?.startsWith("Backup")), activeInPanel.join(","));

    // --- Direct-route navigation (not a sidebar click) opens only that
    // route's own parent section ---
    await page.goto(new URL("/ui/blocklists", baseUrl).toString(), { waitUntil: "networkidle0" });
    await page.waitForSelector("#blocklists-heading", { timeout: 3000 });
    openGroups = await openPanelGroups(page);
    check(
      "direct navigation to a child route opens only that child's own parent section",
      openGroups.length === 1 && openGroups[0]?.includes("Filters"),
      JSON.stringify(openGroups),
    );

    // --- Collapsed rail: flyouts are already inherently single-open
    // (only one flyoutGroup at a time) -- confirm clicking a second
    // group's toggle replaces the first flyout, not adds to it. ---
    await page.click(".rail-toggle");
    await new Promise((r) => setTimeout(r, 80));

    // Collapsed rail: the icon (all that's left once the label is
    // hidden) must be horizontally centered in its button, not flush
    // left against the button's own padding.
    const centering = await page.$eval(".sidebar.collapsed .top-level", (el) => {
      const btn = el.getBoundingClientRect();
      const icon = el.querySelector("svg")?.getBoundingClientRect();
      if (!icon) return null;
      const leftGap = icon.left - btn.left;
      const rightGap = btn.right - icon.right;
      return Math.abs(leftGap - rightGap);
    });
    check("collapsed rail: the icon is horizontally centered in its button", centering !== null && centering < 2, `gap difference=${centering}px`);

    const toggles = await page.$$(".sidebar.collapsed .group-toggle");
    let filtersToggle, systemToggle;
    for (const t of toggles) {
      const text = await t.evaluate((el) => el.textContent?.trim());
      if (text?.includes("Filters")) filtersToggle = t;
      if (text?.includes("System")) systemToggle = t;
    }
    await filtersToggle.click();
    await new Promise((r) => setTimeout(r, 80));
    let flyoutCount = await page.$$eval(".sidebar .flyout", (els) => els.length);
    check("collapsed rail: opening a flyout shows exactly one", flyoutCount === 1, `count=${flyoutCount}`);
    await systemToggle.click();
    await new Promise((r) => setTimeout(r, 80));
    flyoutCount = await page.$$eval(".sidebar .flyout", (els) => els.length);
    const flyoutLabel = await page.$eval(".sidebar .flyout .flyout-label", (el) => el.textContent).catch(() => "");
    check("collapsed rail: opening a different group's flyout replaces the previous one, not both open", flyoutCount === 1 && flyoutLabel.includes("System"), `count=${flyoutCount} label=${flyoutLabel}`);
    await page.click(".rail-toggle"); // back to expanded

    // --- Mobile drawer: same single-open accordion as desktop ---
    await page.setViewport({ width: 390, height: 844 });
    await new Promise((r) => setTimeout(r, 100));
    await page.click(".menu-btn");
    await new Promise((r) => setTimeout(r, 150));
    const drawerOpen = await page.$eval(".sidebar", (el) => el.classList.contains("mobile-open"));
    check("mobile menu button opens the drawer", drawerOpen);
    // Currently on /ui/blocklists -- the drawer should show "Filters" open.
    openGroups = await openPanelGroups(page, ".sidebar.mobile-open .group");
    check("mobile drawer opens the current route's own section", openGroups.length === 1 && openGroups[0]?.includes("Filters"), JSON.stringify(openGroups));

    let systemToggleMobile = null;
    for (const btn of await page.$$(".sidebar.mobile-open .group-toggle")) {
      if ((await btn.evaluate((el) => el.textContent?.trim())).includes("System")) {
        systemToggleMobile = btn;
        break;
      }
    }
    await systemToggleMobile.click();
    await new Promise((r) => setTimeout(r, 80));
    openGroups = await openPanelGroups(page, ".sidebar.mobile-open .group");
    check("opening a different section in the mobile drawer closes the previous one", openGroups.length === 1 && openGroups[0]?.includes("System"), JSON.stringify(openGroups));
    const stillOpen = await page.$eval(".sidebar", (el) => el.classList.contains("mobile-open"));
    check("toggling a section in the drawer does not close the drawer itself", stillOpen);

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
