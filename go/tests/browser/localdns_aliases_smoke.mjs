// Real-Chromium coverage for Local DNS's new Client Aliases section.
// Usage: node localdns_aliases_smoke.mjs <base-url> <username> <password>
import puppeteer from "puppeteer-core";

const [, , baseUrl, username, password] = process.argv;
if (!baseUrl || !username || !password) {
  console.error("usage: node localdns_aliases_smoke.mjs <base-url> <username> <password>");
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
    const consoleErrors = [];
    page.on("console", (m) => { if (m.type() === "error") consoleErrors.push(m.text()); });

    await page.setViewport({ width: 1440, height: 900 });
    await page.goto(baseUrl, { waitUntil: "networkidle0" });
    await page.waitForSelector("#login-heading", { timeout: 5000 });
    await page.type('input[autocomplete="username"]', username);
    await page.type('input[autocomplete="current-password"]', password);
    await Promise.all([page.waitForSelector(".app-layout", { timeout: 5000 }), page.click('button[type="submit"]')]);

    async function clickNav(name) {
      const tryFind = async () => {
        for (const btn of await page.$$(".sidebar .item")) {
          if ((await btn.evaluate((el) => el.textContent.trim())) === name) { await btn.click(); return true; }
        }
        return false;
      };
      if (await tryFind()) return true;
      for (const toggle of await page.$$(".sidebar .group-toggle")) {
        await toggle.click();
        await new Promise((r) => setTimeout(r, 50));
        if (await tryFind()) return true;
      }
      return false;
    }

    check("Local DNS nav item exists and is clickable", await clickNav("Local DNS"));
    await page.waitForSelector("#localdns-heading", { timeout: 3000 });

    const aliasHeadingExists = await page.evaluate(() =>
      [...document.querySelectorAll("h2")].some((h) => h.textContent.trim() === "Client Aliases"),
    );
    check("Client Aliases panel heading renders", aliasHeadingExists);

    // Add a real alias.
    const aliasForm = await page.evaluateHandle(() => {
      const heading = [...document.querySelectorAll("h2")].find((h) => h.textContent.trim() === "Client Aliases");
      return heading.closest(".panel").querySelector("form.add-form");
    });
    const cidrInput = await aliasForm.asElement().$("input[placeholder='192.168.1.0/24']");
    const nameInput = await aliasForm.asElement().$("input[placeholder='Kids devices']");
    await cidrInput.type("192.168.50.0/24");
    await nameInput.type("Guest network");
    await Promise.all([
      page.waitForFunction(() => document.body.textContent.includes("Guest network"), { timeout: 3000 }),
      aliasForm.asElement().$eval("button[type=submit]", (el) => el.click()),
    ]);
    const panelText = await page.evaluate(() => {
      const heading = [...document.querySelectorAll("h2")].find((h) => h.textContent.trim() === "Client Aliases");
      return heading.closest(".panel").textContent;
    });
    check("creating a client alias adds a real entry", panelText.includes("192.168.50.0/24") && panelText.includes("Guest network"), panelText);

    // Reload: persistence proof.
    await page.reload({ waitUntil: "networkidle0" });
    await page.waitForSelector("#localdns-heading", { timeout: 5000 });
    const panelTextAfterReload = await page.evaluate(() => {
      const heading = [...document.querySelectorAll("h2")].find((h) => h.textContent.trim() === "Client Aliases");
      return heading ? heading.closest(".panel").textContent : "";
    });
    check("client alias persists across a full page reload", panelTextAfterReload.includes("Guest network"), panelTextAfterReload);

    // Remove it -- goes through the shared app-styled ConfirmDialog now,
    // not a native window.confirm() (see LocalDnsView.svelte's own
    // 2026-08-29 design-system unification).
    const removeClicked = await page.evaluate(() => {
      const heading = [...document.querySelectorAll("h2")].find((h) => h.textContent.trim() === "Client Aliases");
      const btn = [...heading.closest(".panel").querySelectorAll("button")].find((b) => b.textContent.trim() === "Remove");
      if (!btn) return false;
      btn.click();
      return true;
    });
    check("Remove button exists and is clickable", removeClicked);
    await page.waitForSelector(".modal .danger", { timeout: 3000 });
    await page.click(".modal .danger");
    await page.waitForSelector(".toast--success", { timeout: 3000 }).catch(() => null);
    check("removing an alias shows a real toast confirmation", !!(await page.$(".toast--success")));
    await new Promise((r) => setTimeout(r, 300));
    const panelTextAfterRemove = await page.evaluate(() => {
      const heading = [...document.querySelectorAll("h2")].find((h) => h.textContent.trim() === "Client Aliases");
      return heading.closest(".panel").textContent;
    });
    check("removing an alias actually removes it", !panelTextAfterRemove.includes("Guest network"), panelTextAfterRemove);

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
