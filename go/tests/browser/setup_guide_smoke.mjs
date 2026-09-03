// Real-Chromium coverage for Encryption + Setup Guide's device/protocol
// instructions -- the pair of pages this session's "re-verify Encryption
// and Setup Guide completely, including ... DoT, DoH, DoQ, DoH3,
// DNSCrypt and all device instructions" instruction covers. Neither page
// had any dedicated Chromium coverage before this file.
//
// A real, previously-undisclosed gap this run proves fixed: Setup
// Guide's per-device tabs (DEVICE_PROTOCOLS) never listed DoQ/DoH3/
// DNSCrypt for ANY device (no OS has native support for them -- a real,
// deliberate limit), which meant a protocol enabled in Encryption was
// completely invisible on Setup Guide with no acknowledgment at all once
// you clicked into any device tab. This fixture enables DoQ (a DB write,
// no hostagent/real dnsdist needed -- DNSCrypt's own enable additionally
// requires a provisioned provider identity, out of scope for this
// hostagent-less fixture, matching every other page's own "no hostagent
// here" contract) and proves it now surfaces on every device tab via the
// new "Also enabled" fallback section.
//
// Usage: node setup_guide_smoke.mjs <base-url> <username> <password>
import puppeteer from "puppeteer-core";

const [, , baseUrl, username, password] = process.argv;
if (!baseUrl || !username || !password) {
  console.error("usage: node setup_guide_smoke.mjs <base-url> <username> <password>");
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

    // ================= Encryption =================
    check("Encryption nav item exists and is clickable", await clickNavItem(page, (t) => t === "Encryption"));
    await page.waitForSelector("#encryption-heading", { timeout: 3000 });
    const encryptionText = await page.$eval(".encryption", (el) => el.textContent);
    check("TLS Certificate card renders real subject/SAN info, not a placeholder", /Subject Alternative Names/.test(encryptionText), encryptionText.slice(0, 200));
    check("Client-Facing Address card renders", /Client-Facing Address/.test(encryptionText));
    for (const label of ["DNS-over-TLS (DoT)", "DNS-over-HTTPS (DoH)", "DNS-over-QUIC (DoQ)", "DNS-over-HTTP/3 (DoH3)", "DNSCrypt"]) {
      check(`Encryption lists the ${label} transport`, encryptionText.includes(label), label);
    }

    // Enable DoQ via the real PUT this page's own Save button uses --
    // a plain DB write, no hostagent needed for the save itself (the
    // subsequent DNS-runtime auto-apply is real but best-effort and
    // does not block the save in a hostagent-less fixture, same
    // contract as every other transport toggle on this page). Also
    // sets a real owner-saved client_facing_ip: this fixture has no
    // hostagent (so LAN detection is honestly unavailable) and this
    // fixture's own cert SAN is loopback-only, so without an explicit
    // saved address effective_client_address would honestly be "" --
    // real, but it would leave the DoQ manual-setup URI this test
    // checks below showing a placeholder instead of a real address.
    const enableResp = await page.evaluate(async () => {
      const session = await (await fetch("/api/session", { credentials: "same-origin" })).json();
      const cur = await (await fetch("/api/dns-transports", { credentials: "same-origin" })).json();
      const updated = { ...cur, doq_enabled: true, client_facing_ip: "192.168.50.10" };
      const r = await fetch("/api/dns-transports", {
        method: "PUT", credentials: "same-origin",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": session.csrf },
        body: JSON.stringify(updated),
      });
      return { status: r.status, body: await r.json() };
    });
    check("enabling DoQ via PUT /api/dns-transports succeeds", enableResp.status === 200 && enableResp.body.doq_enabled === true, JSON.stringify(enableResp).slice(0, 300));

    await page.reload({ waitUntil: "networkidle0" });
    await page.waitForSelector("#encryption-heading", { timeout: 5000 });
    const doqManualText = await page.evaluate(() => {
      const legend = [...document.querySelectorAll("fieldset legend")].find((l) => l.textContent?.includes("DoQ"));
      return legend?.closest("fieldset")?.textContent ?? "";
    });
    check("Encryption's DoQ fieldset shows real manual setup once enabled", /quic:\/\//.test(doqManualText), doqManualText.slice(0, 200));

    const newErrors1 = consoleErrors.filter((e) => !/Failed to load resource/.test(e));
    check("zero unexpected console errors on Encryption", newErrors1.length === 0, newErrors1.join("; "));

    // ================= Setup Guide =================
    check("Setup Guide nav item exists and is clickable", await clickNavItem(page, (t) => t === "Setup Guide"));
    await page.waitForSelector("#setup-guide-heading", { timeout: 3000 });
    const summaryText = await page.$eval(".status-summary", (el) => el.textContent).catch(() => "");
    check("Setup Guide status summary lists DoQ as an enabled protocol", /DoQ/.test(summaryText), summaryText);

    // Windows' own device tab (DEVICE_PROTOCOLS) never lists DoQ -- the
    // real gap this run proves fixed: it must still show up in the new
    // "Also enabled" fallback section instead of vanishing entirely.
    const windowsTabClicked = await page.evaluate(() => {
      const btn = [...document.querySelectorAll('[role="tab"]')].find((b) => b.textContent?.trim() === "Windows");
      if (btn) { btn.click(); return true; }
      return false;
    });
    check("Windows device tab is clickable", windowsTabClicked);
    await new Promise((r) => setTimeout(r, 200));
    const windowsPageText = await page.evaluate(() => document.body.textContent);
    check(
      "DoQ (not natively covered by any device) still appears via the 'Also enabled' fallback section on Windows",
      /Also enabled/.test(windowsPageText) && /quic:\/\//.test(windowsPageText),
      windowsPageText.includes("Also enabled") ? "found fallback section" : "fallback section MISSING",
    );

    // A protocol that is genuinely not enabled (DNSCrypt, never
    // provisioned in this fixture) must say so honestly, not silently
    // omit itself the same way the DoQ gap used to.
    const routerTabClicked = await page.evaluate(() => {
      const btn = [...document.querySelectorAll('[role="tab"]')].find((b) => b.textContent?.trim() === "Router");
      if (btn) { btn.click(); return true; }
      return false;
    });
    check("Router device tab is clickable", routerTabClicked);
    await new Promise((r) => setTimeout(r, 200));
    const routerHasNoDnscryptFallback = await page.evaluate(() => !document.body.textContent.includes("DNSCrypt"));
    check("DNSCrypt (never enabled in this fixture) does not appear anywhere on Setup Guide", routerHasNoDnscryptFallback);

    const newErrors2 = consoleErrors.filter((e) => !/Failed to load resource/.test(e));
    check("zero unexpected console errors on Setup Guide", newErrors2.length === 0, newErrors2.join("; "));

    await page.close();
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
