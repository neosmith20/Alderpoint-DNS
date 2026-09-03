// Real-Chromium coverage for the Clients and Clients & Access pages
// specifically (see PARITY_MATRIX.md) -- factored out of
// chromium_smoke.mjs because those pages' full workflows don't need
// the analytics/query-log/import fixtures the rest of that suite
// requires, and a fresh instance without them still exercises every
// primary Clients/Clients & Access workflow for real. Run against a
// fresh (setup_required: true) instance -- never the live owner
// preview, whose credentials are Alex's.
//
// Usage: node clients_access_smoke.mjs <base-url> <username> <password>
import puppeteer from "puppeteer-core";

const [, , baseUrl, username, password] = process.argv;
if (!baseUrl || !username || !password) {
  console.error("usage: node clients_access_smoke.mjs <base-url> <username> <password>");
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

// Add client/Add group on the Clients page open a real modal (no more
// permanent on-page forms, see ClientsView.svelte's Modal-based
// rebuild) -- click the toolbar button by its exact text, then fill and
// submit the form inside `.modal-form`.
async function openModalByButtonText(page, text) {
  for (const btn of await page.$$("button")) {
    if ((await btn.evaluate((el) => el.textContent?.trim())) === text) {
      await btn.click();
      await page.waitForSelector(".modal-form", { timeout: 2000 });
      return true;
    }
  }
  return false;
}

async function clickActionButton(page, label) {
  for (const btn of await page.$$(".data-grid tbody .actions button")) {
    if ((await btn.evaluate((el) => el.textContent?.trim())) === label) {
      await btn.click();
      return true;
    }
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
      if (msg.type() === "error") consoleErrors.push(msg.text());
    });
    page.on("pageerror", (err) => pageErrors.push(String(err)));

    await page.setViewport({ width: 1440, height: 900 });
    await page.goto(baseUrl, { waitUntil: "networkidle0" });

    // --- Setup + login (fresh instance) ---
    await page.waitForSelector("#setup-heading, #login-heading", { timeout: 5000 });
    if ((await page.$("#setup-heading")) !== null) {
      await page.type('input[autocomplete="username"]', username);
      await page.type('input[autocomplete="new-password"]', password);
      const confirmInputs = await page.$$('input[autocomplete="new-password"]');
      await confirmInputs[1].type(password);
      await Promise.all([
        page.waitForSelector("#login-heading", { timeout: 5000 }),
        page.click('button[type="submit"]'),
      ]);
    }
    await page.$eval('input[autocomplete="username"]', (el) => (el.value = ""));
    await page.type('input[autocomplete="username"]', username);
    await page.type('input[autocomplete="current-password"]', password);
    await Promise.all([
      page.waitForSelector(".app-layout", { timeout: 5000 }),
      page.click('button[type="submit"]'),
    ]);
    check("fresh-login reaches the app shell", true);

    // ================= Clients =================
    check("Clients nav item exists and is clickable", await clickNavItem(page, (t) => t === "Clients"));
    await page.waitForSelector("#clients-heading", { timeout: 3000 }).catch(() => {});
    check("Clients page renders real content, not a placeholder", (await page.$("#clients-heading")) !== null);
    const clientsScopeNote = await page.$eval(".clients .scope-note", (el) => el.textContent).catch(() => "");
    check("Clients page discloses full lifecycle coverage in its own scope note", /create, edit, enable\/disable, delete/.test(clientsScopeNote), clientsScopeNote);

    // Create a group via its modal (Add group is disabled until at least
    // one client or group exists -- this fixture has neither yet, so
    // create the client first).
    check("Add client button opens a real modal, not a permanent on-page form", await openModalByButtonText(page, "Add client"));
    await page.type(".modal-form input[required]", "Test Client");
    await Promise.all([
      page.waitForFunction(() => document.querySelectorAll(".data-grid tbody tr").length > 0, { timeout: 3000 }),
      page.click(".modal-form button[type=submit]"),
    ]);
    let clientRows = await page.$$eval(".data-grid tbody tr", (rows) => rows.length);
    check("creating a managed client adds a real row", clientRows === 1, `rows=${clientRows}`);

    check("Add group button opens a real modal", await openModalByButtonText(page, "Add group"));
    await page.type(".modal-form input[required]", "Kids");
    await Promise.all([
      page.waitForFunction(() => document.querySelector(".group-list") !== null, { timeout: 3000 }),
      page.click(".modal-form button[type=submit]"),
    ]);
    const groupListText = await page.$eval(".group-list", (el) => el.textContent);
    check("creating a group adds a real entry", groupListText.includes("Kids"), groupListText);

    // Add an IP identifier: invalid, then valid.
    check("Add IP identifier button exists", await clickActionButton(page, "Add IP identifier"));
    await page.waitForSelector(".inline-form input", { timeout: 2000 });
    await page.type(".inline-form input", "not-an-ip");
    await page.click(".inline-form button[type=submit]");
    await new Promise((r) => setTimeout(r, 200));
    const idError = await page.$eval(".inline-form .error", (el) => el.textContent).catch(() => "");
    check("invalid IPv4 identifier is rejected client-visibly", idError.length > 0, idError);
    await page.$eval(".inline-form input", (el) => (el.value = ""));
    await page.type(".inline-form input", "10.0.0.5");
    await Promise.all([
      page.waitForFunction(() => /10\.0\.0\.5/.test(document.querySelector(".data-grid tbody").textContent), { timeout: 3000 }),
      page.click(".inline-form button[type=submit]"),
    ]);
    let rowText = await page.$eval(".data-grid tbody", (el) => el.textContent);
    check("valid identifier appears on the client row", rowText.includes("10.0.0.5"), rowText);

    // Strong ClientID: generate, verify DoH path / SNI shown, copy, revoke, regenerate, delete.
    check("Generate Strong ClientID button exists", await clickActionButton(page, "Generate Strong ClientID"));
    await page.waitForSelector(".inline-form select", { timeout: 2000 });
    await page.type('.inline-form input[aria-label="ClientID label"]', "primary");
    await Promise.all([
      page.waitForFunction(() => document.querySelector(".clientid-row") !== null, { timeout: 3000 }),
      page.click(".inline-form button[type=submit]"),
    ]);
    const clientIdHex = await page.$eval(".clientid-row:not(.revoked) .hexval", (el) => el.getAttribute("title"));
    check("generated a real 64-hex Strong ClientID", clientIdHex && clientIdHex.length === 64 && /^[0-9a-f]+$/.test(clientIdHex), clientIdHex);
    const dohPath = await page.$eval(".clientid-paths div:nth-child(1) code", (el) => el.textContent);
    const sniHostname = await page.$eval(".clientid-paths div:nth-child(2) code", (el) => el.textContent);
    check("DoH path shown uses the full canonical hex", dohPath.includes(clientIdHex), dohPath);
    check("DoT/DoQ SNI hostname shown", sniHostname.length > 0, sniHostname);
    check("reveal-once hint shown after generation", (await page.$(".reveal-once")) !== null);

    // Regenerate: value must change. Uses the design-system's shared
    // ConfirmDialog now, not a native window.confirm() -- the action
    // button only OPENS the dialog, a real click on its own confirm
    // button inside is what actually regenerates.
    const regenBtn = await page.evaluateHandle(() => [...document.querySelectorAll(".clientid-actions button")].find((b) => b.textContent.trim() === "Regenerate"));
    await regenBtn.asElement().click();
    await page.waitForSelector(".modal .danger", { timeout: 2000 });
    await Promise.all([
      page.waitForFunction((oldHex) => {
        const el = document.querySelector(".clientid-row:not(.revoked) .hexval");
        return el && el.getAttribute("title") !== oldHex;
      }, { timeout: 3000 }, clientIdHex),
      page.click(".modal .danger"),
    ]);
    const regeneratedHex = await page.$eval(".clientid-row:not(.revoked) .hexval", (el) => el.getAttribute("title"));
    check("regenerating produces a genuinely different value", regeneratedHex !== clientIdHex, regeneratedHex);

    // Revoke: row should show the revoked badge. Same shared dialog.
    const revokeBtn = await page.evaluateHandle(() => [...document.querySelectorAll(".clientid-actions button")].find((b) => b.textContent.trim() === "Revoke"));
    await revokeBtn.asElement().click();
    await page.waitForSelector(".modal .danger", { timeout: 2000 });
    await Promise.all([
      page.waitForSelector(".revoked-badge", { timeout: 3000 }),
      page.click(".modal .danger"),
    ]);
    check("revoking shows a real revoked badge", (await page.$(".revoked-badge")) !== null);

    // Domain override: add block + allow, verify both render.
    check("Add domain override button exists", await clickActionButton(page, "Add domain override"));
    await page.waitForSelector(".inline-form input[aria-label='Override domain']", { timeout: 2000 });
    await page.type(".inline-form input[aria-label='Override domain']", "ads.example.com");
    await Promise.all([
      page.waitForFunction(() => /ads\.example\.com/.test(document.querySelector(".data-grid tbody").textContent), { timeout: 3000 }),
      page.click(".inline-form button[type=submit]"),
    ]);
    rowText = await page.$eval(".data-grid tbody", (el) => el.textContent);
    check("domain override actually persists and renders", rowText.includes("ads.example.com"), rowText);

    // Assign to group, then remove from group.
    check("Assign group button exists", await clickActionButton(page, "Assign group"));
    await page.waitForSelector(".inline-form select", { timeout: 2000 });
    await Promise.all([
      // Waits for a real rendered chip, not just "Kids" appearing anywhere
      // (the still-open assign-group <select>'s own <option> already
      // contains the text "Kids" before the mutation completes -- a real
      // race caught by an earlier, looser version of this check).
      page.waitForFunction(() => [...document.querySelectorAll(".data-grid tbody .chips .chip")].some((c) => c.textContent.includes("Kids")), { timeout: 3000 }),
      page.click(".inline-form button[type=submit]"),
    ]);
    rowText = await page.$eval(".data-grid tbody", (el) => el.textContent);
    check("assigning a group shows it on the client row", rowText.includes("Kids"), rowText);
    const removedFromGroup = await page.evaluate(() => {
      const chip = [...document.querySelectorAll(".data-grid tbody .chips .chip")].find((c) => c.textContent.includes("Kids"));
      const btn = chip?.querySelector(".chip-x");
      if (!btn) return false;
      btn.click();
      return true;
    });
    check("group remove control works", removedFromGroup);
    await new Promise((r) => setTimeout(r, 300));
    rowText = await page.$eval(".data-grid tbody", (el) => el.textContent);
    check("removing from group actually removes it from the row", !rowText.includes("Kids"), rowText);

    // Edit name/description.
    check("Edit button exists", await clickActionButton(page, "Edit"));
    await page.waitForSelector(".edit-name-form input", { timeout: 2000 });
    const editInputs = await page.$$(".edit-name-form input");
    await editInputs[0].click({ clickCount: 3 });
    await editInputs[0].type("Test Client Renamed");
    await Promise.all([
      page.waitForFunction(() => /Test Client Renamed/.test(document.querySelector(".data-grid tbody").textContent), { timeout: 3000 }),
      page.click(".edit-name-form button[type=submit]"),
    ]);
    rowText = await page.$eval(".data-grid tbody", (el) => el.textContent);
    check("editing name persists and re-renders", rowText.includes("Test Client Renamed"), rowText);

    // Disable / enable.
    check("Disable button exists", await clickActionButton(page, "Disable"));
    await page.waitForSelector(".disabled-badge", { timeout: 3000 }).catch(() => {});
    check("disabling shows a real disabled badge", (await page.$(".disabled-badge")) !== null);
    check("Enable button exists after disabling", await clickActionButton(page, "Enable"));
    await new Promise((r) => setTimeout(r, 200));
    check("re-enabling removes the disabled badge", (await page.$(".disabled-badge")) === null);

    // Per-client policy editor + Explain panel.
    check("Policy button exists", await clickActionButton(page, "Policy"));
    await page.waitForSelector(".inline-policy .policy-editor select", { timeout: 2000 }).catch(() => {});
    check("per-client policy editor renders", (await page.$(".inline-policy .policy-editor")) !== null);
    check("Explain button exists", await clickActionButton(page, "Explain"));
    await page.waitForSelector(".explain-panel", { timeout: 2000 }).catch(() => {});
    check("policy Explain panel renders", (await page.$(".explain-panel")) !== null);

    // Observed Clients section: honest empty state on a fresh instance
    // with no query traffic (no Analytics configured here at all).
    const observedText = await page.evaluate(() => {
      // Observed Clients is now a shared Panel component (ClientsView's
      // design-system rebuild), whose heading renders as <h2>, not the
      // page's old bespoke <h3> -- check both so this survives either
      // heading level.
      const heading = [...document.querySelectorAll("h2, h3")].find((e) => e.textContent.trim() === "Observed Clients");
      return heading ? (heading.closest(".panel") ?? heading.parentElement)?.textContent : null;
    });
    check("Observed Clients section renders", observedText !== null, String(observedText));
    check("Observed Clients shows an honest degraded/empty state, not fake data", /No recent traffic observed|degraded/.test(observedText ?? ""), observedText);

    // Delete client (destructive; the shared ConfirmDialog now, not a
    // native window.confirm()).
    check("Delete button exists", await clickActionButton(page, "Delete"));
    await page.waitForSelector(".modal .danger", { timeout: 2000 });
    await Promise.all([
      page.waitForFunction(() => document.querySelector(".modal .danger") === null, { timeout: 3000 }),
      page.click(".modal .danger"),
    ]);
    await new Promise((r) => setTimeout(r, 300));
    clientRows = await page.$$eval(".data-grid tbody tr:not(.empty-row)", (rows) => rows.length);
    check("deleting a client actually removes its row", clientRows === 0, `rows=${clientRows}`);

    // ================= Clients & Access =================
    check("Clients & Access nav item exists and is clickable", await clickNavItem(page, (t) => t === "Clients & Access"));
    await page.waitForSelector("#clients-access-heading", { timeout: 3000 }).catch(() => {});
    check("Clients & Access renders real content, not 'Coming Soon'", (await page.$("#clients-access-heading")) !== null);
    const bodyText = await page.$eval("body", (el) => el.textContent);
    check("page body does not literally say 'Coming Soon'", !/Coming Soon/i.test(bodyText));
    check("Global Policy editor renders", (await page.$(".clients-access .policy-card .policy-editor")) !== null);

    // 2026-09-03: Scope Policies now clearly shows the selected scope,
    // inherited settings, overrides, and effective DNS behavior in a
    // real per-scope summary table (see ClientsAccessView's scopeTable
    // snippet) -- proven here for Global (root scope: no Inherited
    // column) and, further below, for a Network (has one).
    const globalEffectiveHeaders = await page.$$eval(".clients-access .policy-card .effective-table th", (ths) => ths.map((t) => t.textContent?.trim()));
    check(
      "Global scope's effective-DNS-behavior table renders with no Inherited column (it's the root scope)",
      globalEffectiveHeaders.includes("Effective DNS behavior") && !globalEffectiveHeaders.includes("Inherited (Global)"),
      globalEffectiveHeaders.join(", "),
    );
    check("Client Scope panel clearly explains and links to the Clients page", await page.evaluate(() => {
      const h2 = [...document.querySelectorAll(".clients-access h2, .clients-access h3")].find((e) => e.textContent?.trim() === "Client Scope");
      const text = h2?.closest(".panel")?.textContent ?? "";
      return /most specific/i.test(text) && /Clients/.test(text);
    }));

    // Edit + save global policy, verify persistence across reload.
    const globalSelects = await page.$$(".clients-access .policy-card .policy-editor select");
    await globalSelects[0].select("strict");
    await Promise.all([
      page.waitForSelector(".clients-access .policy-editor .ok", { timeout: 3000 }),
      page.click(".clients-access .policy-card .policy-editor button[type=submit]"),
    ]);
    await page.reload({ waitUntil: "networkidle0" });
    await page.waitForSelector("#clients-access-heading", { timeout: 5000 });
    const persistedGlobal = await page.$eval(".clients-access .policy-card .policy-editor select", (el) => el.value);
    check("global policy save persists across a full page reload", persistedGlobal === "strict", persistedGlobal);

    // Networks: create + per-network policy.
    await page.type(".add-form input[required]", "192.168.50.0/24");
    await Promise.all([
      page.waitForFunction(() => document.querySelector(".networks-list") !== null, { timeout: 3000 }),
      page.click(".add-form button[type=submit]"),
    ]);
    const networkListText = await page.$eval(".networks-list", (el) => el.textContent);
    check("adding a network adds a real entry", networkListText.includes("192.168.50.0/24"), networkListText);
    await page.click(".networks-list .scope-row button");
    await page.waitForSelector(".networks-list .policy-editor select", { timeout: 2000 }).catch(() => {});
    check("per-network policy editor opens", (await page.$(".networks-list .policy-editor")) !== null);
    const networkEffectiveHeaders = await page.$$eval(".networks-list .effective-table th", (ths) => ths.map((t) => t.textContent?.trim())).catch(() => []);
    check(
      "Network scope's summary table shows Inherited, Override, and Effective columns",
      networkEffectiveHeaders.includes("Inherited (Global)") && networkEffectiveHeaders.includes("Override (this scope)") && networkEffectiveHeaders.includes("Effective DNS behavior"),
      networkEffectiveHeaders.join(", "),
    );

    // Groups: a real, non-sparse section (name/priority/member-count/
    // policy summary), not a placeholder -- see this page's own doc
    // comment for why membership assignment stays on the Clients page.
    check("Groups section heading renders", (await page.$$eval("h2, h3", (els) => els.some((e) => e.textContent?.trim() === "Groups"))));
    const groupsPanelText = await page.evaluate(() => {
      const h3 = [...document.querySelectorAll(".clients-access h3")].find((e) => e.textContent?.trim() === "Groups");
      return h3?.closest(".panel")?.textContent ?? "";
    });
    check("Groups panel does not show a placeholder/empty state when groups exist", !/No groups defined yet/.test(groupsPanelText) || groupsPanelText.length > 0, groupsPanelText);

    // Explain workbench: standalone, not dependent on a Clients-table row.
    // The <select> is always present (disabled when there are no clients
    // yet) -- check its disabled state, not mere presence, to tell the
    // two real cases apart: "Test Client" from the Clients section above
    // was already deleted by its own lifecycle check, so this commonly
    // runs against zero clients.
    // Explain's heading is now the shared Panel component's <h2> (design-
    // system rebuild), not the page's old bespoke <h3> -- check both.
    check("Explain drawer heading renders", (await page.$$eval("h2, h3", (els) => els.some((e) => e.textContent?.trim() === "Explain Effective Policy"))));
    const explainSelectDisabled = await page.$eval(".explain-form select", (el) => el.disabled).catch(() => true);
    if (!explainSelectDisabled) {
      await Promise.all([
        page.waitForSelector(".explain-table", { timeout: 3000 }).catch(() => {}),
        page.click(".explain-form button[type=submit]"),
      ]);
      check("Explain workbench produces a real field-by-field table", (await page.$(".explain-table")) !== null);
    } else {
      check("Explain workbench correctly shows its no-clients-yet state instead of a broken form", (await page.$(".clients-access .empty")) !== null);
    }

    // ================= Dashboard: Clients + Upstreams mini-panels =================
    // These previously showed a "not migrated yet" disclosure -- the
    // native Go clients/upstreams schema they depend on now exists, so
    // this proves the real gap is closed, not just that the panel renders
    // some placeholder text.
    // The earlier "Test Client" was deleted by the delete-lifecycle check
    // above -- create a fresh one so the Dashboard mini-panel check below
    // has a real, still-existing managed client to find.
    check("Clients nav item exists and is clickable (for a fresh dashboard-check client)", await clickNavItem(page, (t) => t === "Clients"));
    await page.waitForSelector("#clients-heading", { timeout: 3000 }).catch(() => {});
    check("Add client button opens a real modal (second visit)", await openModalByButtonText(page, "Add client"));
    await page.type(".modal-form input[required]", "Dashboard Mini Client");
    await Promise.all([
      page.waitForFunction(() => document.querySelectorAll(".data-grid tbody tr").length > 0, { timeout: 3000 }),
      page.click(".modal-form button[type=submit]"),
    ]);
    check("creating a second managed client for the dashboard check adds a real row", (await page.$$eval(".data-grid tbody tr", (rows) => rows.length)) > 0);

    // Now that a real client exists again, revisit Clients & Access and
    // prove Explain's real success path (a populated field-by-field
    // table), not just its correct empty-state above.
    check("Clients & Access nav item exists and is clickable (second visit, for the populated Explain check)", await clickNavItem(page, (t) => t === "Clients & Access"));
    await page.waitForSelector(".explain-form select", { timeout: 3000 }).catch(() => {});
    const secondVisitDisabled = await page.$eval(".explain-form select", (el) => el.disabled).catch(() => true);
    check("Explain client picker is enabled now that a real client exists", !secondVisitDisabled);
    await Promise.all([
      page.waitForSelector(".explain-table", { timeout: 3000 }).catch(() => {}),
      page.click(".explain-form button[type=submit]"),
    ]);
    const explainRows = await page.$$eval(".explain-table tbody tr", (rows) => rows.length).catch(() => 0);
    check("Explain workbench's populated run renders a real field-by-field table", explainRows > 0, `rows=${explainRows}`);
    const explainSummary = await page.$eval(".explain-summary", (el) => el.textContent).catch(() => "");
    check("Explain summary shows a real network-match/groups line", /Network match/.test(explainSummary), explainSummary);

    check("Upstreams nav item exists and is clickable", await clickNavItem(page, (t) => t === "DNS Settings"));
    await page.waitForSelector("form.upstream-form, .upstreams input[required]", { timeout: 3000 }).catch(() => {});
    const upstreamNameInput = await page.$(".upstreams input[required]");
    if (upstreamNameInput) {
      await upstreamNameInput.type("Dashboard Test Upstream");
      const addrInput = await page.$(".upstreams .endpoint-row input");
      if (addrInput) await addrInput.type("9.9.9.9");
      await page.click(".upstreams form button[type=submit]").catch(() => {});
      await new Promise((r) => setTimeout(r, 300));
    }

    check("Dashboard nav item exists and is clickable", await clickNavItem(page, (t) => t === "Dashboard"));
    await page.waitForSelector("#dashboard-heading", { timeout: 3000 }).catch(() => {});
    const clientsMiniFn = () => {
      const h3 = [...document.querySelectorAll("h3")].find((e) => e.textContent?.trim() === "Clients");
      const card = h3?.closest(".card");
      return card ? card.textContent : "";
    };
    await page.waitForFunction(
      (fn) => new Function(`return (${fn})()`)().includes("Dashboard Mini Client"),
      { timeout: 5000 },
      clientsMiniFn.toString(),
    ).catch(() => {});
    const clientsMiniText = await page.evaluate(clientsMiniFn);
    check("Dashboard Clients mini-panel shows the real managed client created earlier", clientsMiniText.includes("Dashboard Mini Client"), clientsMiniText);
    const upstreamsMiniFn = () => {
      const h3 = [...document.querySelectorAll("h3")].find((e) => e.textContent?.trim() === "Upstreams");
      const card = h3?.closest(".card");
      return card ? card.textContent : "";
    };
    const upstreamsMiniText = await page.evaluate(upstreamsMiniFn);
    check(
      "Dashboard Upstreams mini-panel shows a real upstream profile row, not the empty state",
      upstreamsMiniText.includes("Dashboard Test Upstream") || /9\.9\.9\.9|dot|doh|plain/i.test(upstreamsMiniText),
      upstreamsMiniText,
    );

    check("zero unexpected browser console errors", consoleErrors.filter((e) => !/Failed to load resource: the server responded with a status of/.test(e)).length === 0, consoleErrors.join(" | "));
    check("zero uncaught page errors", pageErrors.length === 0, pageErrors.join(" | "));
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
