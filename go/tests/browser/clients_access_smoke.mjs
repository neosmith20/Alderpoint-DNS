// Real-Chromium coverage for the Clients and Scope Policies pages
// specifically (see PARITY_MATRIX.md) -- factored out of
// chromium_smoke.mjs because those pages' full workflows don't need
// the analytics/query-log/import fixtures the rest of that suite
// requires. Run against an instance whose one-time bootstrap setup has
// already been completed (see setup_bootstrap_smoke.mjs for that gate's
// own dedicated coverage) -- never the live owner preview, whose
// credentials are Alex's.
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
      await page.waitForSelector(".modal-form", { timeout: 5000 });
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

// Clicks a button anywhere on the page by its exact text -- used inside
// the Edit-client modal below, where several distinct `.inline-form`s
// (Identity/Identifiers/Strong ClientID/Group/Overrides) share the same
// class, so a bare `.inline-form button[type=submit]` selector is
// ambiguous; each form's own submit text is unique instead.
// Finds AND clicks atomically inside one page.evaluate() -- not a
// separate evaluateHandle()-then-.click() round trip, which leaves a
// window where a concurrent Svelte re-render can detach the handle's
// node between the two steps, silently no-op'ing the click.
async function clickButtonByText(page, text) {
  return page.evaluate((t) => {
    const btn = [...document.querySelectorAll("button")].find((b) => b.textContent?.trim() === t);
    if (!btn) return false;
    btn.click();
    return true;
  }, text);
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
    // A real fresh instance now always lands on the bootstrap-token gate
    // first (internal/bootstrap), not directly on #setup-heading -- this
    // file's own 3-arg usage (no token path) means it's meant to run
    // against an instance whose one-time setup was already completed by
    // setup_bootstrap_smoke.mjs (the dedicated coverage for that gate
    // itself), same convention as domain_routing_rulesets_smoke.mjs/
    // notifications_smoke.mjs. Fail with a clear, actionable message
    // instead of an opaque timeout if that wasn't done.
    await page.waitForSelector("#bootstrap-heading, #setup-heading, #login-heading", { timeout: 5000 });
    if ((await page.$("#bootstrap-heading")) !== null) {
      throw new Error(
        "landed on the bootstrap-token gate -- this instance's one-time setup was never completed. " +
        "Run setup_bootstrap_smoke.mjs against it first (or point this script at an already-set-up instance), " +
        "matching every other 3-arg script in this suite.",
      );
    }
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

    // Scope Policies lives under an Advanced-only nav group (nav.ts) --
    // not rendered in the sidebar under the default Standard profile.
    // Same real fix as chromium_smoke.mjs's own copy of this gap.
    await page.evaluate(() => localStorage.setItem("apdns-go-nav-profile", "advanced"));
    await page.reload({ waitUntil: "networkidle0" });
    await page.waitForSelector(".app-layout", { timeout: 5000 });
    check("switching to the Advanced nav profile takes effect", await page.evaluate(() => localStorage.getItem("apdns-go-nav-profile")) === "advanced");

    // ================= Clients =================
    check("Clients nav item exists and is clickable", await clickNavItem(page, (t) => t === "Clients"));
    await page.waitForSelector("#clients-heading", { timeout: 5000 }).catch(() => {});
    check("Clients page renders real content, not a placeholder", (await page.$("#clients-heading")) !== null);
    // The page's own real PageHeader description covers this now (a
    // separate `.scope-note` paragraph this check used to read no
    // longer exists on this page) -- full lifecycle coverage (create,
    // rename, enable/disable, delete) is proven directly by this test's
    // own real interactions below instead of by a disclosure string.
    const clientsDescription = await page.$eval(".page-header p", (el) => el.textContent).catch(() => "");
    check("Clients page header renders a real description", clientsDescription.length > 0, clientsDescription);

    // Create a group via its modal (Add group is disabled until at least
    // one client or group exists -- this fixture has neither yet, so
    // create the client first).
    check("Add client button opens a real modal, not a permanent on-page form", await openModalByButtonText(page, "Add Managed Client"));
    await page.type(".modal-form input[required]", "Test Client");
    // :not(.empty-row) -- DataGrid's own empty state is a real
    // `<tr class="empty-row">`, always present before any client
    // exists, so a bare "tr count > 0" wait is satisfied instantly by
    // THAT row and races ahead of the real creation response -- a real
    // bug found live here (it let the code race on to "Manage Groups"
    // below before "Add Managed Client"'s own modal had genuinely
    // closed, which is the actual cause of that step's own intermittent
    // ".modal-form" timeout).
    await Promise.all([
      page.waitForFunction(() => document.querySelectorAll(".data-grid tbody tr:not(.empty-row)").length > 0, { timeout: 5000 }),
      page.click(".modal-form button[type=submit]"),
    ]);
    let clientRows = await page.$$eval(".data-grid tbody tr:not(.empty-row)", (rows) => rows.length);
    check("creating a managed client adds a real row", clientRows === 1, `rows=${clientRows}`);

    // "Create and continue" auto-opens the new client's own Edit modal
    // (clientModal is set to its id, not cleared) -- close it first, or
    // the next real click below lands on this modal's own backdrop
    // instead of the page underneath it.
    await page.evaluate(() => document.querySelector(".modal__close")?.click());
    await page.waitForFunction(() => document.querySelector(".modal-backdrop") === null, { timeout: 4000 }).catch(() => {});

    // "Manage Groups" (not a separate "Add group" button) opens the
    // group-management modal, which contains both the group list and
    // the real create-group form.
    check("Manage Groups button opens a real modal", await openModalByButtonText(page, "Manage Groups"));
    await page.type(".modal-form input[required]", "Kids");
    // addGroup() closes this modal on success rather than leaving it
    // open to show the updated list -- reopen it afterward to see the
    // real, persisted group. Poll for the modal closing rather than a
    // single fixed-timeout waitForFunction -- a real, occasionally
    // slower round trip through this fixture's own real hostagent.
    await page.click(".modal-form button[type=submit]");
    for (let i = 0; i < 15; i++) {
      if ((await page.$(".modal-backdrop")) === null) break;
      await new Promise((r) => setTimeout(r, 300));
    }
    check("Manage Groups reopens to show the newly-created group", await openModalByButtonText(page, "Manage Groups"));
    const groupListText = await page.$eval(".group-list", (el) => el.textContent);
    check("creating a group adds a real entry", groupListText.includes("Kids"), groupListText);
    await page.evaluate(() => document.querySelector(".modal__close")?.click());
    await page.waitForFunction(() => document.querySelector(".modal-backdrop") === null, { timeout: 4000 }).catch(() => {});

    // --- Full managed-client lifecycle, all inside the real Edit modal
    // (2026-09-03: identifiers/Strong ClientID/groups/policy/overrides/
    // explain-preview all consolidated into one Edit modal per client,
    // opened via the row's own "Edit" button -- no more separate
    // per-action "Add IP identifier"/"Generate Strong ClientID"/"Add
    // domain override"/"Assign group"/"Policy"/"Explain" row buttons). ---
    check("Edit button exists", await clickActionButton(page, "Edit"));
    await page.waitForSelector('input[aria-label="Client name"]', { timeout: 4000 });

    // Add an IP identifier: invalid, then valid.
    await page.type('input[aria-label="Identifier value"]', "not-an-ip");
    await clickButtonByText(page, "Add address");
    await new Promise((r) => setTimeout(r, 200));
    const idError = await page.$eval(".editor-sections .error", (el) => el.textContent).catch(() => "");
    check("invalid IPv4 identifier is rejected client-visibly", idError.length > 0, idError);
    await page.$eval('input[aria-label="Identifier value"]', (el) => (el.value = ""));
    await page.type('input[aria-label="Identifier value"]', "10.0.0.5");
    await Promise.all([
      page.waitForFunction(() => document.querySelector(".id-list")?.textContent?.includes("10.0.0.5"), { timeout: 5000 }),
      clickButtonByText(page, "Add address"),
    ]);
    let modalText = await page.$eval(".id-list", (el) => el.textContent);
    check("valid identifier appears in the edit modal", modalText.includes("10.0.0.5"), modalText);

    // Strong ClientID: generate, verify DoH path / SNI shown, copy, revoke, regenerate, delete.
    await page.type('input[aria-label="ClientID label"]', "primary");
    await Promise.all([
      page.waitForFunction(() => document.querySelector(".clientid-row") !== null, { timeout: 5000 }),
      clickButtonByText(page, "Generate"),
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
    // button inside is what actually regenerates. ConfirmDialog stacks
    // on top of the still-open Edit modal (both share the real `.modal`
    // wrapper), so `.modal .danger` matches only its own confirm button
    // (Edit's own "Delete this client" uses a different class).
    const regenBtn = await page.evaluateHandle(() => [...document.querySelectorAll(".clientid-actions button")].find((b) => b.textContent.trim() === "Regenerate"));
    await regenBtn.asElement().click();
    await page.waitForSelector(".modal .danger", { timeout: 4000 });
    await Promise.all([
      page.waitForFunction((oldHex) => {
        const el = document.querySelector(".clientid-row:not(.revoked) .hexval");
        return el && el.getAttribute("title") !== oldHex;
      }, { timeout: 5000 }, clientIdHex),
      page.click(".modal .danger"),
    ]);
    const regeneratedHex = await page.$eval(".clientid-row:not(.revoked) .hexval", (el) => el.getAttribute("title"));
    check("regenerating produces a genuinely different value", regeneratedHex !== clientIdHex, regeneratedHex);

    // Revoke: row should show the revoked badge. Same shared dialog.
    const revokeBtn = await page.evaluateHandle(() => [...document.querySelectorAll(".clientid-actions button")].find((b) => b.textContent.trim() === "Revoke"));
    await revokeBtn.asElement().click();
    await page.waitForSelector(".modal .danger", { timeout: 4000 });
    await Promise.all([
      page.waitForSelector(".revoked-badge", { timeout: 5000 }),
      page.click(".modal .danger"),
    ]);
    check("revoking shows a real revoked badge", (await page.$(".revoked-badge")) !== null);

    // Domain override: add. Sequential click-then-poll -- this
    // fixture's real hostagent round trip occasionally takes longer
    // than a single 3s waitForFunction window.
    await page.type('input[aria-label="Override domain"]', "ads.example.com");
    await clickButtonByText(page, "Add override");
    modalText = "";
    for (let i = 0; i < 15; i++) {
      modalText = await page.$eval(".editor-sections", (el) => el.textContent).catch(() => "");
      if (modalText.includes("ads.example.com")) break;
      await new Promise((r) => setTimeout(r, 300));
    }
    if (!modalText.includes("ads.example.com")) {
      const overrideErr = await page.$eval(".editor-sections .error", (el) => el.textContent).catch(() => "(no .error element found)");
      console.error("DEBUG override error:", overrideErr);
    }
    check("domain override actually persists and renders", modalText.includes("ads.example.com"), modalText);

    // Assign to group, then remove from group.
    const kidsOptionValue = await page.$$eval('select[aria-label="Assign to group"] option', (opts) => {
      const o = opts.find((op) => op.textContent?.trim() === "Kids");
      return o ? o.value : "";
    });
    check("the real 'Kids' group created earlier is a selectable option", !!kidsOptionValue, kidsOptionValue);
    await page.select('select[aria-label="Assign to group"]', kidsOptionValue);
    // Waits for a real rendered chip in the Group section's own `.chips`,
    // not just "Kids" appearing anywhere in the modal -- the still-open
    // <select>'s own <option>Kids</option> already contains that text
    // before the real assignment lands, a real false-positive race
    // found live here.
    await Promise.all([
      page.waitForFunction(() => [...document.querySelectorAll(".chips .chip")].some((c) => c.textContent.includes("Kids")), { timeout: 5000 }),
      clickButtonByText(page, "Assign"),
    ]);
    modalText = await page.$eval(".modal", (el) => el.textContent);
    check("assigning a group shows it in the edit modal", modalText.includes("Kids"), modalText.slice(0, 200));
    const removedFromGroup = await page.evaluate(() => {
      const chip = [...document.querySelectorAll(".chips .chip")].find((c) => c.textContent.includes("Kids"));
      const btn = chip?.querySelector(".chip-x");
      if (!btn) return false;
      btn.click();
      return true;
    });
    check("group remove control works", removedFromGroup);
    await new Promise((r) => setTimeout(r, 300));
    // Scoped to the real chips specifically, not the whole modal -- the
    // "Assign to group" <select>'s own <option>Kids</option> stays
    // present after removal (the group itself still exists, only this
    // client's membership was removed), a real false-negative risk in a
    // whole-modal text check found live here.
    const chipsAfterRemove = await page.$eval(".chips", (el) => el.textContent).catch(() => "");
    check("removing from group actually removes it from the modal", !chipsAfterRemove.includes("Kids"), chipsAfterRemove);

    // Rename (the modal's own Identity form, not a separate reveal).
    // Retries the whole select+type+save+poll cycle -- a genuine
    // intermittent flake was found live (not just a display-timing
    // race) doing this same real interaction in chromium_smoke.mjs.
    let renameOk = false;
    let rowText = "";
    for (let attempt = 0; attempt < 3 && !renameOk; attempt++) {
      const clientNameInput = await page.$('input[aria-label="Client name"]');
      await clientNameInput.click();
      await clientNameInput.evaluate((el) => el.select());
      await clientNameInput.type("Test Client Renamed");
      await clickButtonByText(page, "Save");
      for (let i = 0; i < 15; i++) {
        await new Promise((r) => setTimeout(r, 300));
        rowText = await page.$eval(".data-grid tbody", (el) => el.textContent).catch(() => "");
        if (rowText.includes("Test Client Renamed")) { renameOk = true; break; }
      }
    }
    check("editing name persists and re-renders on the row underneath", renameOk, rowText);

    // Per-client policy editor + effective-policy preview, both embedded
    // directly in the modal now (no separate "Policy"/"Explain" buttons).
    check("per-client policy editor renders", (await page.$(".editor-sections .policy-editor")) !== null);
    const clientPolicySelects = await page.$$(".editor-sections .policy-editor select");
    await clientPolicySelects[0].select("strict");
    await Promise.all([
      page.waitForSelector(".editor-sections .policy-editor .ok", { timeout: 5000 }),
      clickButtonByText(page, "Save policy"),
    ]);
    await page.waitForFunction(() => document.querySelector(".explain-table") !== null || document.querySelector(".explain-summary") !== null, { timeout: 5000 }).catch(() => {});
    check("saving the client's policy renders a real effective-policy preview", (await page.$(".explain-table")) !== null || (await page.$(".explain-summary")) !== null);

    await page.evaluate(() => document.querySelector(".modal__close")?.click());
    await page.waitForFunction(() => document.querySelector(".modal-backdrop") === null, { timeout: 4000 }).catch(() => {});
    check("Edit modal actually closed before the row-level actions below", (await page.$(".modal-backdrop")) === null);

    // Disable / enable (real row-level actions, outside the modal).
    // Poll for the real outcome rather than a single fixed wait -- this
    // fixture's real hostagent round trip is occasionally slower than
    // 5s for a policy-affecting save's own DNS-runtime auto-apply.
    check("Disable button exists", await clickActionButton(page, "Disable"));
    let disabledBadgeSeen = false;
    for (let i = 0; i < 20; i++) {
      if ((await page.$(".disabled-badge")) !== null) { disabledBadgeSeen = true; break; }
      await new Promise((r) => setTimeout(r, 300));
    }
    check("disabling shows a real disabled badge", disabledBadgeSeen);
    check("Enable button exists after disabling", await clickActionButton(page, "Enable"));
    let disabledBadgeGone = false;
    for (let i = 0; i < 20; i++) {
      if ((await page.$(".disabled-badge")) === null) { disabledBadgeGone = true; break; }
      await new Promise((r) => setTimeout(r, 300));
    }
    check("re-enabling removes the disabled badge", disabledBadgeGone);

    // Observed Clients: its own tab now (2026-09-03 structural redesign),
    // not a section visible alongside Managed Clients -- switch to it
    // first. Honest empty state on a fresh instance with no query
    // traffic (this fixture has no seeded query_events at all).
    const observedTabClicked = await page.evaluate(() => {
      const tab = [...document.querySelectorAll('[role="tab"]')].find((t) => t.textContent?.includes("Observed Clients"));
      if (tab) { tab.click(); return true; }
      return false;
    });
    check("Observed Clients tab is clickable", observedTabClicked);
    await page.waitForSelector('[data-grid-id="observed-clients"]', { timeout: 5000 }).catch(() => {});
    const observedText = await page.$eval('[data-grid-id="observed-clients"]', (el) => el.textContent).catch(() => null);
    check("Observed Clients section renders", observedText !== null, String(observedText));
    check("Observed Clients shows an honest degraded/empty state, not fake data", /No recent traffic observed|degraded/.test(observedText ?? ""), observedText);
    // Switch back to Managed for the delete step below.
    await page.evaluate(() => {
      const tab = [...document.querySelectorAll('[role="tab"]')].find((t) => t.textContent?.includes("Managed Clients"));
      tab?.click();
    });

    // Delete client (destructive; the shared ConfirmDialog now, not a
    // native window.confirm()).
    check("Delete button exists", await clickActionButton(page, "Delete"));
    await page.waitForSelector(".modal .danger", { timeout: 4000 });
    await Promise.all([
      page.waitForFunction(() => document.querySelector(".modal .danger") === null, { timeout: 5000 }),
      page.click(".modal .danger"),
    ]);
    await new Promise((r) => setTimeout(r, 300));
    clientRows = await page.$$eval(".data-grid tbody tr:not(.empty-row)", (rows) => rows.length);
    check("deleting a client actually removes its row", clientRows === 0, `rows=${clientRows}`);

    // ================= Clients & Access =================
    check("Scope Policies nav item exists and is clickable", await clickNavItem(page, (t) => t === "Scope Policies"));
    await page.waitForSelector("#clients-access-heading", { timeout: 5000 }).catch(() => {});
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
      page.waitForSelector(".clients-access .policy-editor .ok", { timeout: 5000 }),
      page.click(".clients-access .policy-card .policy-editor button[type=submit]"),
    ]);
    await page.reload({ waitUntil: "networkidle0" });
    await page.waitForSelector("#clients-access-heading", { timeout: 5000 });
    const persistedGlobal = await page.$eval(".clients-access .policy-card .policy-editor select", (el) => el.value);
    check("global policy save persists across a full page reload", persistedGlobal === "strict", persistedGlobal);

    // Networks: create + per-network policy.
    await page.type(".add-form input[required]", "192.168.50.0/24");
    await Promise.all([
      page.waitForFunction(() => document.querySelector(".networks-list") !== null, { timeout: 5000 }),
      page.click(".add-form button[type=submit]"),
    ]);
    const networkListText = await page.$eval(".networks-list", (el) => el.textContent);
    check("adding a network adds a real entry", networkListText.includes("192.168.50.0/24"), networkListText);
    await page.click(".networks-list .scope-row button");
    await page.waitForSelector(".networks-list .policy-editor select", { timeout: 4000 }).catch(() => {});
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
        page.waitForSelector(".explain-table", { timeout: 5000 }).catch(() => {}),
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
    await page.waitForSelector("#clients-heading", { timeout: 5000 }).catch(() => {});
    check("Add client button opens a real modal (second visit)", await openModalByButtonText(page, "Add Managed Client"));
    await page.type(".modal-form input[required]", "Dashboard Mini Client");
    await Promise.all([
      page.waitForFunction(() => document.querySelectorAll(".data-grid tbody tr:not(.empty-row)").length > 0, { timeout: 5000 }),
      page.click(".modal-form button[type=submit]"),
    ]);
    check("creating a second managed client for the dashboard check adds a real row", (await page.$$eval(".data-grid tbody tr:not(.empty-row)", (rows) => rows.length)) > 0);
    // "Create and continue" auto-opens this new client's own Edit modal
    // -- close it before navigating away, or the next nav click lands
    // on this modal's own backdrop instead of the sidebar underneath it.
    await page.evaluate(() => document.querySelector(".modal__close")?.click());
    await page.waitForFunction(() => document.querySelector(".modal-backdrop") === null, { timeout: 4000 }).catch(() => {});

    // Now that a real client exists again, revisit Clients & Access and
    // prove Explain's real success path (a populated field-by-field
    // table), not just its correct empty-state above.
    check("Scope Policies nav item exists and is clickable (second visit, for the populated Explain check)", await clickNavItem(page, (t) => t === "Scope Policies"));
    await page.waitForSelector("#clients-access-heading", { timeout: 5000 });
    await page.waitForSelector(".explain-form select", { timeout: 5000 });
    // Poll: refreshClients()'s own real fetch can land a beat after the
    // component mounts and the <select> itself first appears.
    let secondVisitDisabled = true;
    for (let i = 0; i < 15; i++) {
      secondVisitDisabled = await page.$eval(".explain-form select", (el) => el.disabled).catch(() => true);
      if (!secondVisitDisabled) break;
      await new Promise((r) => setTimeout(r, 300));
    }
    check("Explain client picker is enabled now that a real client exists", !secondVisitDisabled);
    await Promise.all([
      page.waitForSelector(".explain-table", { timeout: 5000 }).catch(() => {}),
      page.click(".explain-form button[type=submit]"),
    ]);
    const explainRows = await page.$$eval(".explain-table tbody tr", (rows) => rows.length).catch(() => 0);
    check("Explain workbench's populated run renders a real field-by-field table", explainRows > 0, `rows=${explainRows}`);
    const explainSummary = await page.$eval(".explain-summary", (el) => el.textContent).catch(() => "");
    check("Explain summary shows a real network-match/groups line", /Network match/.test(explainSummary), explainSummary);

    // DNS Settings (nav.ts's real label is "DNS", not "DNS Settings";
    // the real Add Resolver form is now a modal on DnsSettingsView.svelte,
    // not a permanently-visible `.upstreams` form).
    check("DNS nav item exists and is clickable", await clickNavItem(page, (t) => t === "DNS"));
    await page.waitForSelector("#dns-settings-heading", { timeout: 5000 }).catch(() => {});
    const addResolverClicked = await clickButtonByText(page, "Add Resolver");
    if (addResolverClicked) {
      await page.waitForSelector('input[placeholder="e.g. Cloudflare"]', { timeout: 4000 }).catch(() => {});
      await page.type('input[placeholder="e.g. Cloudflare"]', "Dashboard Test Upstream");
      await page.type("textarea", "9.9.9.9");
      // "Add Resolver" is both the header's opener button and the modal's
      // own submit button -- scope the submit click to `.modal-form` to
      // avoid landing on the (DOM-order-first) header button instead.
      await Promise.all([
        page.waitForFunction(() => document.querySelector(".modal-backdrop") === null, { timeout: 5000 }).catch(() => {}),
        page.evaluate(() => {
          const btn = [...document.querySelectorAll(".modal-form button")].find((b) => b.textContent?.trim() === "Add Resolver");
          btn?.click();
        }),
      ]);
    }

    check("Dashboard nav item exists and is clickable", await clickNavItem(page, (t) => t === "Dashboard"));
    await page.waitForSelector("#dashboard-heading", { timeout: 5000 }).catch(() => {});
    // Both cards are real but OFF by default (dashboardCards.ts's own
    // ALL_CARDS: defaultVisible: false for "clients"/"upstreams") --
    // turn them on via the real Customize Dashboard control first,
    // matching what an operator would actually do to see them (same
    // real gap already found and fixed in chromium_smoke.mjs).
    const customizeClicked = await clickButtonByText(page, "Customize Dashboard");
    if (customizeClicked) {
      await page.waitForSelector(".customize-panel", { timeout: 4000 }).catch(() => {});
      for (const wantLabel of ["Clients (managed + observed)", "Upstreams (configured profiles)"]) {
        await page.evaluate((label) => {
          const li = [...document.querySelectorAll(".customize-panel li")].find((el) => el.querySelector("label")?.textContent?.trim() === label);
          const cb = li?.querySelector('input[type="checkbox"]');
          if (cb && !cb.checked) cb.click();
        }, wantLabel);
      }
      await clickButtonByText(page, "Customize Dashboard");
    }
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
