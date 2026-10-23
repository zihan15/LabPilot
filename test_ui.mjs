import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import vm from "node:vm";

test("operations controls expose request, approval, user and activity workflows", () => {
  const html = readFileSync(new URL("./static/index.html", import.meta.url), "utf8");
  const script = readFileSync(new URL("./static/app.js", import.meta.url), "utf8");
  for (const id of ["new-environment", "users-view", "users", "activity-filters", "activity-events"])
    assert.match(html, new RegExp(`id="${id}"`));
  for (const route of ["/api/environments/requests", "/api/users", "/api/activity", "/decision", "/start"])
    assert.ok(script.includes(route), `missing ${route}`);
  assert.doesNotMatch(script, /node\("p", "run-output", run\.output\)/);
});

test("admin creates a tester with a long password and CSRF protection", async () => {
  class Element {
    constructor() { this.children = []; this.value = ""; this.hidden = false; this.dataset = {}; this.classList = { add() {}, remove() {}, toggle() {} }; this.listeners = {}; }
    addEventListener(name, handler) { this.listeners[name] = handler; }
    replaceChildren(...children) { this.children = children; }
    append(...children) { this.children.push(...children); }
    focus() {}
    setAttribute() {}
    showModal() { this.open = true; }
    close() { this.open = false; }
    get firstChild() { return this.children[0]; }
    get textContent() { return this._text || ""; }
    set textContent(text) { this._text = text; this.children = []; }
  }
  const elements = new Map(), get = (id) => {
    const lookup = (item) => item.id === id ? item : item.children?.map(lookup).find(Boolean);
    const dynamic = elements.get("dialog-fields")?.children.map(lookup).find(Boolean);
    if (dynamic) return dynamic;
    if (!elements.has(id)) elements.set(id, new Element());
    return elements.get(id);
  };
  const calls = [];
  const document = {
    getElementById: get,
    createElement: (tag) => Object.assign(new Element(), { tagName: tag.toUpperCase() }),
    querySelector: () => new Element(),
    querySelectorAll: () => [],
    hidden: false,
  };
  const responses = {
    "/api/me": { user: { username: "owner", role: "admin" }, csrfToken: "token" },
    "/api/labs": { labs: [{ id: "dam-mxha", name: "Test lab", start_available: true, components: [
      { id: "primary-mx", name: "Primary MX", ec2State: "running", productHealth: "unknown" },
      { id: "secondary-mx", name: "Secondary MX", ec2State: "running", productHealth: "unknown" },
      { id: "gateway", name: "Gateway", ec2State: "running", productHealth: "unknown" },
    ] }] }, "/api/gateways": { gateways: [] },
    "/api/sessions": { sessions: [{ id: "sid", lab_id: "dam-mxha", title: "Live check", mode: "full" }] },
    "/api/sessions/sid": { session: { id: "sid", lab_id: "dam-mxha", title: "Live check", mode: "full" }, messages: [] },
    "/api/runs": { runs: [{ id: "rid", session_id: "sid", user: "owner", status: "running", screenshot: true, steps: [{ at: "2026-10-22T00:00:00Z", status: "running", summary: "Trying terminal: git status --short" }] }] },
    "/api/requests": { requests: [{ id: "legacy", lab_id: "dam-mxha", kind: "environment", status: "pending", user: "alice", proposed_name: null, spec: { lab_id: "new", topology: "mxha", gateway_count: 1, db_version: "", ttl_hours: 24, max_spend_usd: 100 }, note: "Old request" }, { id: "db", kind: "environment", status: "approved", user: "owner", proposed_name: "db-request", spec: { lab_id: "new", topology: "database", gateway_count: 0, db_engine: "postgresql", db_version: "", os_version: "" } }, { id: "pending-db", kind: "environment", status: "pending", user: "alice", proposed_name: "db-request", spec: { lab_id: "new", topology: "database", gateway_count: 0, db_engine: "postgresql", db_version: "", os_version: "" } }] }, "/api/activity": { events: [] },
    "/api/users": { users: [] },
    "/api/labs/dam-mxha/stop": { lab_id: "dam-mxha", status: "already_stopped", requested: 0 },
  };
  const context = vm.createContext({ document, URLSearchParams, window: { confirm: () => true }, setTimeout: () => 0, clearTimeout() {}, setInterval() {}, fetch: async (path, options = {}) => {
    calls.push({ path, options });
    return { ok: true, status: 200, json: async () => responses[path] || { user: { username: "alice", role: "tester" } } };
  } });
  vm.runInContext(readFileSync(new URL("./static/app.js", import.meta.url), "utf8"), context);
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(get("users-nav").hidden, false);
  const findButton = (item, text) => item.textContent === text && item.listeners?.click ? item : item.children?.map((child) => findButton(child, text)).find(Boolean);
  const texts = (item) => [item.textContent, ...(item.children || []).flatMap(texts)];
  await get("session-list").children[0].listeners.click();
  assert.ok(texts(get("run-progress")).some((text) => text.includes("git status --short")), "active session must display in-flight command");
  assert.equal(get("run-progress").children.find((child) => child.tagName === "IMG")?.src, "/api/runs/rid/screenshot");
  assert.equal(get("grant-login").hidden, false, "admin full session needs an in-session access control");
  get("grant-login").listeners.click();
  get("dialog-detail").value = "https://mx.example.test:8083";
  get("dialog-identifier").value = "operator";
  get("dialog-password").value = "TEST_PRIVATE_CANARY";
  await get("dialog-form").listeners.submit({ preventDefault() {} });
  const login = calls.find(({ path }) => path === "/api/sessions/sid/login");
  assert.ok(login, "secret must use the dedicated vault endpoint");
  assert.equal(login.options.headers["X-CSRF-Token"], "token");
  assert.equal(get("dialog-password").value, "");
  assert.equal(get("dialog-fields").children.length, 0);
  get("grant-login").listeners.click();
  get("dialog-password").value = "CANCEL_PRIVATE_CANARY";
  get("cancel-dialog").listeners.click();
  assert.equal(get("dialog-password").value, "", "cancel must clear an unsent credential");
  assert.ok(texts(get("requests")).some((text) => /historical.*24h.*USD 100/i.test(text)), "legacy TTL/spend must remain visible");
  const dbRows = get("requests").children.filter((row) => texts(row).some((text) => /db-request/.test(text)));
  assert.notEqual(findButton(dbRows[0], "Start admin fulfillment").disabled, true);
  assert.notEqual(findButton(dbRows[1], "Approve for fulfillment").disabled, true);
  assert.equal(findButton(get("requests"), "Approve for fulfillment").disabled, true, "versionless legacy request needs resubmission");
  const stop = findButton(get("labs"), "Stop lab");
  assert.ok(stop, "admin should see Stop lab on a running environment");
  await stop.listeners.click();
  assert.ok(calls.some(({ path, options }) => path === "/api/labs/dam-mxha/stop" && options.method === "POST"));
  assert.match(get("notice").textContent, /already stopped/i);
  const componentStop = findButton(get("labs"), "Stop Primary MX");
  assert.ok(componentStop, "admin should see an individual stop action");
  await componentStop.listeners.click();
  assert.ok(calls.some(({ path, options }) => path === "/api/labs/dam-mxha/components/primary-mx/stop" && options.method === "POST"));
  get("create-user").listeners.click();
  get("dialog-detail").value = "alice";
  get("dialog-password").value = "short";
  await get("dialog-form").listeners.submit({ preventDefault() {} });
  assert.equal(calls.filter(({ path, options }) => path === "/api/users" && options.method === "POST").length, 0);
  assert.match(get("dialog-error").textContent, /16 characters/);
  get("dialog-password").value = "sixteen-characters";
  get("dialog-role").value = "tester";
  await get("dialog-form").listeners.submit({ preventDefault() {} });
  const created = calls.find(({ path, options }) => path === "/api/users" && options.method === "POST");
  assert.ok(created);
  assert.deepEqual(JSON.parse(created.options.body), { username: "alice", password: "sixteen-characters", role: "tester" });
  assert.equal(created.options.headers["X-CSRF-Token"], "token");
  assert.equal(get("dialog-fields").children.length, 0);
  get("new-environment").listeners.click();
  assert.equal(get("dialog-topology").children.some((option) => option.value === "database"), true);
  get("dialog-topology").value = "database";
  get("dialog-topology").listeners.change();
  assert.equal(get("dialog-db-fields").hidden, false);
  assert.deepEqual(get("dialog-db-engine").children.map((option) => option.value), ["", "mysql", "postgresql", "oracle", "sql-server", "mariadb"]);
  assert.equal(get("dialog-version").required, false);
  assert.equal(get("dialog-version").hidden, true);
  assert.equal(get("dialog-gateways").hidden, true);
  assert.equal(get("dialog-gateways").disabled, true);
  get("dialog-lab").value = "new";
  get("dialog-db-engine").value = "";
  get("dialog-detail").value = "Private database test";
  await get("dialog-form").listeners.submit({ preventDefault() {} });
  assert.equal(calls.filter(({ path, options }) => path === "/api/environments/requests" && options.method === "POST").length, 0);
  assert.match(get("dialog-error").textContent, /engine/i);
  get("dialog-db-engine").value = "postgresql";
  get("dialog-db-version").value = "";
  get("dialog-os-version").value = "";
  await get("dialog-form").listeners.submit({ preventDefault() {} });
  const database = calls.find(({ path, options }) => path === "/api/environments/requests" && options.method === "POST");
  assert.deepEqual(JSON.parse(database.options.body), { lab_id: "new", topology: "database", gateway_count: 0, db_engine: "postgresql", db_version: "", os_version: "", purpose: "Private database test" });
  assert.match(get("notice").textContent, /human review|manual/i);
  get("new-environment").listeners.click();
  get("dialog-lab").value = "dam-mxha";
  get("dialog-topology").value = "mxha";
  get("dialog-gateways").value = "2";
  get("dialog-version").value = "14.19.1.150";
  get("dialog-detail").value = "Need isolated test environment";
  await get("dialog-form").listeners.submit({ preventDefault() {} });
  const environment = calls.filter(({ path, options }) => path === "/api/environments/requests" && options.method === "POST").at(-1);
  assert.ok(environment);
  assert.deepEqual(JSON.parse(environment.options.body), { lab_id: "dam-mxha", topology: "mxha", gateway_count: 2, version: "14.19.1.150", purpose: "Need isolated test environment" });
  assert.equal(get("dialog-fields").children.some((child) => /Expiry in hours|Maximum spend/.test(child.textContent)), false);
  assert.match(get("notice").textContent, /unlocks an admin fulfillment session/);
});

test("database advice remains optional and read-only", async () => {
  const h = proposalHarness("tester", []);
  await new Promise((resolve) => setImmediate(resolve));
  h.get("new-environment").listeners.click();
  h.get("dialog-topology").value = "database";
  h.get("dialog-topology").listeners.change();
  h.get("dialog-db-engine").value = "postgresql";
  await h.get("dialog-db-advice-button").listeners.click();
  const sent = h.calls.find(({ path }) => path === "/api/db-advice");
  assert.deepEqual(JSON.parse(sent.options.body), { db_engine: "postgresql", db_version: "", os_version: "" });
  assert.equal(sent.options.headers["X-CSRF-Token"], "csrf");
  assert.match(h.get("dialog-db-advice").textContent, /Verify compatibility/i);
  assert.equal(h.calls.some(({ path }) => path === "/api/environments/requests"), false);
});

// Exercise the actual boot/session-expiry path without a browser dependency.
test("session expiry removes account identity and unsent private input from DOM", async () => {
  const elements = new Map();
  const get = (id) => {
    if (!elements.has(id))
      elements.set(id, {
        textContent: "",
        value: "",
        hidden: false,
        children: [],
        open: false,
        replaceChildren(...children) {
          this.children = children;
        },
        close() {
          this.open = false;
        },
        addEventListener() {},
        querySelector() { return { disabled: false }; },
      });
    return elements.get(id);
  };
  const chatPanel = { classList: { add() {} } };
  const document = {
    getElementById: get,
    querySelector: () => chatPanel,
    querySelectorAll: () => [],
  };
  get("username-display").textContent = "prior account";
  get("avatar").textContent = "P";
  get("username").value = "prior account";
  get("password").value = "unsent password";
  get("message-text").value = "unsent private question";
  get("dialog-password").value = "UNSENT_WEBSITE_PASSWORD";
  get("run-progress").children = [{ textContent: "private command" }];
  get("dialog-fields").children = [{ value: "private request" }];
  get("dialog-description").textContent = "Reset account for prior user";
  get("filter-user").value = "prior account";
  get("proposal-session").value = "prior session";
  get("proposal-preview").children = [{ textContent: "private generated draft" }];
  get("skill-proposals").children = [{ textContent: "private proposal" }];
  get("proposal-review").children = [{ textContent: "private review" }];
  get("form-dialog").open = true;
  const context = vm.createContext({
    document,
    fetch: async () => ({
      status: 401,
      ok: false,
      json: async () => ({ error: "Unauthorized" }),
    }),
    setInterval: () => 0,
    setTimeout: () => 0,
    clearTimeout: () => {},
  });
  vm.runInContext(
    readFileSync(new URL("./static/app.js", import.meta.url), "utf8"),
    context,
  );
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(get("app").hidden, true);
  assert.equal(get("login").hidden, false);
  assert.equal(get("username-display").textContent, "");
  assert.equal(get("avatar").textContent, "");
  assert.equal(get("username").value, "");
  assert.equal(get("password").value, "");
  assert.equal(get("message-text").value, "");
  assert.equal(get("dialog-password").value, "");
  assert.equal(get("run-progress").children.length, 0);
  assert.equal(get("dialog-fields").children.length, 0);
  assert.equal(get("dialog-description").textContent, "");
  assert.equal(get("filter-user").value, "");
  assert.equal(get("proposal-session").value, "");
  assert.equal(get("proposal-preview").children.length, 0);
  assert.equal(get("skill-proposals").children.length, 0);
  assert.equal(get("proposal-review").children.length, 0);
  assert.equal(get("form-dialog").open, false);
});

function proposalHarness(role, proposals, deferred = false, files = [], activity = []) {
  class Element {
    constructor() { this.children = []; this.value = ""; this.hidden = false; this.dataset = {}; this.listeners = {}; this.classList = { add() {}, remove() {}, toggle() {} }; }
    addEventListener(name, fn) { this.listeners[name] = fn; }
    querySelector() { return this.submitButton ||= new Element(); }
    replaceChildren(...children) { this.children = children; }
    append(...children) { this.children.push(...children); }
    get firstChild() { return this.children[0]; }
    focus() {}
    setAttribute() {}
    showModal() { this.open = true; }
    close() { this.open = false; }
    get textContent() { return this._text || ""; }
    set textContent(text) { this._text = text; this.children = []; }
  }
  const elements = new Map(), get = (id) => {
    const lookup = (item) => item.id === id ? item : item.children?.map(lookup).find(Boolean);
    const dynamic = elements.get("dialog-fields")?.children.map(lookup).find(Boolean);
    if (dynamic) return dynamic;
    if (!elements.has(id)) elements.set(id, new Element());
    return elements.get(id);
  };
  const calls = [], sessionId = "22222222-2222-4222-8222-222222222222";
  let release;
  const pending = new Promise((resolve) => { release = resolve; });
  const responses = {
    "/api/me": { user: { username: "alice", role }, csrfToken: "csrf" },
    "/api/labs": { labs: [] }, "/api/gateways": { gateways: [] },
    "/api/sessions": { sessions: [{ id: sessionId, title: "Selected" }] },
    [`/api/sessions/${sessionId}`]: { session: { id: sessionId, title: "Selected" }, messages: [] },
    "/api/runs": { runs: [] }, "/api/requests": { requests: [] },
    "/api/activity": { events: activity }, "/api/users": { users: [] },
    "/api/skill-proposals": { proposals }, "/api/files": { files },
    "/api/db-advice": { advice: "Verify vendor documentation; no version selected.", status: "advisory" },
    [`/api/sessions/${sessionId}/skill-draft`]: { proposal: { id: "33333333-3333-4333-8333-333333333333", session_id: sessionId, title: "Generated lesson", guidance: "Check vendor releases", evidence: "Verified session reference", status: "draft" } },
  };
  const document = {
    getElementById: get,
    createElement: (tag) => Object.assign(new Element(), { tagName: tag.toUpperCase() }),
    querySelector: () => new Element(),
    querySelectorAll: (selector) => selector === ".view" ? ["overview", "sessions", "activity", "access", "skill-proposals", "files", "users"].map((name) => Object.assign(get(`${name}-view`), { id: `${name}-view` })) : [], hidden: false,
  };
  get("files-view").hidden = true;
  const context = vm.createContext({ document, URLSearchParams, window: { confirm: () => true }, setTimeout: () => 0, clearTimeout() {}, setInterval() {}, fetch: async (path, options = {}) => {
    calls.push({ path, options });
    if (deferred === "get" && path === "/api/skill-proposals" && !options.method || deferred === "draft" && path.endsWith("/skill-draft") || deferred === "submit" && path.endsWith("/submit") || deferred === "files" && path === "/api/files" && !options.method || deferred === "upload" && path === "/api/files" && options.method === "POST" || deferred === "advice" && path === "/api/db-advice") await pending;
    return { ok: true, status: 200, json: async () => responses[path] || { id: "new", status: "pending" } };
  } });
  vm.runInContext(readFileSync(new URL("./static/app.js", import.meta.url), "utf8"), context);
  const texts = (item) => [item.textContent, ...(item.children || []).flatMap(texts)];
  const button = (item, label) => item.textContent === label && item.listeners?.click ? item : item.children?.map((child) => button(child, label)).find(Boolean);
  return { get, calls, release, texts, button, sessionId };
}

test("Activity shows the owner's timed agent trail and only aggregate peer highlights", async () => {
  const sessionId = "22222222-2222-4222-8222-222222222222";
  const events = [
    { id: "mine", kind: "hermes", user: "alice", status: "failed", lab_id: "dam-mxha",
      session_id: sessionId, tool_attempts: 1, tool_errors: 1,
      steps: [{ at: "2026-10-22T00:00:00Z", status: "running", summary: "Trying terminal: git status --short" },
        { at: "2026-10-22T00:01:00Z", status: "failed", summary: "terminal returned an error" }] },
    { id: "peer", kind: "hermes", user: "bob", status: "completed", lab_id: "dam-mxha",
      tool_attempts: 2, tool_errors: 0, steps: [{ summary: "OTHER_USER_CANARY" }] },
  ];
  const h = proposalHarness("admin", [], false, [], events);
  await new Promise((resolve) => setImmediate(resolve));
  const cards = h.get("activity-events").children;
  assert.ok(h.texts(cards[0]).some((text) => text.includes("git status --short")));
  assert.ok(h.texts(cards[0]).some((text) => text.includes("1 tool attempt")));
  assert.ok(h.texts(cards[0]).some((text) => text.includes("1 reported tool error")));
  assert.ok(h.texts(cards[0]).some((text) => text.includes("Recorded agent actions")));
  assert.ok(h.button(cards[0], "Open session"));
  assert.equal(h.texts(cards[1]).includes("OTHER_USER_CANARY"), false);
  assert.equal(h.button(cards[1], "Open session"), undefined);
  await h.button(cards[0], "Open session").listeners.click();
  assert.ok(h.calls.some(({ path }) => path === `/api/sessions/${sessionId}`));
});

test("Files tab is admin-only and shows download links without internal paths", async () => {
  const html = readFileSync(new URL("./static/index.html", import.meta.url), "utf8");
  for (const id of ["files-nav", "files-view", "file-form", "file-input", "files"])
    assert.match(html, new RegExp(`id="${id}"`));
  assert.match(html, /256 MiB/);
  assert.match(html, /no virus scanning/i);
  assert.match(html, /admin.only/i);
  const file = { id: "11111111-1111-4111-8111-111111111111", name: "patch.bin", size: 25, sha256: "abcd", created_at: "2026-10-20T00:00:00Z", user: "alice", path: "/private/raw/path" };
  const h = proposalHarness("admin", [], false, [file]);
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(h.get("files-nav").hidden, false);
  assert.ok(h.texts(h.get("files")).includes("patch.bin"));
  assert.equal(h.texts(h.get("files")).some((text) => text.includes("/private/raw/path")), false);
  const link = h.get("files").children[0].children.find((child) => child.tagName === "A");
  assert.equal(link.href, `/api/files/${file.id}/download`);
  const tester = proposalHarness("tester", [], false, [file]);
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(tester.get("files-nav").hidden, true);
  assert.equal(tester.calls.some(({ path }) => path === "/api/files"), false);
  tester.get("nav").listeners.click({ target: { closest: () => ({ dataset: { view: "files" } }) } });
  assert.equal(tester.get("files-view").hidden, true);
});

test("admin file upload sends binary, filename and CSRF but rejects over 256 MiB", async () => {
  const h = proposalHarness("admin", []);
  await new Promise((resolve) => setImmediate(resolve));
  const file = { name: "update.tar.gz", size: 12 };
  h.get("file-input").files = [file];
  await h.get("file-form").listeners.submit({ preventDefault() {} });
  const sent = h.calls.find(({ path, options }) => path === "/api/files" && options.method === "POST");
  assert.equal(sent.options.body, file);
  assert.equal(sent.options.headers["X-File-Name"], "update.tar.gz");
  assert.equal(sent.options.headers["X-CSRF-Token"], "csrf");
  assert.equal(sent.options.headers["Content-Type"], "application/octet-stream");
  h.get("file-input").files = [{ name: "oversized.bin", size: 256 * 1024 * 1024 + 1 }];
  await h.get("file-form").listeners.submit({ preventDefault() {} });
  assert.equal(h.calls.filter(({ path, options }) => path === "/api/files" && options.method === "POST").length, 1);
  assert.match(h.get("file-error").textContent, /256 MiB/);
});

test("late file listing after logout cannot restore private data", async () => {
  const h = proposalHarness("admin", [], "files", [{ id: "old", name: "private.bin", user: "alice" }]);
  await new Promise((resolve) => setImmediate(resolve));
  await h.get("logout").listeners.click();
  h.release();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(h.get("files").children.length, 0);
  assert.equal(h.get("file-input").value, "");
});

test("late file upload after logout cannot restore an admin notice", async () => {
  const h = proposalHarness("admin", [], "upload");
  await new Promise((resolve) => setImmediate(resolve));
  h.get("file-input").files = [{ name: "patch.bin", size: 9 }];
  const upload = h.get("file-form").listeners.submit({ preventDefault() {} });
  await h.get("logout").listeners.click();
  h.release();
  await upload;
  assert.equal(h.get("notice").hidden, true);
  assert.equal(h.get("files").children.length, 0);
  assert.equal(h.get("file-input").value, "");
});

test("late database advice cannot reappear after logout", async () => {
  const h = proposalHarness("tester", [], "advice");
  await new Promise((resolve) => setImmediate(resolve));
  h.get("new-environment").listeners.click();
  h.get("dialog-topology").value = "database";
  h.get("dialog-topology").listeners.change();
  h.get("dialog-db-engine").value = "postgresql";
  const advice = h.get("dialog-db-advice-button").listeners.click();
  await h.get("logout").listeners.click();
  h.release();
  await advice;
  assert.equal(h.get("dialog-fields").children.length, 0);
  assert.equal(h.get("notice").hidden, true);
});

test("late database advice cannot describe an outdated engine or OS", async () => {
  const h = proposalHarness("tester", [], "advice");
  await new Promise((resolve) => setImmediate(resolve));
  h.get("new-environment").listeners.click();
  h.get("dialog-topology").value = "database";
  h.get("dialog-topology").listeners.change();
  h.get("dialog-db-engine").value = "postgresql";
  const pending = h.get("dialog-db-advice-button").listeners.click();
  h.get("dialog-db-engine").value = "mysql";
  h.get("dialog-db-engine").listeners.change();
  h.release();
  await pending;
  assert.doesNotMatch(h.get("dialog-db-advice").textContent, /Verify compatibility/i);
});

test("owner generates a session draft and previews it without submitting", async () => {
  const html = readFileSync(new URL("./static/index.html", import.meta.url), "utf8");
  assert.match(html, /data-view="skill-proposals"/);
  for (const id of ["skill-proposals-view", "proposal-form", "proposal-session", "proposal-preview", "suggest-session-skill", "skill-proposals"])
    assert.match(html, new RegExp(`id="${id}"`));
  assert.doesNotMatch(html, /id="proposal-(title|guidance|evidence)"/);
  const h = proposalHarness("tester", [{ id: "one", user: "alice", title: "Version check", guidance: "Check vendor availability", evidence: "Vendor matrix", status: "pending" }]);
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(h.get("proposal-review").hidden, true);
  assert.ok(h.texts(h.get("skill-proposals")).includes("Vendor matrix"));
  assert.ok(h.texts(h.get("skill-proposals")).includes("pending"));
  h.get("proposal-session").value = h.sessionId;
  await h.get("proposal-form").listeners.submit({ preventDefault() {} });
  const sent = h.calls.find(({ path }) => path.endsWith("/skill-draft"));
  assert.equal(sent.path, `/api/sessions/${h.sessionId}/skill-draft`);
  assert.deepEqual(JSON.parse(sent.options.body), {});
  assert.equal(sent.options.headers["X-CSRF-Token"], "csrf");
  assert.ok(h.texts(h.get("proposal-preview")).includes("Generated lesson"));
  assert.ok(h.texts(h.get("proposal-preview")).includes("Check vendor releases"));
  assert.ok(h.texts(h.get("proposal-preview")).includes("Verified session reference"));
  assert.equal(h.calls.some(({ path, options }) => path === "/api/skill-proposals" && options.method === "POST"), false);
  assert.equal(h.calls.some(({ path }) => path.endsWith("/submit")), false);
  assert.equal(h.calls.some(({ path }) => path.includes("/decision")), false);
});

test("session-pane suggestion opens generated preview; owner submits only by explicit click", async () => {
  const h = proposalHarness("tester", []);
  await new Promise((resolve) => setImmediate(resolve));
  await h.get("session-list").children[0].listeners.click();
  assert.equal(h.get("suggest-session-skill").hidden, false);
  await h.get("suggest-session-skill").listeners.click();
  assert.equal(h.get("skill-proposals-view").hidden, false);
  assert.ok(h.texts(h.get("proposal-preview")).includes("Generated lesson"));
  assert.equal(h.calls.some(({ path }) => path.endsWith("/submit")), false);
  await h.button(h.get("proposal-preview"), "Submit for review").listeners.click();
  const sent = h.calls.find(({ path }) => path.endsWith("/submit"));
  assert.equal(sent.path, "/api/skill-proposals/33333333-3333-4333-8333-333333333333/submit");
  assert.deepEqual(JSON.parse(sent.options.body), {});
  assert.equal(sent.options.headers["X-CSRF-Token"], "csrf");
  assert.equal(h.button(h.get("proposal-preview"), "Submit for review"), undefined);
});

test("owner can discard a generated draft without review", async () => {
  const h = proposalHarness("tester", []);
  await new Promise((resolve) => setImmediate(resolve));
  h.get("proposal-session").value = h.sessionId;
  await h.get("proposal-form").listeners.submit({ preventDefault() {} });
  await h.button(h.get("proposal-preview"), "Discard draft").listeners.click();
  const sent = h.calls.find(({ path }) => path.endsWith("/discard"));
  assert.equal(sent.path, "/api/skill-proposals/33333333-3333-4333-8333-333333333333/discard");
  assert.deepEqual(JSON.parse(sent.options.body), {});
  assert.equal(h.button(h.get("proposal-preview"), "Submit for review"), undefined);
  assert.equal(h.texts(h.get("skill-proposals")).includes("Generated lesson"), false);
  assert.equal(h.texts(h.get("proposal-preview")).includes("Generated lesson"), false);
  assert.equal(h.texts(h.get("skill-proposals")).includes("Check vendor releases"), false);
});

test("admin reviews pending proposal with independently edited guidance", async () => {
  const h = proposalHarness("admin", [{ id: "11111111-1111-4111-8111-111111111111", user: "bob", title: "Version 14.13", guidance: "Install 14.13 now", evidence: "Unverified chat output", status: "pending" }]);
  await new Promise((resolve) => setImmediate(resolve));
  const review = h.get("proposal-review");
  assert.equal(review.hidden, false);
  assert.ok(h.texts(review).includes("Unverified chat output"));
  const approved = review.children[0].children.find((el) => el.tagName === "TEXTAREA");
  assert.equal(approved.value, "", "untrusted suggestion must not prefill approved guidance");
  approved.value = "Check vendor release matrix first; if unavailable, use documented upgrade path.";
  const note = review.children[0].children.find((el) => el.tagName === "INPUT");
  note.value = "Verified against release matrix";
  await h.button(review, "Approve").listeners.click();
  const sent = h.calls.find(({ path }) => path.endsWith("/decision"));
  assert.equal(sent.path, "/api/skill-proposals/11111111-1111-4111-8111-111111111111/decision");
  assert.deepEqual(JSON.parse(sent.options.body), { decision: "approved", approved_text: approved.value, review_note: note.value });
});

test("admin sees own pending proposal but cannot review it", async () => {
  const h = proposalHarness("admin", [{ id: "mine", user: "alice", title: "Needs peer review", guidance: "Draft guidance", evidence: "Vendor documentation", status: "pending" }]);
  await new Promise((resolve) => setImmediate(resolve));
  assert.ok(h.texts(h.get("skill-proposals")).includes("Needs peer review"));
  assert.equal(h.button(h.get("proposal-review"), "Approve"), undefined);
});

test("admin can retry only the recorded reviewed wording after publication failure", async () => {
  const id = "11111111-1111-4111-8111-111111111111";
  const h = proposalHarness("admin", [{ id, user: "bob", title: "Patch selection", status: "approving",
    guidance: "Draft", evidence: "Vendor notes", approved_text: "Verified exact patch and upgrade path before confirming.",
    review_note: "Thales notes checked" }]);
  await new Promise((resolve) => setImmediate(resolve));
  await h.button(h.get("skill-proposals"), "Retry publication").listeners.click();
  const sent = h.calls.find(({ path }) => path.endsWith("/decision"));
  assert.deepEqual(JSON.parse(sent.options.body), { decision: "approved", approved_text: "Verified exact patch and upgrade path before confirming.", review_note: "Thales notes checked" });
  assert.equal(h.button(h.get("proposal-review"), "Approve"), undefined);
});

test("expired session ignores a late proposal-list response", async () => {
  const h = proposalHarness("tester", [{ id: "old", user: "alice", title: "Private", evidence: "Secret" }], "get");
  await new Promise((resolve) => setImmediate(resolve));
  await h.get("logout").listeners.click();
  h.release();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(h.get("proposal-session").value, "");
  assert.equal(h.get("proposal-preview").children.length, 0);
  assert.equal(h.get("skill-proposals").children.length, 0);
  assert.equal(h.get("proposal-review").children.length, 0);
});

test("tester never renders another user's proposal even if returned by API", async () => {
  const h = proposalHarness("tester", [
    { id: "mine", user: "alice", title: "Mine", evidence: "My source", status: "pending" },
    { id: "other", user: "bob", title: "Other private proposal", evidence: "Private source", status: "pending" },
  ]);
  await new Promise((resolve) => setImmediate(resolve));
  assert.ok(h.texts(h.get("skill-proposals")).includes("Mine"));
  assert.equal(h.texts(h.get("skill-proposals")).includes("Other private proposal"), false);
  assert.equal(h.get("proposal-review").children.length, 0);
});

test("logout during draft generation keeps a late response out of the next account", async () => {
  const h = proposalHarness("tester", [], "draft");
  await new Promise((resolve) => setImmediate(resolve));
  h.get("proposal-session").value = h.sessionId;
  const submit = h.get("proposal-form").querySelector('button[type="submit"]');
  const generation = h.get("proposal-form").listeners.submit({ preventDefault() {} });
  await h.get("logout").listeners.click();
  h.release();
  await generation;
  assert.equal(h.get("proposal-session").value, "");
  assert.equal(h.get("proposal-preview").children.length, 0);
  assert.equal(h.get("skill-proposals").children.length, 0);
  assert.equal(submit.disabled, false);
});

test("logout during draft submission keeps a late response out of the next account", async () => {
  const h = proposalHarness("tester", [{ id: "draft-id", user: "alice", title: "Private draft", guidance: "Private guidance", evidence: "Private evidence", status: "draft" }], "submit");
  await new Promise((resolve) => setImmediate(resolve));
  const submitting = h.button(h.get("proposal-preview"), "Submit for review").listeners.click();
  await h.get("logout").listeners.click();
  h.release();
  await submitting;
  assert.equal(h.get("proposal-preview").children.length, 0);
  assert.equal(h.get("skill-proposals").children.length, 0);
});

test("admins cannot see another owner's drafts even if the API returns them", async () => {
  const h = proposalHarness("admin", [
    { id: "mine", user: "alice", title: "Mine", guidance: "My draft", status: "draft" },
    { id: "other", user: "bob", title: "Other private draft", guidance: "Secret guidance", status: "draft" },
    { id: "submitted", user: "bob", title: "Peer submission", status: "pending" },
  ]);
  await new Promise((resolve) => setImmediate(resolve));
  assert.ok(h.texts(h.get("proposal-preview")).includes("My draft"));
  assert.equal(h.texts(h.get("skill-proposals")).includes("Other private draft"), false);
  assert.ok(h.texts(h.get("proposal-review")).some((text) => text.includes("Peer submission")));
});
