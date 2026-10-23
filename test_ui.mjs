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
    "/api/requests": { requests: [{ id: "legacy", lab_id: "dam-mxha", kind: "environment", status: "pending", user: "alice", proposed_name: null, spec: { lab_id: "new", topology: "mxha", gateway_count: 1, db_version: "", ttl_hours: 24, max_spend_usd: 100 }, note: "Old request" }] }, "/api/activity": { events: [] },
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
  assert.equal(get("dialog-topology").children.some((option) => option.value === "database"), false);
  assert.equal(get("dialog-fields").children.some((child) => /Database engine|OS and version/.test(child.textContent)), false);
  get("dialog-lab").value = "dam-mxha";
  get("dialog-topology").value = "mxha";
  get("dialog-gateways").value = "2";
  get("dialog-version").value = "14.19.1.150";
  get("dialog-detail").value = "Need isolated test environment";
  await get("dialog-form").listeners.submit({ preventDefault() {} });
  const environment = calls.find(({ path, options }) => path === "/api/environments/requests" && options.method === "POST");
  assert.ok(environment);
  assert.deepEqual(JSON.parse(environment.options.body), { lab_id: "dam-mxha", topology: "mxha", gateway_count: 2, version: "14.19.1.150", purpose: "Need isolated test environment" });
  assert.equal(get("dialog-fields").children.some((child) => /Expiry in hours|Maximum spend/.test(child.textContent)), false);
  assert.match(get("notice").textContent, /unlocks an admin fulfillment session/);
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
  assert.equal(get("form-dialog").open, false);
});
