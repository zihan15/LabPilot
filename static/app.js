(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const state = {
    csrf: "",
    me: null,
    labs: [],
    gateways: [],
    sessions: [],
    runs: [],
    requests: [],
    users: [],
    events: [],
    activityTicket: 0,
    sessionId: null,
    sessionTicket: 0,
    modal: null,
    pendingRun: null,
    runsLoaded: false,
    authEpoch: 0,
  };
  const node = (tag, className, text) => {
    const n = document.createElement(tag);
    if (className) n.className = className;
    if (text !== undefined && text !== null) n.textContent = String(text);
    return n;
  };
  const value = (v, fallback = "Unknown") =>
    v === null || v === undefined || v === "" ? fallback : String(v);
  const rows = (data, key) =>
    Array.isArray(data) ? data : Array.isArray(data?.[key]) ? data[key] : [];
  const time = (input) => {
    if (!input) return "Not observed";
    const date = new Date(input);
    return Number.isNaN(date.getTime())
      ? "Time unknown"
      : date.toLocaleString(undefined, {
          dateStyle: "medium",
          timeStyle: "short",
        });
  };
  const statusClass = (input) => {
    const s = String(input || "").toLowerCase();
    if (
      [
        "healthy",
        "ok",
        "ready",
        "completed",
        "succeeded",
        "success",
        "approved",
      ].includes(s)
    )
      return "good";
    if (
      [
        "failed",
        "error",
        "unhealthy",
        "denied",
        "rejected",
        "stopped",
        "terminated",
      ].includes(s)
    )
      return "bad";
    if (
      [
        "running",
        "pending",
        "queued",
        "starting",
        "degraded",
        "warning",
        "requested",
      ].includes(s)
    )
      return "warn";
    return "";
  };
  const badge = (text, kind) =>
    node("span", `pill ${kind ?? statusClass(text)}`, value(text));
  const empty = (text, error = false) =>
    node("div", `empty${error ? " error-state" : ""}`, text);
  function notice(text, error = false) {
    const n = $("notice");
    n.textContent = text;
    n.className = `notice${error ? " error" : ""}`;
    n.hidden = false;
    clearTimeout(notice.timer);
    notice.timer = setTimeout(() => {
      n.hidden = true;
    }, 6500);
  }
  async function api(path, options = {}) {
    const epoch = state.authEpoch;
    const headers = {
      Accept: "application/json",
      ...(options.body ? { "Content-Type": "application/json" } : {}),
    };
    if (options.method && options.method !== "GET" && state.csrf)
      headers["X-CSRF-Token"] = state.csrf;
    const response = await fetch(path, {
      credentials: "same-origin",
      ...options,
      headers: { ...headers, ...options.headers },
    });
    if (epoch !== state.authEpoch) throw new Error("Session changed");
    if (
      response.status === 401 &&
      path !== "/api/login" &&
      path !== "/api/me"
    ) {
      showLogin();
      throw new Error("Your session expired. Please sign in again.");
    }
    let body = null;
    try {
      body = await response.json();
    } catch {
      /* Empty or non-JSON response. */
    }
    if (epoch !== state.authEpoch) throw new Error("Session changed");
    if (!response.ok)
      throw new Error(
        value(
          body?.error || body?.message,
          `Request failed (${response.status})`,
        ),
      );
    return body || {};
  }
  const post = (path, payload) =>
    api(path, { method: "POST", body: JSON.stringify(payload) });
  function captureCsrf(body) {
    state.csrf =
      body?.csrf_token || body?.csrfToken || body?.csrf || state.csrf;
  }
  function showLogin() {
    state.authEpoch++;
    state.me = null;
    state.csrf = "";
    state.labs = [];
    state.gateways = [];
    state.sessions = [];
    state.runs = [];
    state.requests = [];
    state.users = [];
    state.events = [];
    state.activityTicket++;
    state.sessionId = null;
    state.pendingRun = null;
    state.runsLoaded = false;
    state.sessionTicket++;
    const dialogPassword = $("dialog-password");
    if (dialogPassword) dialogPassword.value = "";
    if ($("form-dialog").open) $("form-dialog").close();
    state.modal = null;
    $("dialog-fields").replaceChildren();
    $("dialog-title").textContent = "";
    $("dialog-description").textContent = "";
    $("dialog-error").textContent = "";
    $("dialog-error").hidden = true;
    $("message-text").value = "";
    $("username-display").textContent = "";
    $("avatar").textContent = "";
    for (const id of [
      "labs",
      "gateways",
      "agents",
      "agent-preview",
      "timeline",
      "session-list",
      "messages",
      "run-progress",
      "requests",
      "users",
      "activity-events",
      "chat-header",
    ])
      $(id).replaceChildren();
    $("lab-summary").textContent = "Loading observations…";
    $("observation-stamp").textContent = "Waiting for AWS observation";
    $("message-form").hidden = true;
    $("grant-login").hidden = true;
    document.querySelector(".chat-panel").classList.add("is-empty");
    $("notice").hidden = true;
    $("notice").textContent = "";
    $("users-nav").hidden = true;
    $("filter-user-label").hidden = true;
    for (const id of ["filter-user", "filter-lab", "filter-kind", "filter-status"])
      $(id).value = "";
    for (const id of ["filter-lab", "filter-kind", "filter-status"])
      $(id).replaceChildren();
    $("app").hidden = true;
    $("login").hidden = false;
    $("username").value = "";
    $("password").value = "";
    $("login-error").textContent = "";
    $("login-error").hidden = true;
  }
  async function signedIn(body) {
    state.me = body?.user || body?.me || body;
    captureCsrf(body);
    $("username-display").textContent = value(
      state.me?.username || state.me?.name,
      "Team member",
    );
    $("avatar").textContent = String(
      state.me?.username || state.me?.name || "L",
    )
      .charAt(0)
      .toUpperCase();
    $("login").hidden = true;
    $("app").hidden = false;
    $("users-nav").hidden = !isAdmin();
    $("filter-user-label").hidden = !isAdmin();
    view("overview");
    await Promise.all([
      loadLabs(),
      loadGateways(),
      loadSessions(),
      loadRuns(),
      loadRequests(),
      loadActivity(),
      ...(isAdmin() ? [loadUsers()] : []),
    ]);
  }
  function view(name) {
    if (!state.me || (name === "users" && !isAdmin())) return;
    for (const section of document.querySelectorAll(".view"))
      section.hidden = section.id !== `${name}-view`;
    for (const button of document.querySelectorAll(".nav-item")) {
      button.classList.toggle("selected", button.dataset.view === name);
      button.setAttribute(
        "aria-current",
        button.dataset.view === name ? "page" : "false",
      );
    }
    $("crumb").textContent = {
      overview: "Lab inventory",
      sessions: "Sessions",
      activity: "Activity",
      access: "Access requests",
      users: "Users",
    }[name];
    $("main").focus({ preventScroll: true });
  }
  async function loadLabs() {
    const epoch = state.authEpoch,
      refresh = $("refresh");
    refresh.disabled = true;
    refresh.textContent = "Refreshing…";
    try {
      const labs = rows(await api("/api/labs"), "labs");
      if (epoch !== state.authEpoch) return;
      state.labs = labs;
      renderLabs();
      renderSessions();
      renderRequests();
      renderLabFilter();
      if (state.events.length) renderActivity();
    } catch (err) {
      if (state.me && epoch === state.authEpoch) {
        if (state.labs.length) {
          renderLabs();
          $("labs").prepend(
            empty(
              `Refresh failed: ${err.message}. Previous observations may be stale.`,
              true,
            ),
          );
        } else {
          $("lab-summary").textContent =
            "Observation unavailable. No live product check has been made.";
          $("observation-stamp").textContent = "No current observation";
          $("labs").replaceChildren(
            empty(`Labs unavailable: ${err.message}`, true),
          );
        }
        notice(err.message, true);
      }
    } finally {
      if (epoch === state.authEpoch) {
        refresh.disabled = false;
        refresh.textContent = "Refresh";
      }
    }
  }
  function renderLabs() {
    const root = $("labs");
    root.replaceChildren();
    const components = state.labs.flatMap((lab) =>
      Array.isArray(lab.components) ? lab.components : [],
    );
    const running = components.filter((c) => c.ec2State === "running").length;
    const stopped = components.filter((c) => c.ec2State === "stopped").length;
    const missing = components.length - running - stopped;
    const counts = [
      `${components.length} component${components.length === 1 ? "" : "s"} observed`,
      `${running} EC2 running`,
      `${stopped} stopped`,
    ];
    if (missing) counts.push(`${missing} other / unknown`);
    $("lab-summary").textContent = state.labs.length
      ? `${counts.join(" · ")}. Product health is not checked here.`
      : "No lab observations available.";
    const stamp = state.labs[0]?.observedAt;
    $("observation-stamp").textContent = stamp
      ? `AWS observation · ${time(stamp)}`
      : "Observation time unknown";
    if (!state.labs.length) {
      root.append(
        empty(
          "No labs are available to your account yet. Request access to get started.",
        ),
      );
      return;
    }
    for (const lab of state.labs) {
      const item = node("article", "lab-item");
      const parts = Array.isArray(lab.components) ? lab.components : [];
      const countsByState = new Map();
      for (const part of parts)
        countsByState.set(
          value(part.ec2State, "unknown"),
          (countsByState.get(value(part.ec2State, "unknown")) || 0) + 1,
        );
      const stateText = parts.length
        ? [...countsByState]
            .map(([name, count]) => `${count} ${name}`)
            .join(" · ")
        : "EC2 state unknown";
      const status =
        parts.length && parts.every((c) => c.ec2State === "running")
          ? "good"
          : parts.some((c) => c.ec2State === "failed")
            ? "bad"
            : "";
      const header = node("div", "lab-header"),
        title = node("div");
      title.append(
        node("h3", "lab-title", value(lab.name, "Unnamed lab")),
        node("div", "lab-owner", `Owner: ${value(lab.owner, "Unassigned")}`),
      );
      header.append(title, node("span", `lab-state ${status}`, stateText));
      item.append(header);
      if (parts.length) {
        const table = node("table", "component-table");
        const head = node("thead"),
          headings = node("tr");
        for (const label of ["Component", "EC2 state", "Product check"]) {
          const th = node("th", "", label);
          th.scope = "col";
          headings.append(th);
        }
        head.append(headings);
        table.append(head);
        const body = node("tbody");
        for (const part of parts) {
          const health =
            part.productHealth === "unknown"
              ? "Not checked"
              : value(part.productHealth, "Not checked");
          const row = node("tr"),
            name = node("td"),
            ec2 = node("td", "ec2-state", value(part.ec2State)),
            product = node("td", "product-state", health);
          name.append(
            node(
              "div",
              "component-name",
              value(part.name, "Unnamed component"),
            ),
            node("div", "component-role", value(part.role, "Role unknown")),
            node("div", "mobile-product-state", `Product: ${health}`),
          );
          if (lab.start_available === true && part.id && (part.ec2State === "stopped" || (isAdmin() && part.ec2State === "running"))) {
            const operation = part.ec2State === "stopped" ? "start" : "stop";
            const control = node("button", "text-button component-action", `${operation === "start" ? "Start" : "Stop"} ${part.name}`);
            control.type = "button";
            control.addEventListener("click", async () => {
              const warning = operation === "stop"
                ? "This interrupts tests and may lose unflushed or instance-store data. Verify workload and backup readiness."
                : "This incurs AWS charges and does not verify product health.";
              if (!window.confirm(`${operation === "start" ? "Start" : "Stop"} ${part.name}? ${warning}`)) return;
              const epoch = state.authEpoch;
              control.disabled = true;
              try {
                const result = await post(`/api/labs/${encodeURIComponent(lab.id)}/components/${encodeURIComponent(part.id)}/${operation}`, {});
                if (epoch !== state.authEpoch) return;
                notice(result.requested ? `${part.name}: EC2 ${operation} accepted; product health not verified.` : `${part.name}: no new EC2 ${operation} needed (${result.status}).`);
                await loadLabs();
                await loadActivity();
              } catch (err) {
                if (epoch === state.authEpoch) notice(`${part.name}: ${operation} unavailable: ${err.message}`, true);
              } finally { control.disabled = false; }
            });
            name.append(control);
          }
          if (part.ec2State === "running") ec2.classList.add("good");
          if (part.ec2State === "failed") ec2.classList.add("bad");
          row.append(name, ec2, product);
          body.append(row);
        }
        table.append(body);
        item.append(table);
      } else
        item.append(
          empty(
            "No matching components observed. EC2 state and product health are unknown.",
          ),
        );
      const stacks =
        lab.stackStatus && typeof lab.stackStatus === "object"
          ? Object.entries(lab.stackStatus).sort(([a], [b]) =>
              a.localeCompare(b),
            )
          : [];
      if (stacks.length) {
        const line = node("div", "lab-stack");
        for (const [name, status] of stacks) {
          const entry = node("span");
          entry.append(
            node("span", "", `${name} stack: `),
            node("strong", "", status),
          );
          line.append(entry);
        }
        item.append(line);
      }
      const observed = node("div", "lab-observation");
      observed.append(
        node("strong", "", `Observed ${time(lab.observedAt)}`),
        node("div", "", "Source: AWS EC2 and CloudFormation"),
      );
      if (Array.isArray(lab.errors) && lab.errors.length)
        observed.append(node("div", "lab-error", lab.errors.join("; ")));
      const footer = node("div", "lab-footer"),
        button = node("button", "button primary hermes-session-cta", "Start Hermes session");
      button.type = "button";
      button.addEventListener("click", () => openNewSession(lab.id));
      footer.append(observed, button);
      if (parts.length === 3 && parts.some((part) => part.ec2State === "stopped") && parts.every((part) => ["stopped", "running"].includes(part.ec2State)) && lab.start_available === true) {
        const start = node("button", "button outline", "Start lab");
        start.type = "button";
        start.addEventListener("click", async () => {
          if (!window.confirm(`Start the stopped EC2 components of ${lab.name}? This incurs AWS charges, has no automatic stop, and does not verify product health.`)) return;
          const epoch = state.authEpoch;
          start.disabled = true;
          try {
            const result = await post(`/api/labs/${encodeURIComponent(lab.id)}/start`, {});
            if (epoch !== state.authEpoch) return;
            notice(result.status === "already_running" ? "EC2 instances were already running; product health remains unverified." : result.status === "pending" ? "EC2 start was already pending; no new start requested. Refresh observations for state." : "EC2 start accepted. Refresh observations for state; product health remains unverified.");
            await loadLabs();
            await loadActivity();
          } catch (err) {
            if (epoch === state.authEpoch) notice(`Start unavailable: ${err.message}`, true);
          } finally { start.disabled = false; }
        });
        footer.append(start);
      }
      if (isAdmin() && lab.start_available === true && parts.length === 3 && parts.some((part) => part.ec2State === "running") && parts.every((part) => ["stopped", "running"].includes(part.ec2State))) {
        const stop = node("button", "button outline", "Stop lab");
        stop.type = "button";
        stop.addEventListener("click", async () => {
          if (!window.confirm(`Stop running EC2 components of ${lab.name}? This interrupts tests, disconnects users, and may lose unflushed or instance-store data. EC2 may change public IPs. Verify workload/backup readiness before continuing.`)) return;
          const epoch = state.authEpoch;
          stop.disabled = true;
          try {
            const result = await post(`/api/labs/${encodeURIComponent(lab.id)}/stop`, {});
            if (epoch !== state.authEpoch) return;
            notice(result.status === "pending" ? "EC2 stop was already pending; no new stop requested." : result.status === "already_stopped" ? "EC2 instances were already stopped; no new stop requested." : "EC2 stop accepted. Refresh observations for state; product health remains unverified.");
            await loadLabs();
            await loadActivity();
          } catch (err) {
            if (epoch === state.authEpoch) notice(`Stop unavailable: ${err.message}`, true);
          } finally { stop.disabled = false; }
        });
        footer.append(stop);
      }
      item.append(footer);
      root.append(item);
    }
  }
  const isAdmin = () =>
    state.me?.is_admin === true ||
    state.me?.isAdmin === true ||
    String(state.me?.role || "").toLowerCase() === "admin" ||
    (Array.isArray(state.me?.roles) && state.me.roles.includes("admin"));
  function renderLabFilter() {
    const select = $("filter-lab"), current = select.value;
    select.replaceChildren(node("option", "", "All environments"));
    select.firstChild.value = "";
    for (const lab of state.labs) {
      const option = node("option", "", value(lab.name, "Unnamed lab"));
      option.value = String(lab.id);
      select.append(option);
    }
    select.value = current;
  }
  async function loadActivity() {
    const epoch = state.authEpoch, ticket = ++state.activityTicket;
    const params = new URLSearchParams();
    for (const [id, key] of [["filter-user", "user"], ["filter-lab", "lab_id"], ["filter-status", "status"], ["filter-kind", "kind"]]) {
      const selected = $(id).value.trim();
      if (selected && (key !== "user" || isAdmin())) params.set(key, selected);
    }
    try {
      const events = rows(await api(`/api/activity${params.size ? `?${params}` : ""}`), "events");
      if (epoch !== state.authEpoch || ticket !== state.activityTicket) return;
      state.events = events;
      renderActivity();
    } catch (err) {
      if (state.me && epoch === state.authEpoch && ticket === state.activityTicket)
        $("activity-events").replaceChildren(empty(`Activity unavailable: ${err.message}`, true));
    }
  }
  function renderActivity() {
    const root = $("activity-events");
    root.replaceChildren();
    for (const [id, key, choices] of [["filter-kind", "kind", ["hermes", "advisory", "request", "start", "stop"]], ["filter-status", "status", ["queued", "running", "completed", "failed", "pending", "approved", "denied", "starting", "already_running", "stopping", "already_stopped", "unknown"]]]) {
      const select = $(id), selected = select.value;
      select.replaceChildren(node("option", "", `All ${key === "kind" ? "kinds" : "statuses"}`));
      select.firstChild.value = "";
      for (const choice of choices) {
        const option = node("option", "", choice);
        option.value = choice;
        select.append(option);
      }
      select.value = selected;
    }
    if (!state.events.length) root.append(empty("No matching events recorded."));
    for (const event of state.events) {
      const card = node("article", "event-card");
      card.append(node("div", "event-route", `${value(event.user, "Unknown user")} → ${value(state.labs.find((lab) => String(lab.id) === String(event.lab_id))?.name, value(event.lab_id, "Unknown environment"))}`));
      const meta = node("div", "event-meta");
      meta.append(badge(value(event.kind)), badge(value(event.status)), node("span", "", time(event.updated_at || event.created_at)));
      card.append(meta, node("p", "event-summary", value(event.summary, "No summary recorded.")), node("strong", "", "Things checked"));
      const checks = Array.isArray(event.checks) && event.checks.length ? event.checks : ["No checks recorded; product health not verified."];
      const list = node("ul", "event-checks");
      for (const check of checks) list.append(node("li", "", check));
      card.append(list);
      root.append(card);
    }
  }
  async function loadUsers() {
    if (!isAdmin()) return;
    const epoch = state.authEpoch;
    try {
      const users = rows(await api("/api/users"), "users");
      if (epoch !== state.authEpoch || !isAdmin()) return;
      state.users = users;
      renderUsers();
    } catch (err) {
      if (state.me && epoch === state.authEpoch)
        $("users").replaceChildren(empty(`Users unavailable: ${err.message}`, true));
    }
  }
  function renderUsers() {
    const root = $("users");
    root.replaceChildren();
    if (!state.users.length) root.append(empty("No user accounts reported."));
    for (const user of state.users) {
      const row = node("div", "list-row"), left = node("div"), actions = node("div", "row-actions");
      left.append(node("div", "row-name", value(user.username)), node("div", "row-sub", `${value(user.role)} · ${user.disabled ? "Disabled" : "Active"}`));
      for (const [label, payload] of [[user.role === "admin" ? "Demote" : "Promote", { role: user.role === "admin" ? "tester" : "admin" }], [user.disabled ? "Enable" : "Disable", { disabled: !user.disabled }]]) {
        const button = node("button", "button outline", label);
        button.type = "button";
        button.addEventListener("click", () => updateUser(user, payload, button));
        actions.append(button);
      }
      const reset = node("button", "button outline", "Reset password");
      reset.type = "button";
      reset.addEventListener("click", () => openDialog("reset", user));
      actions.append(reset);
      row.append(left, actions);
      root.append(row);
    }
  }
  async function updateUser(user, payload, button) {
    if (!isAdmin()) return;
    const epoch = state.authEpoch;
    button.disabled = true;
    try {
      await post(`/api/users/${encodeURIComponent(user.id)}/update`, payload);
      if (epoch !== state.authEpoch) return;
      await loadUsers();
      if (epoch === state.authEpoch) notice("Account updated.");
    } catch (err) {
      if (epoch === state.authEpoch) notice(`Account not updated: ${err.message}`, true);
    } finally { button.disabled = false; }
  }
  async function loadGateways() {
    const epoch = state.authEpoch;
    try {
      const gateways = rows(await api("/api/gateways"), "gateways");
      if (epoch !== state.authEpoch) return;
      state.gateways = gateways;
      renderGateways();
    } catch (err) {
      if (state.me && epoch === state.authEpoch)
        $("gateways").replaceChildren(
          empty(`Gateways unavailable: ${err.message}`, true),
        );
    }
  }
  function renderGateways() {
    const root = $("gateways");
    root.replaceChildren();
    if (!state.gateways.length) {
      root.append(empty("No gateways reported."));
      return;
    }
    for (const gateway of state.gateways) {
      const row = node("div", "list-row"),
        label = value(gateway.label || gateway.nickname, "Unnamed gateway"),
        left = node("div");
      left.append(
        node("div", "row-name", label),
        node(
          "div",
          "row-sub",
          gateway.id === "web"
            ? "Portal chat origin · other Hermes channels not connected"
            : "Source status unknown",
        ),
      );
      row.append(left);
      if (isAdmin()) {
        const button = node("button", "text-button", "Rename");
        button.type = "button";
        button.setAttribute("aria-label", `Rename ${label}`);
        button.addEventListener("click", () => openDialog("gateway", gateway));
        row.append(button);
      }
      root.append(row);
    }
  }
  async function loadSessions() {
    const epoch = state.authEpoch;
    try {
      const sessions = rows(await api("/api/sessions"), "sessions");
      if (epoch !== state.authEpoch) return;
      state.sessions = sessions;
      renderSessions();
    } catch (err) {
      if (state.me && epoch === state.authEpoch)
        $("session-list").replaceChildren(
          empty(`Sessions unavailable: ${err.message}`, true),
        );
    }
  }
  function renderSessions() {
    const root = $("session-list");
    root.replaceChildren();
    if (!state.sessions.length) {
      root.append(empty("No sessions yet. Start one in a lab."));
      if (!state.sessionId) renderNoSession();
      return;
    }
    for (const session of state.sessions) {
      const id = session.id ?? session.session_id;
      const button = node(
        "button",
        `session-button${String(id) === String(state.sessionId) ? " active" : ""}`,
      );
      button.type = "button";
      button.append(
        node("strong", "", value(session.title, "Untitled session")),
        node("small", "", session.mode === "full" && isAdmin() ? "Full harness · host/AWS" : "Advisory · no lab command broker"),
        node(
          "small",
          "",
          `${value(state.labs.find((l) => String(l.id) === String(session.lab_id))?.name || session.lab_name, "Lab")} · ${time(session.updatedAt || session.updated_at || session.createdAt || session.created_at)}`,
        ),
      );
      button.addEventListener("click", () => selectSession(id));
      root.append(button);
    }
    if (!state.sessionId) renderNoSession();
  }
  function renderNoSession() {
    document.querySelector(".chat-panel").classList.add("is-empty");
    $("chat-header").textContent = "Select a session";
    $("messages").replaceChildren(
      empty(
        "Choose a Hermes session from the list, or start one from an environment. Admin-created sessions can use host/AWS tools; tester sessions remain advisory.",
      ),
    );
    $("message-form").hidden = true;
    $("grant-login").hidden = true;
    $("run-progress").replaceChildren();
    $("run-progress").hidden = true;
  }
  async function selectSession(id) {
    if (id === null || id === undefined) return;
    state.sessionId = id;
    document.querySelector(".chat-panel").classList.remove("is-empty");
    const ticket = ++state.sessionTicket;
    view("sessions");
    renderSessions();
    $("chat-header").textContent = "Loading session…";
    $("messages").replaceChildren();
    $("message-form").hidden = true;
    $("grant-login").hidden = true;
    try {
      const data = await api(`/api/sessions/${encodeURIComponent(id)}`);
      if (ticket !== state.sessionTicket || !state.me) return;
      const session =
        data.session ||
        state.sessions.find(
          (s) => String(s.id ?? s.session_id) === String(id),
        ) ||
        {};
      $("chat-header").replaceChildren(
        node("span", "", value(session.title, "Untitled session")),
        node(
          "small",
          "",
          value(
            session.lab_name ||
              state.labs.find((l) => String(l.id) === String(session.lab_id))
                ?.name,
            "Lab",
          ),
        ),
      );
      const box = $("messages");
      box.replaceChildren();
      const messages = rows(data, "messages");
      if (!messages.length)
        box.append(empty("No messages yet. Start the conversation below."));
      for (const message of messages) {
        const author = String(
            message.role || message.author || "",
          ).toLowerCase(),
          item = node(
            "div",
            `message${["user", "human"].includes(author) ? " self" : ""}`,
          );
        item.append(
          node(
            "div",
            "message-bubble",
            value(message.text ?? message.content, "No message text"),
          ),
          node(
            "div",
            "message-meta",
            `${value(message.role || message.author, "Agent")} · ${time(message.createdAt || message.created_at)}`,
          ),
        );
        box.append(item);
      }
      $("message-form").hidden = false;
      $("grant-login").hidden = !(isAdmin() && session.mode === "full");
      renderSessionProgress();
      box.scrollTop = box.scrollHeight;
    } catch (err) {
      if (ticket === state.sessionTicket && state.me)
        $("messages").replaceChildren(
          empty(`Could not load session: ${err.message}`, true),
        );
    }
  }
  async function loadRuns() {
    const epoch = state.authEpoch;
    try {
      const fresh = rows(await api("/api/runs"), "runs");
      if (epoch !== state.authEpoch) return;
      if (
        !state.runsLoaded ||
        JSON.stringify(fresh) !== JSON.stringify(state.runs)
      ) {
        state.runs = fresh;
        state.runsLoaded = true;
        renderRuns();
        renderSessionProgress();
      }
    } catch (err) {
      if (state.me && epoch === state.authEpoch) {
        $("agents").replaceChildren(
          empty(`Agent status unavailable: ${err.message}`, true),
        );
        $("agent-preview").replaceChildren(
          empty("Agent status unavailable.", true),
        );
        $("timeline").replaceChildren(
          empty(`Activity unavailable: ${err.message}`, true),
        );
      }
    }
  }
  function runStatus(run) {
    return value(run.status || run.state);
  }
  function renderSessionProgress() {
    const root = $("run-progress");
    root.replaceChildren();
    const run = state.runs.find((item) => item.session_id === state.sessionId && item.user === state.me?.username);
    if (!run) { root.hidden = true; return; }
    root.hidden = false;
    root.append(node("strong", "", `Agent run · ${runStatus(run)}`));
    const steps = node("ol", "run-steps");
    for (const step of run.steps || []) steps.append(node("li", "", value(step.summary, "Step reported")));
    root.append(steps);
    if (run.screenshot) {
      const image = node("img", "run-screenshot");
      image.src = `/api/runs/${encodeURIComponent(run.id)}/screenshot`;
      image.alt = "Screenshot captured during this agent run";
      image.loading = "lazy";
      const link = node("a", "", "Open screenshot at full size");
      link.href = image.src; link.target = "_blank"; link.rel = "noopener noreferrer";
      root.append(image, link);
    }
    if (["running", "queued"].includes(run.status) && !state.pendingRun)
      state.pendingRun = { id: run.id, sessionId: state.sessionId };
  }
  function renderRuns() {
    const agents = $("agents"),
      preview = $("agent-preview"),
      timeline = $("timeline");
    agents.replaceChildren();
    preview.replaceChildren();
    timeline.replaceChildren();
    const active = state.runs.filter((run) =>
      ["running", "queued", "pending", "starting", "in_progress"].includes(
        String(runStatus(run)).toLowerCase(),
      ),
    );
    if (!active.length) {
      agents.append(empty("No currently active agents reported."));
      preview.append(empty("No currently active agents reported."));
    }
    for (const run of active)
      for (const root of [agents, preview]) {
        const row = node("div", "list-row"),
          left = node("div");
        left.append(
          node("div", "row-name", run.execution_mode === "full" ? "Full Hermes run" : "Advisory Hermes run"),
          node(
            "div",
            "row-sub",
            `${value(run.user, "User")} · ${value(run.gateway_label, "Web")} · ${runStatus(run)}`,
          ),
        );
        row.append(left, badge(runStatus(run)));
        root.append(row);
      }
    if (!state.runs.length) {
      timeline.append(empty("No activity reported yet."));
      return;
    }
    for (const run of [...state.runs].sort(
      (a, b) =>
        Date.parse(
          b.updatedAt || b.updated_at || b.createdAt || b.created_at || 0,
        ) -
        Date.parse(
          a.updatedAt || a.updated_at || a.createdAt || a.created_at || 0,
        ),
    )) {
      const item = node("div", "timeline-item"),
        body = node("div"),
        title = node("div", "timeline-title", run.execution_mode === "full" ? "Full Hermes run" : "Advisory Hermes run");
      body.append(
        title,
        node(
          "div",
          "timeline-description",
          `${value(run.user, "User")} · ${value(run.gateway_label, "Web")} · ${runStatus(run)} · ${time(run.updated_at)}`,
        ),
      );

      item.append(node("span", "timeline-dot"), body);
      timeline.append(item);
    }
  }
  async function loadRequests() {
    const epoch = state.authEpoch;
    try {
      const requests = rows(await api("/api/requests"), "requests");
      if (epoch !== state.authEpoch) return;
      state.requests = requests;
      renderRequests();
    } catch (err) {
      if (state.me && epoch === state.authEpoch)
        $("requests").replaceChildren(
          empty(`Requests unavailable: ${err.message}`, true),
        );
    }
  }
  function renderRequests() {
    const root = $("requests");
    root.replaceChildren();
    if (!state.requests.length) {
      root.append(empty("No access requests yet."));
      return;
    }
    for (const request of state.requests) {
      if (!isAdmin() && request.user && request.user !== state.me?.username) continue;
      const row = node("div", "list-row"),
        left = node("div");
      left.append(
        node(
          "div",
          "row-name",
          value(
            request.lab_name ||
              state.labs.find((l) => String(l.id) === String(request.lab_id))
                ?.name,
            "Lab request",
          ) + (request.kind === "environment" ? " · New environment request" : " · Access request"),
        ),
        node(
          "div",
          "row-sub",
          `${isAdmin() ? `${value(request.user, "User")} · ` : ""}${time(request.createdAt || request.created_at)}${request.note ? ` · ${request.note}` : ""}`,
        ),
      );
      if (request.kind === "environment" && request.spec) {
        const spec = request.spec;
        left.append(node("div", "row-sub", `${value(request.proposed_name, "Legacy request: version missing; resubmit")} · ${spec.gateway_count} gateway(s) · ${spec.lab_id === "new" ? "new lab" : "attach " + spec.lab_id}${spec.topology === "database" ? ` · ${spec.os_version} / ${spec.db_engine}` : ""} · version ${value(spec.version || spec.db_version, "not specified")}`));
        if (spec.ttl_hours !== undefined || spec.max_spend_usd !== undefined) {
          left.append(node("div", "row-sub", `Historical request limits: ${value(spec.ttl_hours, "—")}h TTL · USD ${value(spec.max_spend_usd, "—")} maximum spend (not enforced)`));
        }
      }
      row.append(left, badge(value(request.status, "Requested")));
      if (isAdmin() && ["pending", "requested"].includes(String(request.status).toLowerCase())) {
        const actions = node("div", "row-actions");
        for (const [label, decision] of [[request.kind === "environment" ? "Approve for fulfillment" : "Approve", "approved"], ["Deny", "denied"]]) {
          const button = node("button", "button outline", label);
          button.type = "button";
          if (request.kind === "environment" && (!request.proposed_name || request.spec?.topology === "database") && decision === "approved") {
            button.disabled = true;
            button.title = request.spec?.topology === "database" ? "Database deployment is separate and unavailable here." : "Legacy request lacks a version or topology; ask the requester to resubmit.";
          }
          button.addEventListener("click", async () => {
            const epoch = state.authEpoch;
            button.disabled = true;
            try {
              await post(`/api/requests/${encodeURIComponent(request.id)}/decision`, { decision });
              if (epoch !== state.authEpoch) return;
              await loadRequests();
              await loadActivity();
              if (epoch === state.authEpoch) notice(request.kind === "environment" && decision === "approved" ? "Approved for admin fulfillment. No resources launched; start a fulfillment session to review the plan." : `Request ${decision}. No access grant or environment launch was made.`);
            } catch (err) {
              if (epoch === state.authEpoch) notice(`Decision not saved: ${err.message}`, true);
            } finally { button.disabled = false; }
          });
          actions.append(button);
        }
        row.append(actions);
      }
      if (isAdmin() && request.kind === "environment" && request.status === "approved" && request.spec) {
        const owned = state.sessions.some((s) => s.id === request.fulfillment_session);
        const button = node("button", "button primary", request.spec.topology === "database" ? "Database deployment separate" : !request.proposed_name ? "Version required; resubmit" : request.fulfillment_session ? (owned ? "Open fulfillment" : "Fulfillment with another admin") : "Start admin fulfillment");
        button.type = "button";
        button.disabled = request.spec.topology === "database" || !request.proposed_name || Boolean(request.fulfillment_session && !owned);
        button.addEventListener("click", async () => {
          const epoch = state.authEpoch;
          button.disabled = true;
          try {
            const handoff = await post(`/api/requests/${encodeURIComponent(request.id)}/fulfillment`, {});
            if (epoch !== state.authEpoch) return;
            await loadSessions();
            await loadRequests();
            if (epoch !== state.authEpoch) return;
            await selectSession(handoff.session.id);
            if (epoch === state.authEpoch) {
              $("message-text").value = handoff.draft;
              notice("Fulfillment session ready. Review the drafted request before sending. Approval did not launch anything.");
            }
          } catch (err) {
            if (epoch === state.authEpoch) notice(`Fulfillment unavailable: ${err.message}`, true);
          } finally { button.disabled = false; }
        });
        row.append(button);
      }
      root.append(row);
    }
  }
  function openNewSession(labId) {
    openDialog("session", { lab_id: labId });
  }
  function openDialog(kind, subject = {}) {
    state.modal = { kind, subject };
    const title = {
      session: "Start Hermes session",
      request: "Request lab access",
      gateway: "Rename gateway",
      environment: "Request a new environment",
      login: "Grant website login",
      user: "Add a user",
      reset: "Reset password",
    }[kind];
    $("dialog-title").textContent = title;
    $("dialog-description").textContent = {
      session: isAdmin() ? "Full host/AWS tool access. Only start this session for a trusted admin; review any changes it makes." : "Choose a lab for an advisory Hermes conversation. Lab queries need a separate read-only broker.",
      request: "Tell the team which lab you need and why.",
      gateway:
        "A nickname makes this gateway easier for the team to recognize.",
      environment: "Request a standalone MX or MXHA lab. Database deployment is separate and unavailable here. The proposed name uses LabPilot, your account, topology, then product version.",
      login: "Save a login for the exact HTTPS origin the agent needs (include its port). This enters the shared host Hermes vault, available to full-host admins—not just this session. Never paste a password in chat. Confirm the destination before saving.",
      user: "Create a tester account or explicitly choose admin. Passwords must be at least 16 characters.",
      reset: `Set a new password for ${value(subject.username)} (at least 16 characters).`,
    }[kind];
    $("dialog-submit").textContent = {
      session: "Create session",
      request: "Send request",
      gateway: "Save nickname",
      environment: "Submit for approval",
      login: "Save login",
      user: "Create user",
      reset: "Reset password",
    }[kind];
    $("dialog-error").hidden = true;
    const fields = $("dialog-fields");
    fields.replaceChildren();
    const field = (labelText, control) => {
      const label = node("label", "", labelText);
      label.htmlFor = control.id;
      fields.append(label, control);
    };
    if (["session", "request", "environment"].includes(kind)) {
      const select = node("select");
      select.id = "dialog-lab";
      select.name = "lab_id";
      select.required = true;
      const prompt = node("option", "", "Select a lab");
      prompt.value = "";
      select.append(prompt);
      for (const lab of state.labs) {
        const option = node("option", "", value(lab.name, "Unnamed lab"));
        option.value = String(lab.id);
        select.append(option);
      }
      if (kind === "environment") {
        const fresh = node("option", "", "New standalone lab (MX / MXHA only)");
        fresh.value = "new";
        select.append(fresh);
      }
      if (subject.lab_id !== undefined && subject.lab_id !== null)
        select.value = String(subject.lab_id);
      field(kind === "environment" ? "Attach to lab / create new" : "Lab", select);
      if (!state.labs.length && kind !== "environment") {
        const hint = node(
          "p",
          "form-error",
          "No labs are listed. Refresh observations or ask your administrator about lab access.",
        );
        fields.append(hint);
        $("dialog-submit").disabled = true;
      } else $("dialog-submit").disabled = false;
    } else $("dialog-submit").disabled = false;
    if (kind === "environment") {
      const topology = node("select"); topology.id = "dialog-topology"; topology.required = true;
      for (const [id, label] of [["", "Choose a topology"], ["standalone_mx", "Standalone MX"], ["mxha", "MXHA cluster"]]) {
        const option = node("option", "", label); option.value = id; topology.append(option);
      }
      field("Requested topology", topology);
      const version = node("input"); version.id = "dialog-version"; version.required = true;
      version.maxLength = 40; version.placeholder = "e.g. 14.19.1.150";
      field("MX product version", version);
      const gateways = node("input"); gateways.id = "dialog-gateways"; gateways.type = "number";
      gateways.min = "0"; gateways.max = "4"; gateways.step = "1"; gateways.value = "1";
      field("Gateways (0–4)", gateways);
    }
    const control = ["request", "environment"].includes(kind) ? node("textarea") : node("input");
    control.id = "dialog-detail";
    control.required = true;
    control.maxLength =
      ["request", "environment"].includes(kind) ? 500 : kind === "login" ? 200 : kind === "gateway" ? 40 : 100;
    control.name =
      ["request", "environment"].includes(kind) ? "note" : kind === "login" ? "origin" : kind === "gateway" ? "label" : kind === "user" ? "username" : kind === "reset" ? "password" : "title";
    if (kind === "reset") { control.type = "password"; control.minLength = 16; control.autocomplete = "new-password"; }
    if (kind === "login") { control.type = "url"; control.autocomplete = "off"; }
    if (kind === "gateway")
      control.value = subject.label || subject.nickname || "";
    control.placeholder = {
      session: "e.g. Explore gateway policy",
      request: "What do you need this lab for?",
      gateway: "e.g. East test gateway",
      environment: "What should this environment be used for?",
      user: "Username",
      reset: "New password",
      login: "https://lab-host:8083 (no path)",
    }[kind];
    field(
      {
        session: "Session title",
        request: "Reason for access",
        gateway: "Gateway nickname",
        environment: "Reason for environment",
        user: "Username",
        reset: "New password",
        login: "Exact HTTPS origin",
      }[kind],
      control,
    );
    if (kind === "login") {
      const identifier = node("input"); identifier.id = "dialog-identifier"; identifier.maxLength = 100; identifier.required = true; identifier.autocomplete = "off";
      field("Login identifier", identifier);
      const password = node("input"); password.id = "dialog-password"; password.type = "password"; password.required = true; password.autocomplete = "new-password";
      field("Website password (stored in host vault)", password);
    }
    if (kind === "user") {
      const password = node("input");
      password.id = "dialog-password";
      password.type = "password";
      password.name = "password";
      password.autocomplete = "new-password";
      password.minLength = 16;
      password.required = true;
      field("Password (16 characters minimum)", password);
      const role = node("select");
      role.id = "dialog-role";
      for (const name of ["tester", "admin"]) {
        const option = node("option", "", name === "tester" ? "Tester (default)" : "Admin");
        option.value = name;
        role.append(option);
      }
      field("Role", role);
    }
    $("form-dialog").showModal();
    (["session", "request", "environment"].includes(kind) ? $("dialog-lab") : control).focus();
  }
  async function submitDialog(event) {
    event.preventDefault();
    const { kind, subject } = state.modal || {};
    if (!kind) return;
    const epoch = state.authEpoch;
    const detail = kind === "reset" ? $("dialog-detail").value : $("dialog-detail").value.trim(),
      lab_id = $("dialog-lab")?.value;
    if (!detail || (["session", "request", "environment"].includes(kind) && !lab_id)) {
      $("dialog-error").textContent = "Complete all fields before continuing.";
      $("dialog-error").hidden = false;
      return;
    }
    if (["user", "reset", "login"].includes(kind) && !isAdmin()) return;
    if (["user", "reset"].includes(kind) && (kind === "user" ? $("dialog-password").value : detail).length < 16) {
      $("dialog-error").textContent = "Password must have at least 16 characters.";
      $("dialog-error").hidden = false;
      return;
    }
    const submit = $("dialog-submit");
    submit.disabled = true;
    try {
      if (kind === "login") {
        const identifier = $("dialog-identifier").value.trim();
        const password = $("dialog-password").value;
        if (!identifier || !password || !state.sessionId || subject.sessionId !== state.sessionId)
          throw new Error("Select a full admin session and complete the login fields.");
        const saved = post(`/api/sessions/${encodeURIComponent(subject.sessionId)}/login`, { origin: detail, identifier, password });
        $("dialog-password").value = "";
        await saved;
        if (epoch !== state.authEpoch) return;
        notice("Login saved to the shared host vault. Tell the agent to continue in this session; do not paste credentials in chat.");
      }
      if (kind === "gateway") {
        await post("/api/gateway-labels", {
          gateway_id: subject.id ?? subject.gateway_id,
          label: detail,
        });
        await loadGateways();
        if (epoch !== state.authEpoch) return;
        notice("Gateway nickname saved.");
      }
      if (kind === "request") {
        await post("/api/requests", { lab_id, note: detail });
        await loadRequests();
        if (epoch !== state.authEpoch) return;
        view("access");
        notice("Access request submitted for review. Approval does not provision access in this pilot.");
      }
      if (kind === "environment") {
        const topology = $("dialog-topology").value;
        const gateway_count = Number($("dialog-gateways").value);
        const version = $("dialog-version").value.trim();
        if (!["standalone_mx", "mxha"].includes(topology) || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,39}$/.test(version) ||
            !Number.isInteger(gateway_count) || gateway_count < 0 || gateway_count > 4) {
          throw new Error("Choose a valid topology, attachment and version.");
        }
        const created = await post("/api/environments/requests", { lab_id, topology, gateway_count, version, purpose: detail });
        if (epoch !== state.authEpoch) return;
        await loadRequests();
        await loadActivity();
        if (epoch !== state.authEpoch) return;
        view("access");
        notice(`${value(created.proposed_name, "Environment")} requested. Approval unlocks an admin fulfillment session; it does not launch resources.`);
      }
      if (kind === "user") {
        await post("/api/users", { username: detail, password: $("dialog-password").value, role: $("dialog-role").value });
        if (epoch !== state.authEpoch) return;
        await loadUsers();
        if (epoch === state.authEpoch) notice("User created.");
      }
      if (kind === "reset") {
        await post(`/api/users/${encodeURIComponent(subject.id)}/update`, { password: detail });
        if (epoch !== state.authEpoch) return;
        await loadUsers();
        if (epoch === state.authEpoch) notice("Password reset.");
      }
      if (kind === "session") {
        const data = await post("/api/sessions", { lab_id, title: detail });
        await loadSessions();
        if (epoch !== state.authEpoch) return;
        const id =
          data.session?.id ??
          data.session_id ??
          data.id ??
          state.sessions.find(
            (s) => s.title === detail && String(s.lab_id) === String(lab_id),
          )?.id;
        if (id !== undefined) await selectSession(id);
        else {
          view("sessions");
          notice("Session created. Select it from your sessions.");
        }
      }
      if (epoch !== state.authEpoch) return;
      $("form-dialog").close();
      $("dialog-fields").replaceChildren();
      state.modal = null;
    } catch (err) {
      if (epoch === state.authEpoch) {
        $("dialog-error").textContent = err.message;
        $("dialog-error").hidden = false;
      }
    } finally {
      if (kind === "login" && $("dialog-password")) $("dialog-password").value = "";
      if (epoch === state.authEpoch) submit.disabled = false;
    }
  }
  $("login-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const epoch = ++state.authEpoch;
    const submit = $("login-form").querySelector("button[type=submit]");
    submit.disabled = true;
    $("login-error").hidden = true;
    try {
      const body = await post("/api/login", {
        username: $("username").value.trim(),
        password: $("password").value,
      });
      if (epoch !== state.authEpoch) return;
      captureCsrf(body);
      const me = await api("/api/me");
      if (epoch !== state.authEpoch) return;
      captureCsrf(me);
      await signedIn(me);
    } catch (err) {
      if (epoch === state.authEpoch) {
        $("login-error").textContent = err.message;
        $("login-error").hidden = false;
      }
    } finally {
      submit.disabled = false;
      $("password").value = "";
    }
  });
  $("logout").addEventListener("click", async () => {
    try {
      await post("/api/logout", {});
      showLogin();
    } catch (err) {
      notice(`Sign out failed: ${err.message}`, true);
    }
  });
  $("nav").addEventListener("click", (event) => {
    const button = event.target.closest("[data-view]");
    if (button) view(button.dataset.view);
  });
  document
    .querySelectorAll(".text-button[data-view]")
    .forEach((button) =>
      button.addEventListener("click", () => view(button.dataset.view)),
    );
  $("refresh").addEventListener("click", () =>
    Promise.all([loadLabs(), loadGateways(), loadRuns()]),
  );
  $("refresh-runs").addEventListener("click", () => Promise.all([loadRuns(), loadActivity()]));
  $("activity-filters").addEventListener("submit", (event) => {
    event.preventDefault();
    loadActivity();
  });

  $("create-user").addEventListener("click", () => { if (isAdmin()) openDialog("user"); });
  $("new-environment").addEventListener("click", () => openDialog("environment"));
  $("new-session").addEventListener("click", () => openDialog("session"));
  $("grant-login").addEventListener("click", () => { if (isAdmin() && state.sessionId) openDialog("login", { sessionId: state.sessionId }); });
  $("request-access").addEventListener("click", () => openDialog("request"));
  $("request-from-overview").addEventListener("click", () =>
    openDialog("request"),
  );
  const clearDialog = () => {
    const password = $("dialog-password"); if (password) password.value = "";
    const detail = $("dialog-detail"); if (detail) detail.value = "";
    $("dialog-fields").replaceChildren();
    state.modal = null;
  };
  $("close-dialog").addEventListener("click", () => { clearDialog(); $("form-dialog").close(); });
  $("cancel-dialog").addEventListener("click", () => { clearDialog(); $("form-dialog").close(); });
  $("form-dialog").addEventListener("close", () => {
    clearDialog();
  });
  $("dialog-form").addEventListener("submit", submitDialog);
  $("message-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const text = $("message-text").value.trim();
    if (!text || state.sessionId === null) return;
    const id = state.sessionId,
      epoch = state.authEpoch,
      button = $("message-form").querySelector("button");
    button.disabled = true;
    try {
      const data = await post(
        `/api/sessions/${encodeURIComponent(id)}/messages`,
        { text },
      );
      if (epoch !== state.authEpoch) return;
      $("message-text").value = "";
      await selectSession(id);
      await loadRuns();
      if (epoch !== state.authEpoch) return;
      if (data.run_id) {
        state.pendingRun = { id: data.run_id, sessionId: id };
        notice(
          "Agent started. The answer will appear here when the run finishes.",
        );
      } else notice("Message sent. Refresh this session for updates.");
    } catch (err) {
      if (epoch === state.authEpoch)
        notice(`Message not sent: ${err.message}`, true);
    } finally {
      button.disabled = false;
    }
  });
  setInterval(async () => {
    if (!state.me || document.hidden) return;
    const epoch = state.authEpoch;
    await loadRuns();
    if (epoch !== state.authEpoch || !state.pendingRun) return;
    const active = state.runs.find((r) => r.id === state.pendingRun.id);
    if (active && ["completed", "failed"].includes(active.status)) {
      const sid = state.pendingRun.sessionId;
      state.pendingRun = null;
      if (state.sessionId === sid) await selectSession(sid);
    }
  }, 2000);
  const bootEpoch = state.authEpoch;
  api("/api/me")
    .then((body) => {
      if (bootEpoch === state.authEpoch) signedIn(body);
    })
    .catch(() => {
      if (bootEpoch === state.authEpoch) showLogin();
    });
})();
