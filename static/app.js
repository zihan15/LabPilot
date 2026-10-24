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
    proposals: [],
    files: [],
    proposalTicket: 0,
    drafting: false,
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
    state.proposals = [];
    state.files = [];
    state.proposalTicket++;
    state.drafting = false;
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
      "skill-proposals",
      "proposal-preview",
      "proposal-review",
      "files",
      "users",
      "activity-events",
      "chat-header",
    ])
      $(id).replaceChildren();
    $("lab-summary").textContent = "Loading observations…";
    $("observation-stamp").textContent = "Waiting for AWS observation";
    $("message-form").hidden = true;
    $("grant-login").hidden = true;
    $("suggest-session-skill").hidden = true;
    $("suggest-session-skill").disabled = false;
    document.querySelector(".chat-panel").classList.add("is-empty");
    $("notice").hidden = true;
    $("notice").textContent = "";
    $("users-nav").hidden = true;
    $("files-nav").hidden = true;
    $("sessions-nav").hidden = true;
    $("proposal-form-section").hidden = true;
    $("file-input").value = "";
    $("file-form").querySelector('button[type="submit"]').disabled = false;
    $("file-error").textContent = "";
    $("file-error").hidden = true;
    $("proposal-review-section").hidden = true;
    $("proposal-review").hidden = true;
    $("proposal-session").value = "";
    $("proposal-session").replaceChildren();
    $("proposal-form").querySelector('button[type="submit"]').disabled = false;
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
    $("files-nav").hidden = !isAdmin();
    $("sessions-nav").hidden = !isAdmin();
    $("proposal-form-section").hidden = !isAdmin();
    $("proposal-description").textContent = isAdmin()
      ? "Admins can generate a draft from their own Hermes sessions, preview it privately, then submit it for human review. No skill is installed automatically."
      : "Review the status of earlier proposals. New Hermes sessions and skill drafts are admin-only.";
    $("filter-user-label").hidden = !isAdmin();
    view("overview");
    await Promise.all([
      loadLabs(),
      loadGateways(),
      ...(isAdmin() ? [loadSessions(), loadRuns()] : []),
      loadRequests(),
      loadProposals(),
      loadActivity(),
      ...(isAdmin() ? [loadUsers(), loadFiles()] : []),
    ]);
  }
  function view(name) {
    if (!state.me || (["users", "files", "sessions"].includes(name) && !isAdmin())) return;
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
      "skill-proposals": "Skill proposals",
      files: "Files",
      users: "Users",
    }[name];
    $("main").focus({ preventScroll: true });
  }
  async function loadProposals() {
    const epoch = state.authEpoch, ticket = ++state.proposalTicket;
    try {
      const proposals = rows(await api("/api/skill-proposals"), "proposals");
      if (epoch !== state.authEpoch || ticket !== state.proposalTicket) return;
      state.proposals = proposals.filter((p) => p.user === state.me.username || isAdmin() && !["draft", "discarded"].includes(p.status));
      renderProposals();
    } catch (err) {
      if (state.me && epoch === state.authEpoch && ticket === state.proposalTicket)
        $("skill-proposals").replaceChildren(empty(`Proposals unavailable: ${err.message}`, true));
    }
  }
  function renderProposals() {
    const history = $("skill-proposals"), review = $("proposal-review"), preview = $("proposal-preview");
    history.replaceChildren();
    review.replaceChildren();
    preview.replaceChildren();
    $("proposal-review-section").hidden = !isAdmin();
    review.hidden = !isAdmin();
    if (!state.proposals.some((p) => p.status !== "draft")) history.append(empty("No proposals yet."));
    const drafts = state.proposals.filter((p) => p.status === "draft" && p.user === state.me.username);
    if (drafts.length) preview.append(node("h3", "proposal-preview-heading", "Your private drafts"));
    for (const proposal of state.proposals) {
      const isDraft = proposal.status === "draft";
      const row = node("article", "proposal-row");
      const heading = node("div", "proposal-heading");
      heading.append(node("strong", "", value(proposal.title)), badge(proposal.status));
      row.append(heading, node("p", "proposal-meta", `${value(proposal.user)} · ${time(proposal.created_at)}${proposal.session_id ? " · Session attached" : ""}`),
        node("p", "proposal-copy", value(proposal.guidance, "No proposed guidance")),
        node("p", "proposal-meta", "Evidence"), node("p", "proposal-copy", value(proposal.evidence, "Not supplied")));
      if (proposal.review_note) row.append(node("p", "proposal-copy", `Review note: ${proposal.review_note}`));
      if (proposal.approved_text) row.append(node("p", "proposal-copy", `Approved guidance: ${proposal.approved_text}`));
      if (proposal.reviewed_by) row.append(node("p", "proposal-meta", `Reviewed by ${proposal.reviewed_by}`));
      if (proposal.artifact) row.append(node("p", "proposal-meta", `Artifact: ${proposal.artifact}`));
      (isDraft ? preview : history).append(row);
      if (isDraft) {
        row.append(node("p", "proposal-meta", "Private preview · only submit when the generated guidance and evidence are safe to share for review."));
        const actions = node("div", "row-actions");
        for (const [action, label, style] of (isAdmin() ? [["submit", "Submit for review", "primary"], ["discard", "Discard draft", "outline"]] : [["discard", "Discard draft", "outline"]])) {
          const button = node("button", `button ${style}`, label);
          button.type = "button";
          button.addEventListener("click", async () => {
            if (!state.me || proposal.user !== state.me.username) return;
            const epoch = state.authEpoch;
            for (const control of actions.children) control.disabled = true;
            try {
              const result = await post(`/api/skill-proposals/${encodeURIComponent(proposal.id)}/${action}`, {});
              if (epoch !== state.authEpoch) return;
              state.proposalTicket++;
              if (action === "discard") state.proposals = state.proposals.filter((p) => p.id !== proposal.id);
              else proposal.status = result.status;
              renderProposals();
              notice(action === "submit" ? "Proposal submitted for human review. No skill was automatically added." : "Draft discarded.");
            } catch (err) {
              if (epoch === state.authEpoch) notice(`Draft not ${action === "submit" ? "submitted" : "discarded"}: ${err.message}`, true);
            } finally {
              if (epoch === state.authEpoch) for (const control of actions.children) control.disabled = false;
            }
          });
          actions.append(button);
        }
        row.append(actions);
        continue;
      }
      if (isAdmin() && proposal.status === "approving" && proposal.user !== state.me.username) {
        const retry = node("button", "button outline", "Retry publication");
        retry.type = "button";
        retry.addEventListener("click", async () => {
          const epoch = state.authEpoch;
          retry.disabled = true;
          try {
            await post(`/api/skill-proposals/${encodeURIComponent(proposal.id)}/decision`, {
              decision: "approved", approved_text: proposal.approved_text, review_note: proposal.review_note,
            });
            if (epoch === state.authEpoch) { notice("Reviewed skill published."); await loadProposals(); }
          } catch (err) {
            if (epoch === state.authEpoch) notice(`Publication incomplete: ${err.message}`, true);
          } finally {
            if (epoch === state.authEpoch) retry.disabled = false;
          }
        });
        row.append(node("p", "proposal-meta", "Approval recorded; publication incomplete. Retry after repairing the host skill."), retry);
      }
      if (!isAdmin() || proposal.status !== "pending" || proposal.user === state.me.username) continue;
      const card = node("article", "proposal-row");
      card.append(node("strong", "", `${value(proposal.title)} · ${value(proposal.user)}`),
        node("p", "proposal-copy", `Suggested: ${value(proposal.guidance)}`),
        node("p", "proposal-copy", value(proposal.evidence, "Evidence not supplied")));
      const guidance = node("textarea", "");
      guidance.id = `approved-${proposal.id}`;
      guidance.rows = 4;
      guidance.maxLength = 3000;
      guidance.minLength = 80;
      guidance.setAttribute("aria-label", `Reviewed guidance for ${proposal.title}`);
      guidance.placeholder = "Review the concrete workflow; edit it for the lab scope. Verify product or version claims before approving.";
      const useSuggestion = node("button", "button outline", "Use suggested wording");
      useSuggestion.type = "button";
      useSuggestion.addEventListener("click", () => { guidance.value = value(proposal.guidance).slice(0, 3000); guidance.focus?.(); });
      const note = node("input", "");
      note.id = `review-note-${proposal.id}`;
      note.maxLength = 1000;
      note.minLength = 10;
      note.setAttribute("aria-label", `Review note for ${proposal.title}`);
      note.placeholder = "What was reviewed, or reason for rejection";
      card.append(guidance, useSuggestion, note);
      const actions = node("div", "row-actions");
      for (const decision of ["approved", "rejected"]) {
        const button = node("button", `button ${decision === "approved" ? "primary" : "outline"}`, decision === "approved" ? "Approve & add to skill" : "Reject");
        button.type = "button";
        button.addEventListener("click", async () => {
          if (!isAdmin()) return;
          const approved_text = guidance.value.trim(), review_note = note.value.trim();
          if (decision === "approved" && !approved_text) { notice("Write evidence-backed approved guidance before approving.", true); return; }
          const epoch = state.authEpoch;
          for (const control of actions.children) control.disabled = true;
          try {
            await post(`/api/skill-proposals/${encodeURIComponent(proposal.id)}/decision`, { decision, approved_text: decision === "approved" ? approved_text : "", review_note });
            if (epoch !== state.authEpoch) return;
            notice(`Proposal ${decision}.`);
            await loadProposals();
          } catch (err) {
            if (epoch === state.authEpoch) notice(`Decision not saved: ${err.message}`, true);
          } finally {
            if (epoch === state.authEpoch) for (const control of actions.children) control.disabled = false;
          }
        });
        actions.append(button);
      }
      card.append(actions);
      review.append(card);
    }
    if (isAdmin() && !review.children.length) review.append(empty("No proposals pending review."));
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
      const footer = node("div", "lab-footer");
      footer.append(observed);
      if (isAdmin()) {
        const button = node("button", "button primary hermes-session-cta", "Start Hermes session");
        button.type = "button";
        button.addEventListener("click", () => openNewSession(lab.id));
        footer.append(button);
      }
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
      if (["hermes", "advisory"].includes(event.kind)) {
        const attempts = Number(event.tool_attempts) || 0, errors = Number(event.tool_errors) || 0;
        card.append(node("p", "event-highlights", `${attempts} tool attempt${attempts === 1 ? "" : "s"} in retained trail · ${errors} reported tool error${errors === 1 ? "" : "s"} in retained trail${event.status === "failed" ? " · Run failed; verify any side effects" : ""}`));
        if (event.user === state.me?.username && event.session_id && Array.isArray(event.steps)) {
          const detail = node("details", "event-trail"), trail = node("ol", "event-checks");
          detail.append(node("summary", "", `Recorded agent actions (${event.steps.length})`));
          for (const step of event.steps) trail.append(node("li", "", `${time(step.at)} · ${value(step.summary, "Step reported")}`));
          detail.append(trail, node("p", "muted", "Recorded tool names and allowlisted commands only; no raw tool output. Attempts and returns do not prove changes succeeded."));
          card.append(detail);
          const open = node("button", "button outline", "Open session");
          open.type = "button";
          open.addEventListener("click", () => selectSession(event.session_id));
          card.append(open);
        } else card.append(node("p", "muted", "Agent action trail is private to its run owner."));
      }
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
      if (user.username !== state.me.username) {
        const remove = node("button", "button outline", "Delete");
        remove.type = "button";
        remove.addEventListener("click", () => deleteUser(user, remove));
        actions.append(remove);
      }
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
  async function deleteUser(user, button) {
    if (!isAdmin() || user.username === state.me.username) return;
    if (!window.confirm(`Permanently delete ${user.username} and their portal chats, runs, requests, screenshots, proposals and uploaded files? This cannot be undone. Shared Hermes CLI history, vault entries, approved skills and backups remain outside the portal.`)) return;
    const epoch = state.authEpoch;
    button.disabled = true;
    try {
      const result = await api(`/api/users/${encodeURIComponent(user.id)}/delete`, { method: "POST" });
      if (epoch !== state.authEpoch) return;
      await Promise.all([loadUsers(), loadRuns(), loadActivity(), loadRequests(), loadProposals(), loadFiles()]);
      if (epoch === state.authEpoch) notice(result.cleanup_complete ? "Portal account and data deleted." : "Account deleted, but some private artifacts need operator cleanup.", !result.cleanup_complete);
    } catch (err) {
      if (epoch === state.authEpoch) notice(`Account not deleted: ${err.message}`, true);
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
    if (!isAdmin()) return;
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
    const selected = $("proposal-session").value;
    const selector = $("proposal-session");
    selector.replaceChildren();
    const none = node("option", "", "Choose a session");
    none.value = "";
    selector.append(none);
    for (const session of state.sessions.filter((s) => s.mode === "full")) {
      const option = node("option", "", value(session.title, "Untitled session"));
      option.value = session.id ?? session.session_id;
      selector.append(option);
    }
    selector.value = state.sessions.some((s) => s.mode === "full" && String(s.id ?? s.session_id) === selected) ? selected : "";
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
        node("small", "", session.mode === "full" ? "Full harness · host/AWS · commands auto-approved" : "Historical advisory session"),
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
        "Choose a private Hermes session from the list, or start one from an environment. Admin sessions can use host/AWS tools.",
      ),
    );
    $("message-form").hidden = true;
    $("grant-login").hidden = true;
    $("suggest-session-skill").hidden = true;
    $("run-progress").replaceChildren();
    $("run-progress").hidden = true;
  }
  async function selectSession(id) {
    if (!isAdmin() || id === null || id === undefined) return;
    state.sessionId = id;
    document.querySelector(".chat-panel").classList.remove("is-empty");
    const ticket = ++state.sessionTicket;
    view("sessions");
    renderSessions();
    $("chat-header").textContent = "Loading session…";
    $("messages").replaceChildren();
    $("message-form").hidden = true;
    $("grant-login").hidden = true;
    $("suggest-session-skill").hidden = true;
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
      $("suggest-session-skill").hidden = session.mode !== "full";
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
      $("message-form").hidden = session.mode !== "full";
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
    if (!isAdmin()) return;
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
        left.append(node("div", "row-sub", `${value(request.proposed_name, "Legacy request: version missing; resubmit")} · ${spec.gateway_count} gateway(s) · ${spec.lab_id === "new" ? "new lab" : "attach " + spec.lab_id}${spec.topology === "database" ? ` · ${value(spec.db_engine)} · OS ${value(spec.os_version, "undecided")}` : ""} · version ${value(spec.version || spec.db_version, "undecided")}`));
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
          if (request.kind === "environment" && !request.proposed_name && decision === "approved") {
            button.disabled = true;
            button.title = "Legacy request lacks a version or topology; ask the requester to resubmit.";
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
        const button = node("button", "button primary", !request.proposed_name ? "Version required; resubmit" : request.fulfillment_session ? (owned ? "Open fulfillment" : "Fulfillment with another admin") : "Start admin fulfillment");
        button.type = "button";
        button.disabled = !request.proposed_name || Boolean(request.fulfillment_session && !owned);
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
              notice(request.spec?.topology === "standalone_mx" ? "Review before sending: sending the standalone MX handoff authorizes billable cloud changes. Ticket approval alone launched nothing." : "Fulfillment session ready. Review the drafted request before sending. Approval did not launch anything.");
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
  async function loadFiles() {
    if (!isAdmin()) return;
    const epoch = state.authEpoch;
    try {
      const files = rows(await api("/api/files"), "files");
      if (epoch !== state.authEpoch || !isAdmin()) return;
      state.files = files;
      renderFiles();
    } catch (err) {
      if (epoch === state.authEpoch && isAdmin()) $("files").replaceChildren(empty(`Files unavailable: ${err.message}`, true));
    }
  }
  function renderFiles() {
    const root = $("files"); root.replaceChildren();
    if (!state.files.length) { root.append(empty("No files uploaded yet.")); return; }
    for (const file of state.files) {
      if (!/^[0-9a-f-]{36}$/.test(file.id)) continue;
      const row = node("div", "list-row file-row"), details = node("div");
      details.append(node("div", "row-name", file.name), node("div", "row-sub", `${value(file.user)} · ${file.size} bytes · ${time(file.created_at)}`), node("div", "row-sub", `SHA-256: ${value(file.sha256)}`));
      const download = node("a", "button outline", "Download");
      download.href = `/api/files/${encodeURIComponent(file.id)}/download`;
      row.append(details, download); root.append(row);
    }
  }
  function openNewSession(labId) {
    if (!isAdmin()) return;
    openDialog("session", { lab_id: labId });
  }
  function openDialog(kind, subject = {}) {
    if (kind === "session" && !isAdmin()) return;
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
      session: "Full host/AWS tool access. Only start this session for a trusted admin; review any changes it makes.",
      request: "Tell the team which lab you need and why.",
      gateway:
        "A nickname makes this gateway easier for the team to recognize.",
      environment: "Request a standalone MX, MXHA, or database lab for human review. Database requests are manual handoffs only: no deployment, AWS permissions, or public access is created. Check versions against vendor documentation; never enter credentials here.",
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
      return label;
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
        const fresh = node("option", "", "New lab (manual admin review)");
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
      for (const [id, label] of [["", "Choose a topology"], ["standalone_mx", "Standalone MX"], ["mxha", "MXHA cluster"], ["database", "Database (manual review)"]]) {
        const option = node("option", "", label); option.value = id; topology.append(option);
      }
      field("Requested topology", topology);
      const version = node("input"); version.id = "dialog-version"; version.required = true;
      version.maxLength = 40; version.placeholder = "e.g. 14.19.1.150";
      const versionLabel = field("MX product version", version);
      const gateways = node("input"); gateways.id = "dialog-gateways"; gateways.type = "number";
      gateways.min = "0"; gateways.max = "4"; gateways.step = "1"; gateways.value = "1";
      const gatewayLabel = field("Gateways (0–4)", gateways);
      const dbFields = node("div", "db-fields"); dbFields.id = "dialog-db-fields"; dbFields.hidden = true;
      const dbField = (labelText, id, placeholder) => {
        const label = node("label", "", labelText), input = node("input");
        input.id = id; input.maxLength = 60; input.placeholder = placeholder;
        label.htmlFor = id; dbFields.append(label, input);
        return input;
      };
      const engineLabel = node("label", "", "Database engine (required)"), engine = node("select");
      engine.id = "dialog-db-engine"; engineLabel.htmlFor = engine.id;
      for (const [id, label] of [["", "Choose an engine"], ["mysql", "MySQL"], ["postgresql", "PostgreSQL"], ["oracle", "Oracle"], ["sql-server", "SQL Server"], ["mariadb", "MariaDB"]]) {
        const option = node("option", "", label); option.value = id; engine.append(option);
      }
      dbFields.append(engineLabel, engine);
      dbField("Database version (optional)", "dialog-db-version", "Leave blank if undecided");
      dbField("OS version (optional)", "dialog-os-version", "Leave blank if undecided");
      const adviceButton = node("button", "button outline", "Get optional agent advice");
      adviceButton.id = "dialog-db-advice-button"; adviceButton.type = "button";
      const advice = node("p", "muted"); advice.id = "dialog-db-advice"; advice.setAttribute("role", "status");
      dbFields.append(adviceButton, advice); fields.append(dbFields);
      let adviceSequence = 0;
      const selection = () => ({ db_engine: engine.value.trim(), db_version: $("dialog-db-version").value.trim(), os_version: $("dialog-os-version").value.trim() });
      const invalidateAdvice = () => { adviceSequence += 1; advice.textContent = ""; };
      [engine, $("dialog-db-version"), $("dialog-os-version")].forEach((field) => {
        field.addEventListener("input", invalidateAdvice);
        field.addEventListener("change", invalidateAdvice);
      });
      topology.addEventListener("change", () => {
        const database = topology.value === "database";
        dbFields.hidden = !database; engine.required = database;
        version.required = !database; version.disabled = database;
        gateways.disabled = database;
        version.hidden = versionLabel.hidden = database;
        gateways.hidden = gatewayLabel.hidden = database;
        invalidateAdvice();
      });
      adviceButton.addEventListener("click", async () => {
        if (!engine.value.trim()) { advice.textContent = "Enter a database engine before requesting advice."; return; }
        const epoch = state.authEpoch, modal = state.modal;
        const choice = selection(), sequence = ++adviceSequence;
        const current = () => epoch === state.authEpoch && modal === state.modal &&
          sequence === adviceSequence && JSON.stringify(selection()) === JSON.stringify(choice);
        adviceButton.disabled = true; advice.textContent = "Getting advisory guidance…";
        try {
          const result = await post("/api/db-advice", choice);
          if (current()) advice.textContent = `Advisory only (${value(result.status)}): ${value(result.advice, "No recommendation available")} Verify compatibility and availability before requesting deployment.`;
        } catch (err) {
          if (current()) advice.textContent = `Advice unavailable: ${err.message}`;
        } finally { if (epoch === state.authEpoch && modal === state.modal) adviceButton.disabled = false; }
      });
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
        const database = topology === "database";
        const gateway_count = database ? 0 : Number($("dialog-gateways").value);
        const version = $("dialog-version").value.trim();
        const db_engine = $("dialog-db-engine").value.trim(), db_version = $("dialog-db-version").value.trim(), os_version = $("dialog-os-version").value.trim();
        if (!["standalone_mx", "mxha", "database"].includes(topology) || database && !["mysql", "postgresql", "oracle", "sql-server", "mariadb"].includes(db_engine) || !database && !/^[A-Za-z0-9][A-Za-z0-9._-]{0,39}$/.test(version) ||
            database && [db_version, os_version].some((v) => v && !/^[A-Za-z0-9][A-Za-z0-9 ._()+-]{0,59}$/.test(v)) ||
            !Number.isInteger(gateway_count) || gateway_count < 0 || gateway_count > 4) {
          throw new Error(database ? "Choose a valid database engine and optional versions." : "Choose a valid topology, attachment and version.");
        }
        const created = await post("/api/environments/requests", database ? { lab_id, topology, gateway_count, db_engine, db_version, os_version, purpose: detail } : { lab_id, topology, gateway_count, version, purpose: detail });
        if (epoch !== state.authEpoch) return;
        await loadRequests();
        await loadActivity();
        if (epoch !== state.authEpoch) return;
        view("access");
        notice(database ? "Database request recorded for human review and manual handoff. No automatic deployment or access grant was made." : `${value(created.proposed_name, "Environment")} requested. Approval unlocks an admin fulfillment session; it does not launch resources.`);
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
  $("refresh-proposals").addEventListener("click", loadProposals);
  $("refresh-files").addEventListener("click", loadFiles);
  $("file-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!isAdmin()) return;
    const file = $("file-input").files?.[0], error = $("file-error");
    error.hidden = true;
    if (!file || !file.size || file.size > 256 * 1024 * 1024) {
      error.textContent = "Select a non-empty file no larger than 256 MiB."; error.hidden = false; return;
    }
    if (!/^[A-Za-z0-9][A-Za-z0-9._() -]{0,119}$/.test(file.name) || file.name.includes("..") || /\.(pem|key|p12|pfx|env)$/i.test(file.name)) {
      error.textContent = "Choose a simple filename, not a credential or secret file."; error.hidden = false; return;
    }
    const epoch = state.authEpoch, submit = $("file-form").querySelector('button[type="submit"]');
    submit.disabled = true;
    try {
      await api("/api/files", { method: "POST", body: file, headers: { "Content-Type": "application/octet-stream", "X-File-Name": encodeURIComponent(file.name) } });
      if (epoch !== state.authEpoch) return;
      $("file-input").value = "";
      await loadFiles();
      if (epoch === state.authEpoch) notice("File uploaded for admin download. It was not scanned or executed.");
    } catch (err) {
      if (epoch === state.authEpoch) { error.textContent = `Upload failed: ${err.message}`; error.hidden = false; }
    } finally { if (epoch === state.authEpoch) submit.disabled = false; }
  });
  async function generateSkillDraft(id) {
    if (!isAdmin() || state.drafting || !state.sessions.some((s) => s.mode === "full" && String(s.id ?? s.session_id) === String(id))) {
      if (isAdmin() && !state.drafting) notice("Choose one of your listed sessions.", true);
      return;
    }
    const epoch = state.authEpoch, submit = $("proposal-form").querySelector('button[type="submit"]');
    state.drafting = true;
    submit.disabled = true;
    $("suggest-session-skill").disabled = true;
    try {
      const { proposal } = await post(`/api/sessions/${encodeURIComponent(id)}/skill-draft`, {});
      if (epoch !== state.authEpoch) return;
      if (!proposal?.id || proposal.status !== "draft" || String(proposal.session_id) !== String(id) || proposal.user && proposal.user !== state.me.username) throw new Error("Invalid draft response");
      state.proposalTicket++;
      state.proposals = [{ ...proposal, user: state.me.username }, ...state.proposals.filter((p) => p.id !== proposal.id)];
      $("proposal-session").value = String(id);
      renderProposals();
      view("skill-proposals");
      notice("Private draft ready. Review it before submitting for human review.");
    } catch (err) {
      if (epoch === state.authEpoch) notice(`Draft not generated: ${err.message}`, true);
    } finally {
      if (epoch === state.authEpoch) {
        state.drafting = false;
        submit.disabled = false;
        $("suggest-session-skill").disabled = false;
      }
    }
  }
  $("suggest-session-skill").addEventListener("click", () => generateSkillDraft(state.sessionId));
  $("proposal-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    await generateSkillDraft($("proposal-session").value);
  });
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
