# LabPilot portal user guide

This guide is for a **trusted private pilot**, reached through an authenticated SSH tunnel. It describes the portal in this repository, not the older LabPilot workbench. Ask your operator for an account and the approved tunnel procedure; do not share passwords, private hostnames or cloud identifiers in tickets or chat. See [README.md](README.md) to start locally and [DEPLOYMENT.md](DEPLOYMENT.md) before moving hosts.

## 1. Sign in and orient yourself

1. Open the tunneled `http://127.0.0.1:8090`, enter your portal username and password, then **Sign in**. New accounts default to **tester**; a trusted operator must explicitly assign **admin**. Passwords are at least 16 characters. A session expires after 12 hours; sign in again if prompted.
2. Use **Lab inventory**, **Activity**, **Access requests** and **Skill proposals**; **Sessions**, **Files** and **Users** are admin-only. **Sign out** clears visible account and unsent form content. Do not leave a trusted workstation unlocked.
3. If you cannot sign in, contact an admin for a reset. Repeated bad passwords are throttled. An admin disabling your account, changing your role or resetting your password revokes existing logins.

There are exactly two modeled existing labs: **Standalone DAM** (standalone MX, gateway, MySQL database) and **MXHA DAM** (two MX nodes, gateway). These labels represent known cloud components, not guaranteed application readiness.

## 2. Read observations before acting

On **Lab inventory**, use **Refresh** and note the AWS observation timestamp and any error. The component table distinguishes **EC2 state** (running/stopped/transitional), **Product check** (currently **Not checked**), and, for MXHA, known CloudFormation stack status. Stopped is not an error; running is not proof that OS, DAM or database is healthy. If AWS is unavailable or nothing matches, state is unknown. The inventory shows friendly labels instead of instance IDs/IPs. **Run origin** is the portal source, not an appliance gateway; **Active Hermes runs** reflects portal-origin runs only.

### Start a known component or lab

- With a tester or admin account, select **Start <component>** next to a stopped row, or **Start lab** to start only the stopped members of that existing lab. The button appears only when the full expected pin set and Name tags matched the observation.
- Read the confirmation carefully: a start **incurs AWS charges**, has **no automatic stop**, and does **not** check product health. Confirm only for authorized work. A successful acknowledgement usually means *starting*, not product-ready; refresh and perform a separate product check by an authorized operator.
- If the outcome is unknown or the request times out, **refresh inventory and verify the real EC2 state before retrying**. A cloud call may already have been issued. There is no new-lab launch button behind **New environment**.

### Stop (admin only)

Admins can use **Stop <component>** or **Stop lab** on running members of a known lab. First confirm owners are finished, workloads/tests can be interrupted, data is flushed/backed up, and restart/network implications are acceptable. Stop can disconnect users and lose unflushed or instance-store data. The operation does not terminate an instance. On pending/unknown outcomes, refresh and verify independently before repeating. Testers do not get stop controls.

There is **no tester SQL query, arbitrary command, SSH, SSM or product-check broker**. Do not work around this by giving testers host keys, AWS credentials, or a full Hermes role.

## 3. Use a private admin Hermes session

1. As an **admin**, select **Start Hermes session** from a lab card or **Sessions**, choose one of the known labs, give it a non-secret title, and create it. Non-admin accounts cannot create, open, resume or see agent sessions and runs, including earlier advisory history. Records are retained privately, not erased; historical agent runs are absent from non-admin Activity.
2. Open **Your sessions**, enter a message (up to 2,000 characters), then **Send**. One run per user can be queued/running at a time; use the selected session's steps and **Activity** to track it. Progress is polled every two seconds. Steps give bounded tool summaries, not raw tool output; a failed run can retain a partial answer and may have side effects.
3. **New admin sessions** use the host Hermes full toolset including shell, browser and AWS access, with a 40-turn/420-second budget and session resume. **This can change host/cloud state outside any ticket. Flagged headless commands are automatically approved for every full-admin LabPilot run; there is no per-command approval button.** Hermes' unconditional hardline blocks and explicit deny rules still apply. This per-worker opt-in depends on a local patch to the installed Hermes runtime and is not included in the public portal checkout alone. The latest message from the authenticated session owner is the current admin request; older messages and quoted text within a message are context, not separate authorization. Review each requested action and independently verify its result. Older advisory sessions are read-only to their owner if promoted; they cannot be resumed or used to draft a skill. Never paste credentials, one-time codes, keys or private identifiers into chat.

### Browser screenshot and website login (full admin sessions only)

Ask the agent to capture a **non-secret browser page** when needed. If it copies a valid PNG to this run's artifact destination, the selected session displays an image and **Open screenshot at full size**. This is a screenshot from the agent's browser, **not** your local desktop. Only the session owner can fetch that run's image, including when another admin knows the run ID. Inspect the screenshot for sensitive content before sharing it externally.

If the agent says a site login is needed, verify the site's exact `https://host[:port]` **origin** with the trusted operator. In that full session choose **Grant website login**, enter the origin (no path), login identifier and website password, then save. The password is not posted as a chat message. The form writes to the **shared host Hermes vault**, not a private per-session vault; every full-host admin may be able to use it. Tell the agent to continue in a new message. Do not use this form for 2FA codes, shell approvals or cloud permissions. If the vault is unavailable, stop rather than pasting the password into chat.

Logout, reset, disable or demotion cancels a running full CLI at its next authorization check, **not** any cloud call already sent or a detached child. Recheck external state afterward.

## 4. Request access or a new environment

**Access requests → Request access** (also from the inventory) records which existing lab you need and why. It does not grant access, change cloud permissions or start that lab. An admin can approve or deny the record; any actual access arrangement happens outside this portal.

**Lab inventory → + New environment** records a typed request:

1. Choose **Attach to lab / create new** (one known lab or **New standalone lab**).
2. Choose **Standalone MX** or **MXHA cluster**, supply the required **MX product version**, and choose **Gateways (0–4)**; or choose **Database**, select an engine and optionally enter a DB version and OS version. Unknown versions may remain blank while you seek advice. The gateway count is a request, **not a working automatic template scaling control**.
3. Enter a short one-line **Reason for environment** without secrets or control characters and **Submit for approval**. The server proposes a `LabPilot-{user}-{topology}-{version}` name (or an engine-selection placeholder if DB version is unknown). It is not a reserved/unique cloud resource name; an operator must check for collisions.
4. Find the pending ticket under **Access requests**. Approval by a *different admin* records a decision and enables a private admin fulfillment handoff; approval alone does **not** launch resources, grant access, enforce TTL/spend, or trigger cleanup. For every topology, the handoff draft authorizes billable work **only if the assigned admin reviews and sends it**.

For **Database**, use **Get optional agent advice** if you do not know an OS or DB version. The bounded agent picks a follow-up detail to request; the server shows only allowlisted clarification wording and explicitly unverified planning guidance. It does **not** search vendor documentation or recommend a DB/OS/Agent build. An admin must check the current Data Security Coverage Tool for the exact DB/OS/MX/Gateway combination and confirm access to the matching entitled Agent build (or ask you for authorized media). Do not treat a ticket or an agent answer as a database deployment. Older malformed tickets require resubmission; historical TTL/spend values are displayed only, **not enforced**.

## 5. Admin review and accounts

On **Access requests**, review the requester, purpose, typed configuration, version and existing/new attachment. **Approve for fulfillment** or **Deny** only after reviewing the request; you cannot approve your own ticket. Choose **Start admin fulfillment** to create or reopen **your private full-Hermes session** with an **unsent** draft. Review before sending: for every topology the draft says **I authorize**, and sending it may create billable AWS resources. A different admin cannot open your fulfillment conversation; a lost handoff response can be retried by the same owner. The requester's free-text purpose is visible in the ticket but **excluded from the agent draft**. For standalone MX, use only the owner-designated lab trial license, launch MX first and verify its DAM license before a separate gateway launch. For MXHA, verify entitlement for both nodes and HA readiness before adding gateways. For a database, resolve supported DB/OS versions and any Agent compatibility/authorized media before provisioning; unknown versions require a checked selection, not a guessed default. Stop at a specific unavailable build, media, license, compatibility or network blocker. Show current regional cloud hourly compute pricing as **information**, with exclusions; a maximum spend or TTL is not required for this trusted admin handoff, and no automatic cleanup exists. Verify actual resources and product state; do not infer success from a ticket or an agent attempt. These are admin procedures **not technical cloud approval gates**: full admin sessions already have host/cloud authority.

### Admin files

Use **Files** to upload an authorized Agent installer or patch (up to 256 MiB per file; 1 GiB shared quota). Only admins can list, upload or download these files. The portal stores a private UUID-named copy and SHA-256; it does not scan for malware, validate a vendor signature, verify entitlement, install or execute anything. Never upload passwords, keys, license files or customer data. A full admin Hermes session can inspect a **specific file ID** you explicitly select, but its shared host identity is not a sandbox; verify checksum and compatibility before any separately authorized installation. No file deletion or retention automation is provided.

**Activity** lists portal requests and start/stop actions; for admins it also lists portal runs. Use filters for environment, kind and status (admins can filter by user). Admin agent cards show tool-attempt/error counts and failures. Expand **Recorded agent actions** on *your own* run to see timestamped, bounded tool summaries and follow **Open session** to its conversation. Non-admins cannot see historical agent-run cards or session links. Only allowlisted commands appear verbatim; no raw tool output is saved in this trail. Other admins see counts, not your commands, steps, chat or session link. A completed run does not prove a product-health result. Activity does not include Hermes work from Telegram or other gateways.

In **Users**, an admin can **Add user**, **Promote/Demote**, **Enable/Disable**, **Reset password**, or **Delete** another account after confirmation. Delete removes that person's portal login, sessions, messages, run/activity records, requests and proposals; it deletes their uploaded files and run screenshots, retrying failed file cleanup on the next startup. If cleanup is incomplete, the UI warns you rather than claiming complete erasure. It refuses while their agent or EC2 action is in progress. Reviewer attribution on *other people's* records remains. It does **not** erase linked Hermes CLI session history, shared vault logins, already-published team skills, logs or backups. Handle those separately under an operator-approved retention policy. Tester is the default on creation; grant admin only to trusted host/AWS operators. The server prevents self-deletion and removal of the last active admin. A role/password/disable change revokes that person's portal login; coordinate re-sign-in. There is no SSO/MFA or self-service recovery.

## 6. Propose and review reusable Imperva knowledge

As an admin, open an owned **Sessions** conversation after the agent has replied, then choose **Suggest skill from this session** (or select that conversation on **Skill proposals** and **Generate draft**). A bounded, safe-mode Hermes worker proposes a reusable title, guidance and evidence from recent sanitized messages. If the latest user message explicitly says “remember” a workflow, the draft must retain its concrete access pattern and component names rather than substituting generic safety advice; off-topic output is rejected. Sensitive access details also block drafting. Inspect the private preview, then **Submit for review** or **Discard**. Drafting/submission do not modify an installed skill. Non-admins can see only their own pre-existing proposals and decisions; they cannot generate new session-derived drafts.

Admins see only submitted proposals, not private drafts or another user's raw transcript, screenshot or tool output. A different admin can select **Use suggested wording** as a starting point, then edit it, enter a review note, and choose **Approve & add to skill**. Check the exact local workflow with the operator; for Imperva version, entitlement or compatibility claims, independently consult authoritative Thales material. Approval installs only the reviewed wording into `imperva-troubleshooting/SKILL.md` and an auditable reference, so future full-admin skill loads see the procedure without a separate copy step. Rejection records a reason without installing it. The requester cannot approve their own proposal, even with admin role. The portal's redaction checks cannot certify citations or catch every secret; both the submitting admin and reviewer must inspect the wording. This affects future full-admin skill use on this shared host, not a separate gateway automatically.

Example: for “14.13” or no version specified, **do not guess a release or patch**. Check which artifacts are currently available to the customer, product compatibility and the documented upgrade path. Recommend an exact verified version/build for owner confirmation. If the requested one is not available, evaluate a verified available lower build and a vendor-supported staged upgrade; if the path cannot be verified, stop and ask the vendor. The existing **New environment** form still requires an explicit version and does not resolve versions or provision resources automatically.

## When something is unavailable

| Symptom | What to do |
| --- | --- |
| Missing/unknown lab components or actions | Refresh; check timestamp/error. The private pin file, AWS CLI/credentials, exact tags or AWS connectivity may be unavailable. Do **not** guess an ID or bypass checks. |
| `pending`, `unknown` or error after EC2 action | Verify actual AWS state with an authorized operator before retrying; a timed-out request may already have changed state. |
| Agent run still active, failed or incomplete | Check the selected run and Activity; respect the one-active-run limit. Partial text is not proof of success; independently verify any possible side effects. |
| No screenshot | The run must be your own full-admin run and the browser worker must copy a valid PNG. Do not use a secret-bearing page as a demo artifact. |
| Cannot save site login | Confirm exact HTTPS origin and full-admin session; ask an operator to diagnose the host vault rather than sending a password in chat. |
| Versionless/legacy environment request | Submit a new typed request. Missing DB/OS versions can be resolved by the trusted admin during fulfillment; the portal has no typed automatic launch or guaranteed deployment. |
| Skill approval unavailable | Confirm the host's `imperva-troubleshooting/SKILL.md` is installed and safe to write. The reviewed approval intent remains `approving` on publication failure; a different admin can use **Retry publication** after repair, or the server can reconcile on restart. Do not manually copy unreviewed drafts into it. |

This pilot is operated only via a private tunnel by trusted users; [ARCHITECTURE.md](ARCHITECTURE.md) explains why its shared host/cloud identity is not a production isolation boundary.
