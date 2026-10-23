# LabPilot portal user guide

This guide is for a **trusted private pilot**, reached through an authenticated SSH tunnel. It describes the portal in this repository, not the older LabPilot workbench. Ask your operator for an account and the approved tunnel procedure; do not share passwords, private hostnames or cloud identifiers in tickets or chat. See [README.md](README.md) to start locally and [DEPLOYMENT.md](DEPLOYMENT.md) before moving hosts.

## 1. Sign in and orient yourself

1. Open the tunneled `http://127.0.0.1:8090`, enter your portal username and password, then **Sign in**. New accounts default to **tester**; a trusted operator must explicitly assign **admin**. Passwords are at least 16 characters. A session expires after 12 hours; sign in again if prompted.
2. Use **Lab inventory**, **Sessions**, **Activity**, **Access requests**, and (admin only) **Users** in the navigation. **Sign out** clears the visible account, chat and unsent form content. Do not leave a trusted workstation unlocked.
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

## 3. Use a private Hermes session

1. Select **Start Hermes session** from a lab card or **Sessions**, choose one of the known labs, give it a non-secret title, and create it.
2. Open **Your sessions**, enter a message (up to 2,000 characters), then **Send**. One run per user can be queued/running at a time; use the selected session's steps and **Activity** to track it. Progress is polled every two seconds. Steps give bounded tool summaries, not raw tool output; a failed run can retain a partial answer and may have side effects.
3. **Tester sessions** are advisory: recent context, safe-mode `todo` tool only, two turns and a 70-second CLI budget. They do not read the current lab state on your behalf, execute SQL, or inspect the appliance. Ask for guidance, not a claimed live check.
4. **New admin sessions** use the host Hermes full toolset including shell, browser and AWS access, with a 40-turn/420-second budget and session resume. **This can change host/cloud state outside any ticket.** Review each requested action and independently verify its result. Older sessions created before full mode remain advisory. Never paste credentials, one-time codes, keys or private identifiers into chat.

### Browser screenshot and website login (full admin sessions only)

Ask the agent to capture a **non-secret browser page** when needed. If it copies a valid PNG to this run's artifact destination, the selected session displays an image and **Open screenshot at full size**. This is a screenshot from the agent's browser, **not** your local desktop. Only the session owner can fetch that run's image, including when another admin knows the run ID. Inspect the screenshot for sensitive content before sharing it externally.

If the agent says a site login is needed, verify the site's exact `https://host[:port]` **origin** with the trusted operator. In that full session choose **Grant website login**, enter the origin (no path), login identifier and website password, then save. The password is not posted as a chat message. The form writes to the **shared host Hermes vault**, not a private per-session vault; every full-host admin may be able to use it. Tell the agent to continue in a new message. Do not use this form for 2FA codes, shell approvals or cloud permissions. If the vault is unavailable, stop rather than pasting the password into chat.

Logout, reset, disable or demotion cancels a running full CLI at its next authorization check, **not** any cloud call already sent or a detached child. Recheck external state afterward.

## 4. Request access or a new environment

**Access requests → Request access** (also from the inventory) records which existing lab you need and why. It does not grant access, change cloud permissions or start that lab. An admin can approve or deny the record; any actual access arrangement happens outside this portal.

**Lab inventory → + New environment** records a typed request:

1. Choose **Attach to lab / create new** (one known lab or **New standalone lab**).
2. Choose **Standalone MX** or **MXHA cluster**, supply the required **MX product version**, and choose **Gateways (0–4)**. This is a requested count, **not a working automatic template scaling control**.
3. Enter a short one-line **Reason for environment** without secrets or control characters and **Submit for approval**. The server proposes `LabPilot-{user}-{topology}-{version}` with punctuation slugged. This is not a reserved/unique cloud resource name; an operator must check for collisions.
4. Find the pending ticket under **Access requests**. Approval by a *different admin* records a decision and enables a private admin fulfillment handoff. It does **not** launch resources, create a database, grant access, enforce TTL/spend, or trigger cleanup.

Database deployments are not offered in this form. Older database tickets cannot be fulfilled here, and note-only/versionless MX tickets need a fresh request. Historical TTL/spend fields on old tickets are displayed for context only; **no new request collects or enforces these limits**. If a request is denied, coordinate with an admin before resubmitting.

## 5. Admin review and accounts

On **Access requests**, review the requester, purpose, typed configuration, version and existing/new attachment. **Approve for fulfillment** or **Deny** only after reviewing the request; you cannot approve your own ticket. For an approved typed MX ticket, choose **Start admin fulfillment**. The portal creates or reopens **your private full-Hermes session** and puts an **unsent** draft in its composer. Review/edit before sending. Another admin cannot open your fulfillment conversation; a lost handoff response can be retried by the same owner. The free-text requester purpose is visible in the ticket but **excluded from the agent draft**. Check the proposed name's uniqueness, license entitlement, template feasibility, network/credentials, price, expiration/cleanup and rollback, then give separate explicit confirmation before any manual provisioning. This is a human procedure **not a technical approval gate**: any full admin session has host/cloud authority independently. Do not infer resources exist from a ticket status.

**Activity** lists portal runs, requests and start/stop actions; use filters for environment, kind and status (admins can also filter by user). A completed portal run is not a product-health result; a failed/unknown cloud action has no claimed completed checks. It excludes chat messages/notes from cross-user entries and does not include other Hermes channels.

In **Users**, an admin can **Add user**, **Promote/Demote**, **Enable/Disable**, and **Reset password**. Tester is the default on creation; grant admin only to trusted host/AWS operators. The server prevents removal of the last active admin. A role/password/disable change revokes that person's portal login; coordinate re-sign-in. There is no SSO/MFA or self-service recovery.

## When something is unavailable

| Symptom | What to do |
| --- | --- |
| Missing/unknown lab components or actions | Refresh; check timestamp/error. The private pin file, AWS CLI/credentials, exact tags or AWS connectivity may be unavailable. Do **not** guess an ID or bypass checks. |
| `pending`, `unknown` or error after EC2 action | Verify actual AWS state with an authorized operator before retrying; a timed-out request may already have changed state. |
| Agent run still active, failed or incomplete | Check the selected run and Activity; respect the one-active-run limit. Partial text is not proof of success; independently verify any possible side effects. |
| No screenshot | The run must be your own full-admin run and the browser worker must copy a valid PNG. Do not use a secret-bearing page as a demo artifact. |
| Cannot save site login | Confirm exact HTTPS origin and full-admin session; ask an operator to diagnose the host vault rather than sending a password in chat. |
| Versionless/legacy environment request | Submit a new typed MX request. Database deployment and automatic launch remain unavailable. |

This pilot is operated only via a private tunnel by trusted users; [ARCHITECTURE.md](ARCHITECTURE.md) explains why its shared host/cloud identity is not a production isolation boundary.
