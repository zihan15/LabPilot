# LabPilot — a team workspace for Imperva DAM labs

LabPilot is a private workspace for Imperva DAM engineers. It brings AWS lab visibility, controls for known environments, admin agent sessions, request handoffs and attributed activity into one place. Engineers can see what is running, investigate with an agent, and turn useful session workflows into skill proposals. A different admin reviews each proposal before it becomes shared guidance.

**This is a AI-assisted pilot with limited portal access controls and orchestration**, not a finished lab automation or security product. Admin agents inherit the host's permissions.

## Demo

**labpilotdemo.mp4 (5:23):** Portal inventory, trusted-admin Hermes sessions, policy-testing and reviewed skill proposals, followed by a separate Telegram/Hermes lab workflow. The Telegram gateway is not part of the portal. This recording shows a private test lab; the public source does not independently verify every on-screen product result or an end-to-end deploy/test/cleanup pipeline.

https://github.com/user-attachments/assets/cfaf5556-1d27-4662-a7cc-ae930a163e27

## What is Hermes, and why a separate LabPilot?

[Hermes Agent](https://hermes-agent.nousresearch.com/docs/) is the agent harness: it connects a model to tools, reusable skills, persistent context and optional messaging gateways. It can run through [Telegram, Slack or WhatsApp](https://hermes-agent.nousresearch.com/docs/user-guide/messaging) when each gateway is configured with appropriate access. **Those gateway conversations are not LabPilot sessions** and do not inherit this portal's roles, budgets or review workflow.

The portal gives the team a shared view of known labs and requests while keeping each admin's conversation private. It records bounded run progress and supports private file exchange and reviewed Imperva troubleshooting lessons. The portal's roles do not isolate the underlying host or full-admin agent.

## What this pilot is testing

- **Workflow integration:** Can an engineer combine existing AWS observations, controlled actions, agent research and recorded evidence in one investigation instead of repeating setup from scratch?
- **Learning with review:** Can an agent suggest a reusable procedure from a session, while its owner and a different admin check the claim before it becomes a shared skill?
- **Scale of the idea:** A matrix such as 11 policies across three database types is the kind of repetitive validation we want to simplify—not a test suite this portal currently runs. The same harness pattern could also support authorized vulnerability validation in an isolated lab, mitigation research or building other internal tools. Those are possible extensions, **not shipped LabPilot features**.

This is for engineers who understand the product, the test conditions and the risks well enough to define the workflow and verify outcomes. An agent can help research and execute bounded steps; it does not replace engineering judgment, authorization, vendor compatibility checks or evidence that a fix worked. We deliberately do not use a current vulnerability headline as proof that this pilot detects or remediates emerging attacks.

> **Trust boundary:** Admin Hermes sessions have the host profile, filesystem and broad AWS `AdministratorAccess`. Non-admin accounts have **no portal agent-session capability**; the bounded DB advice worker shares the host OS identity and is **not** an OS/IAM sandbox. Historical advisory runs are retained, not active. Do not publish this service or give untrusted users accounts. A GitHub repository is source distribution, not a deployable security boundary.

## What works

| Surface | Tester | Admin | Important limit |
| --- | --- | --- | --- |
| Lab inventory | View EC2 component state and MXHA stack status | Same | AWS observation time is shown; product check remains “Not checked”; no instance IDs or private IPs in API responses. |
| Existing lab controls | Start individual stopped components or stopped members of a pinned lab | Start and stop individual components or a lab | Six pinned EC2 instances in two labs; exact Name tags and entire pin set checked before mutation. Start incurs cost; stop can interrupt work or lose data. No auto-stop. |
| Hermes sessions | **Not available**, including earlier tester session history and run APIs | Private full host Hermes (`-t all`), 40 turns/420-second budget, resumed on later messages | Existing records are retained, not erased. One active run per admin; visible steps omit raw tool output. An admin can act outside request approvals. |
| Screenshot / website login | Not available | Owner-only run screenshot; exact-origin website login form | Screenshots are private portal artifacts, **not** a local-desktop capture. Login goes to the shared host Hermes vault, accessible to other full-host admins. Never put credentials or codes in chat. |
| Requests | Lab-access note or typed MX/MXHA/database environment request; unknown DB/OS versions may be left blank | Review and approve/deny; any approved environment ticket can open an explicit, unsent admin-agent launch handoff | Ticket approval alone launches nothing. Sending a reviewed handoff can incur cloud charges. Deployment depends on actual media, entitlement, compatibility and safe networking; no automatic cleanup/spend cap. |
| DB planning clarification | Ask a bounded agent which missing DB/OS/MX detail to supply | Same; check private Files inventory for entitled media | The server displays only allowlisted clarification wording, not raw model claims; no vendor search or version recommendation. Exact Agent build and OS/database combination remain **unverified** until current Thales coverage and download entitlement are checked. |
| Files | Not available | Upload and download untrusted Agent/patch media in a private host store | 256 MiB/file, 1 GiB total, admin-only, no malware scanning or automatic execution/install. Never upload credentials or licenses. |
| Skill proposals | View your own earlier proposals and decisions; no new session-derived drafts | Generate a bounded draft from an owned admin session; a **different admin** reviews and approves/rejects, adding only reviewed text to the installed Imperva skill | No publication on generation/submission or vendor-version certification. Drafts stay private to the owner until submission. |
| Activity / users | Own request and known-lab start/stop events; historical agent-run details hidden | Filtered cross-user metadata and tool-attempt/error counts; user management | Only an admin run owner sees bounded tool summaries and a session link. No raw tool output, cross-user chat/steps, or other Hermes channels. Password-only login; no SSO/MFA. |

The environment form accepts standalone MX or MXHA with 0–4 requested gateways and an MX version, or a database request with an engine and optional DB/OS versions. It records a proposed name, not an allocated cloud resource; normalization can collide. All three topologies use the same human-review and admin-session launch handoff. The portal has no typed new-environment executor: a trusted admin agent may attempt deployment after sending the authorization and verifying prerequisites. Missing DB/OS versions require supported version selection before deployment. The form has no TTL or spend controls, and neither limit is enforced. Legacy invalid requests need resubmission.

**Learning loop (admins):** From **Sessions**, choose **Suggest skill from this session**, or select one of your own sessions on **Skill proposals**. A separate bounded safe-mode Hermes process summarizes recent session messages into a private draft. Preview it, discard it if it exposes sensitive information or is wrong, or explicitly **Submit for review**. Only then can a different admin see the candidate, inspect its evidence, enter final reviewed guidance and approve before the server writes `references/portal-approved-<proposal-id>.md` and an index entry under the *installed host* `imperva-troubleshooting` skill. Non-admins retain visibility into their earlier proposals but cannot open agent sessions or generate new drafts. For version requests, verify current Thales release notes, authorized downloads, patch compatibility and upgrade path; neither worker certifies an exact build.

**Skills beyond LabPilot:** Reviewed `SKILL.md` workflows can be transferred to coding agents such as [Codex](https://learn.chatgpt.com/docs/build-skills) and [Claude Code](https://code.claude.com/docs/en/skills), then adapted to each agent's tools and permissions. A team can use them in a wider orchestration workflow with agents powered by different models. LabPilot currently runs its portal sessions through the host's configured Hermes model; it does **not** install skills into Codex or Claude Code, switch models per task, or orchestrate those agents automatically. The separate team handover bundle is a skills package, not a deployment or credential transfer.

## Portal agent versus a normal Hermes gateway session

The portal does **not** attach to your Telegram/gateway conversation. Each admin message starts a separate `hermes chat` CLI subprocess on the portal host; new admin conversations link and resume their **own** Hermes CLI history. Non-admin portal sessions and runs are disabled, including earlier advisory records. Gateway conversations follow their own configured tools, context and approval path. The portal adds account/session checks, one-active-run limits, per-run time/turn caps and owner-scoped progress/artifacts; these are **not token quotas or a sandbox**. Admin sessions inherit the host Hermes profile, filesystem and AWS authority and can act outside request tickets. Full-admin portal workers locally opt into unattended flagged-command approval; separate bounded advice/draft workers do not. See [ARCHITECTURE.md](ARCHITECTURE.md#portal-agent-versus-hermes-gateway) for exact flags and limitations.

## Private local run

Prerequisites: Python with `pip`, Pillow from `requirements.txt`, AWS CLI and credentials appropriate for this **trusted host** if live inventory/actions are needed, and an installed Hermes CLI/profile for chat. Private owner bootstrap credentials and the 0600 instance pin file are **not in Git**. This checkout does not create them. See [DEPLOYMENT.md](DEPLOYMENT.md) before attempting to operate a different host.

```sh
cd /path/to/labpilot-portal
python -m pip install -r requirements.txt
python server.py serve --port 8090
```

The server binds `127.0.0.1:8090` regardless of caller-facing address. On a trusted operator workstation, use an authenticated SSH tunnel (replace placeholders; do not paste private host details into Git):

```sh
ssh -N -L 8090:127.0.0.1:8090 <ssh-user>@<private-host>
```

Open `http://127.0.0.1:8090` locally. A private-host owner account may already exist in its runtime database; **no credential is included here**. An existing admin can add users in **Users**, or a trusted host operator can run `python server.py create-user --username your-username` and enter a 16+ character password at the prompt (tester role by default). Do not bootstrap a second host by copying a private database, credentials or pin file into the repository. `GET /api/health` only confirms the HTTP process is ready, not AWS, Hermes or product health.

## Guides and architecture

- [USER-GUIDE.md](USER-GUIDE.md) — sign-in, observations, actions, conversations, requests, admin review and troubleshooting.
- [ARCHITECTURE.md](ARCHITECTURE.md) — component/data-flow map and code inventory.

- [DEPLOYMENT.md](DEPLOYMENT.md) — private-host prerequisites, GitHub handoff and security gates.
- [HANDOVER.md](HANDOVER.md) — private runtime locations and a source-safe implementation checklist for other Hermes operators.
- No screenshot or video binaries are committed to Git; the demo above is a GitHub-hosted attachment. The repository itself implies no current live lab status.

## Checks

```sh
python -m unittest -v test_portal test_features
node --test test_ui.mjs
node --check static/app.js
git diff --check
```

These tests mock cloud/agent interactions; they are **not** live EC2 or product validation. The portal is not production security architecture: application checks, CSRF, cookies and loopback binding do not isolate a shared host identity. Details and release blockers are in [DEPLOYMENT.md](DEPLOYMENT.md).

## Private demo access

- **Private demo:** [Open LabPilot on localhost](http://127.0.0.1:8090) **after** an authenticated tunnel is running on that local port. Ask the lab operator for an account and follow [Private local run](#private-local-run); there is no public demo URL. If you forward a different local port, use that port instead. The repository alone cannot connect to the private lab.
