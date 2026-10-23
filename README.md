# LabPilot — AI-assisted engineering lab pilot

Reproducing an enterprise issue often means rebuilding the right database, OS, product version and network conditions before anyone can test a fix. LabPilot explores whether an agent harness can make that work more repeatable: observe a lab, help an engineer investigate, record what was attempted, and turn useful findings into reviewed procedures for the next case.

**LabPilot is a vibe-coded, private proof of concept for trusted Imperva DAM engineers**, not a finished automation or security product. This repository contains the portal (`server.py` and `static/`), not the older `../app.py` workbench.

## Demo access and media

- **Private demo:** [Open LabPilot on localhost](http://127.0.0.1:8090) **after** an authenticated tunnel is running on that local port. Ask the lab operator for an account and follow [Private local run](#private-local-run); there is no public demo URL. If you forward a different local port, use that port instead. The repository alone cannot connect to the private lab.
- **Screenshots and video:** A redacted walkthrough may be added here after review. No private sessions, credentials, customer details or live cloud identifiers should be published as demo media.

## What is Hermes, and why a separate LabPilot?

[Hermes Agent](https://hermes-agent.nousresearch.com/docs/) is the agent harness: it connects a model to tools, reusable skills, persistent context and optional messaging gateways. It can run through [Telegram, Slack or WhatsApp](https://hermes-agent.nousresearch.com/docs/user-guide/messaging) when each gateway is configured with appropriate access. **Those gateway conversations are not LabPilot sessions** and do not inherit this portal's roles, budgets or review workflow.

We built a separate, multi-user portal to focus on Imperva DAM lab work: known lab inventory, account-owned conversations, bounded run progress, request review, private file exchange and a human-reviewed path for adding Imperva troubleshooting lessons. This gives engineers a narrower place to try a domain-specific workflow without implying that the underlying host or full-admin agent is isolated.

## What this pilot is testing

- **Workflow integration:** Can an engineer combine existing AWS observations, controlled actions, agent research and recorded evidence in one investigation instead of repeating setup from scratch?
- **Learning with review:** Can an agent suggest a reusable procedure from a session, while its owner and a different admin check the claim before it becomes a shared skill?
- **Scale of the idea:** A matrix such as 11 policies across three database types is the kind of repetitive validation we want to simplify—not a test suite this portal currently runs. The same harness pattern could also support authorized vulnerability validation in an isolated lab, mitigation research or building other internal tools. Those are possible extensions, **not shipped LabPilot features**.

This is for engineers who understand the product, the test conditions and the risks well enough to define the workflow and verify outcomes. An agent can help research and execute bounded steps; it does not replace engineering judgment, authorization, vendor compatibility checks or evidence that a fix worked. We deliberately do not use a current vulnerability headline as proof that this pilot detects or remediates emerging attacks.

> **Trust boundary:** An admin-created Hermes session has the host Hermes profile, filesystem and broad AWS `AdministratorAccess`. The tester safe-mode worker is bounded by tool selection, **not** an OS/IAM sandbox. Do not publish this service or give untrusted users accounts. A GitHub repository is source distribution, not a deployable security boundary.

## What works

| Surface | Tester | Admin | Important limit |
| --- | --- | --- | --- |
| Lab inventory | View EC2 component state and MXHA stack status | Same | AWS observation time is shown; product check remains “Not checked”; no instance IDs or private IPs in API responses. |
| Existing lab controls | Start individual stopped components or stopped members of a pinned lab | Start and stop individual components or a lab | Six pinned EC2 instances in two labs; exact Name tags and entire pin set checked before mutation. Start incurs cost; stop can interrupt work or lose data. No auto-stop. |
| Hermes sessions | Private advisory chat, `todo` tool, two turns/70-second budget | Private full host Hermes (`-t all`), 40 turns/420-second budget, resumed on later messages | One active run per user; visible steps omit raw tool output. An admin can act outside request approvals. |
| Screenshot / website login | Not available | Owner-only run screenshot; exact-origin website login form | Screenshots are private portal artifacts, **not** a local-desktop capture. Login goes to the shared host Hermes vault, accessible to other full-host admins. Never put credentials or codes in chat. |
| Requests | Lab-access note or typed MX/MXHA/database environment request; unknown DB/OS versions may be left blank | Review and approve/deny; approved environment ticket opens a private full-Hermes planning handoff | No automatic database creation or provisioning. Another admin must approve the requester's ticket; exact version, entitlement, cost, expiry and rollback remain human checks. |
| DB planning clarification | Ask a bounded agent which missing DB/OS/MX detail to supply | Same; check private Files inventory for entitled media | The server displays only allowlisted clarification wording, not raw model claims; no vendor search or version recommendation. Exact Agent build and OS/database combination remain **unverified** until current Thales coverage and download entitlement are checked. |
| Files | Not available | Upload and download untrusted Agent/patch media in a private host store | 256 MiB/file, 1 GiB total, admin-only, no malware scanning or automatic execution/install. Never upload credentials or licenses. |
| Skill proposals | Select your own agent session; a bounded Hermes worker drafts a reusable lesson for your preview, then you submit or discard it | A **different admin** reviews, rewrites and approves/rejects; approval writes a reference in the installed Imperva skill | No user-authored skill form, automatic publication or vendor-version certification. Drafts stay private to the owner until submission. |
| Activity / users | Own portal events and timestamped agent action trail | Filtered cross-user metadata and tool-attempt/error counts; user management | Only the run owner sees bounded tool summaries and a session link. No raw tool output, cross-user chat/steps, or other Hermes channels. Password-only login; no SSO/MFA. |

The environment form accepts standalone MX or MXHA with 0–4 requested gateways and an MX version, or a database request with an engine and optional DB/OS versions. It records a proposed name, not an allocated cloud resource; normalization can collide. Database requests enter the same human-review/fulfillment planning flow; no database is actually deployed by this app. The form has no TTL or spend controls, and neither limit is enforced. Legacy invalid requests need resubmission.

**Learning loop:** From **Sessions**, choose **Suggest skill from this session**, or select one of your own sessions on **Skill proposals**. A separate bounded safe-mode Hermes process summarizes recent session messages into a private draft; no user needs to write skill text. Preview it, discard it if it exposes sensitive information or is wrong, or explicitly **Submit for review**. Only then can a different admin see the candidate, inspect its evidence, enter final reviewed guidance and approve before the server writes `references/portal-approved-<proposal-id>.md` and an index entry under the *installed host* `imperva-troubleshooting` skill. For version requests (e.g. 14.13 or unspecified), the curated skill instructs admins to verify current Thales release notes, available authorized downloads, a compatible patch and a supported upgrade path, then seek owner confirmation. The draft worker does not certify any named version; the separate DB advice worker offers guidance, not a verified entitled artifact.

## Portal agent versus a normal Hermes gateway session

The portal does **not** attach to your Telegram/gateway conversation. Each message starts a separate `hermes chat` CLI subprocess on the portal host. New admin conversations link and resume their **own** Hermes CLI history; tester conversations pass only recent portal messages. Gateway conversations follow the gateway's configured tools, context and approval path instead. The portal adds its own account/session checks, one-active-run limit, per-run time/turn caps and owner-scoped progress/artifacts; these are **not token quotas or a sandbox**. New admin sessions still inherit the host Hermes profile, filesystem and AWS authority and can act outside request tickets. Tester safe mode restricts model tools but shares the host OS identity. On this pilot, headless command approvals deny gated commands rather than opening a portal approval card. See [ARCHITECTURE.md](ARCHITECTURE.md#portal-agent-versus-hermes-gateway) for the exact launch flags and limits.

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
- [Architecture diagram](docs/architecture.html) — standalone offline HTML with inline SVG; open the file directly in a browser. It is documentation, not a portal route.
- [DEPLOYMENT.md](DEPLOYMENT.md) — private-host prerequisites, GitHub handoff and security gates.
- UI screenshots from the private pilot are deliberately excluded from this public-source snapshot; no live lab status is implied by the repository.

## Checks

```sh
python -m unittest -v test_portal test_features
node --test test_ui.mjs
node --check static/app.js
git diff --check
```

These tests mock cloud/agent interactions; they are **not** live EC2 or product validation. The portal is not production security architecture: application checks, CSRF, cookies and loopback binding do not isolate a shared host identity. Details and release blockers are in [DEPLOYMENT.md](DEPLOYMENT.md).
