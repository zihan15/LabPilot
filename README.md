# LabPilot — AI-assisted engineering lab pilot

Reproducing an enterprise issue often means rebuilding the right database, OS, product version and network conditions before anyone can test a fix. LabPilot explores whether an agent harness can make that work more repeatable: observe a lab, help an engineer investigate, record what was attempted, and turn useful findings into reviewed procedures for the next case.

**LabPilot is a vibe-coded, private proof of concept for trusted Imperva DAM engineers**, not a finished automation or security product. This repository contains the portal (`server.py` and `static/`), not the older `../app.py` workbench.

## Demo access and media

- **Private demo:** [Open LabPilot on localhost](http://127.0.0.1:8090) **after** an authenticated tunnel is running on that local port. Ask the lab operator for an account and follow [Private local run](#private-local-run); there is no public demo URL. If you forward a different local port, use that port instead. The repository alone cannot connect to the private lab.
- **Demo recording:** A video walkthrough will be linked in the [Demo](#demo) section after the owner publishes a reviewed copy. No private sessions, credentials, customer details or live cloud identifiers should be published as demo media.

## Demo

**Admin-focused video:** Coming soon—the owner will add a link here after reviewing and hosting the recording. No video is bundled with this repository. The walkthrough focuses on admin inventory, private Hermes sessions, request fulfillment, agent progress and reviewed skill proposals; it is a demo of the portal workflow, not proof that a new DAM lab was provisioned or that a policy fired. Review the recording frame by frame for private accounts, identifiers, lab state and credentials before publishing it. For a large video, host it outside the source tree and link it here rather than committing the binary.

## What is Hermes, and why a separate LabPilot?

[Hermes Agent](https://hermes-agent.nousresearch.com/docs/) is the agent harness: it connects a model to tools, reusable skills, persistent context and optional messaging gateways. It can run through [Telegram, Slack or WhatsApp](https://hermes-agent.nousresearch.com/docs/user-guide/messaging) when each gateway is configured with appropriate access. **Those gateway conversations are not LabPilot sessions** and do not inherit this portal's roles, budgets or review workflow.

We built a separate, multi-user portal to focus on Imperva DAM lab work: known lab inventory, account-owned conversations, bounded run progress, request review, private file exchange and a human-reviewed path for adding Imperva troubleshooting lessons. This gives engineers a narrower place to try a domain-specific workflow without implying that the underlying host or full-admin agent is isolated.

## What this pilot is testing

- **Workflow integration:** Can an engineer combine existing AWS observations, controlled actions, agent research and recorded evidence in one investigation instead of repeating setup from scratch?
- **Learning with review:** Can an agent suggest a reusable procedure from a session, while its owner and a different admin check the claim before it becomes a shared skill?
- **Scale of the idea:** A matrix such as 11 policies across three database types is the kind of repetitive validation we want to simplify—not a test suite this portal currently runs. The same harness pattern could also support authorized vulnerability validation in an isolated lab, mitigation research or building other internal tools. Those are possible extensions, **not shipped LabPilot features**.

This is for engineers who understand the product, the test conditions and the risks well enough to define the workflow and verify outcomes. An agent can help research and execute bounded steps; it does not replace engineering judgment, authorization, vendor compatibility checks or evidence that a fix worked. We deliberately do not use a current vulnerability headline as proof that this pilot detects or remediates emerging attacks.

> **Trust boundary:** Admin Hermes sessions have the host profile, filesystem and broad AWS `AdministratorAccess`. Non-admin accounts have **no portal agent-session capability**; bounded DB advice and historical safe-mode agents still share the host OS identity and are **not** an OS/IAM sandbox. Do not publish this service or give untrusted users accounts. A GitHub repository is source distribution, not a deployable security boundary.

## What works

| Surface | Tester | Admin | Important limit |
| --- | --- | --- | --- |
| Lab inventory | View EC2 component state and MXHA stack status | Same | AWS observation time is shown; product check remains “Not checked”; no instance IDs or private IPs in API responses. |
| Existing lab controls | Start individual stopped components or stopped members of a pinned lab | Start and stop individual components or a lab | Six pinned EC2 instances in two labs; exact Name tags and entire pin set checked before mutation. Start incurs cost; stop can interrupt work or lose data. No auto-stop. |
| Hermes sessions | **Not available**, including earlier tester session history and run APIs | Private full host Hermes (`-t all`), 40 turns/420-second budget, resumed on later messages | Existing records are retained, not erased. One active run per admin; visible steps omit raw tool output. An admin can act outside request approvals. |
| Screenshot / website login | Not available | Owner-only run screenshot; exact-origin website login form | Screenshots are private portal artifacts, **not** a local-desktop capture. Login goes to the shared host Hermes vault, accessible to other full-host admins. Never put credentials or codes in chat. |
| Requests | Lab-access note or typed MX/MXHA/database environment request; unknown DB/OS versions may be left blank | Review and approve/deny; approved standalone MX ticket opens an explicit, unsent admin-agent launch handoff; MXHA/DB remain planning | Ticket approval alone launches nothing. A trusted admin who reviews and sends the standalone MX authorization can incur AWS charges; trial licensing must be verified on the new MX before a separate gateway launch. No automatic cleanup/spend cap. |
| DB planning clarification | Ask a bounded agent which missing DB/OS/MX detail to supply | Same; check private Files inventory for entitled media | The server displays only allowlisted clarification wording, not raw model claims; no vendor search or version recommendation. Exact Agent build and OS/database combination remain **unverified** until current Thales coverage and download entitlement are checked. |
| Files | Not available | Upload and download untrusted Agent/patch media in a private host store | 256 MiB/file, 1 GiB total, admin-only, no malware scanning or automatic execution/install. Never upload credentials or licenses. |
| Skill proposals | View your own earlier proposals and decisions; no new session-derived drafts | Generate a bounded draft from an owned admin session; a **different admin** reviews and approves/rejects, adding only reviewed text to the installed Imperva skill | No publication on generation/submission or vendor-version certification. Drafts stay private to the owner until submission. |
| Activity / users | Own request and known-lab start/stop events; historical agent-run details hidden | Filtered cross-user metadata and tool-attempt/error counts; user management | Only an admin run owner sees bounded tool summaries and a session link. No raw tool output, cross-user chat/steps, or other Hermes channels. Password-only login; no SSO/MFA. |

The environment form accepts standalone MX or MXHA with 0–4 requested gateways and an MX version, or a database request with an engine and optional DB/OS versions. It records a proposed name, not an allocated cloud resource; normalization can collide. Database requests enter the same human-review/fulfillment planning flow; no database is actually deployed by this app. The form has no TTL or spend controls, and neither limit is enforced. Legacy invalid requests need resubmission.

**Learning loop (admins):** From **Sessions**, choose **Suggest skill from this session**, or select one of your own sessions on **Skill proposals**. A separate bounded safe-mode Hermes process summarizes recent session messages into a private draft. Preview it, discard it if it exposes sensitive information or is wrong, or explicitly **Submit for review**. Only then can a different admin see the candidate, inspect its evidence, enter final reviewed guidance and approve before the server writes `references/portal-approved-<proposal-id>.md` and an index entry under the *installed host* `imperva-troubleshooting` skill. Non-admins retain visibility into their earlier proposals but cannot open agent sessions or generate new drafts. For version requests, verify current Thales release notes, authorized downloads, patch compatibility and upgrade path; neither worker certifies an exact build.

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
- UI screenshots from the private pilot are deliberately excluded from this public-source snapshot; no live lab status is implied by the repository.

## Checks

```sh
python -m unittest -v test_portal test_features
node --test test_ui.mjs
node --check static/app.js
git diff --check
```

These tests mock cloud/agent interactions; they are **not** live EC2 or product validation. The portal is not production security architecture: application checks, CSRF, cookies and loopback binding do not isolate a shared host identity. Details and release blockers are in [DEPLOYMENT.md](DEPLOYMENT.md).
