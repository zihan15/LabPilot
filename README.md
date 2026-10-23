# LabPilot portal

A **vibe-coded (AI-assisted), private proof-of-concept portal** built to showcase what a Hermes harness agent can do in a DAM engineering-lab workflow. It is a demonstration surface for agent-led investigation, visible tool progress, evidence handoff and bounded existing-lab actions—not a finished, independently secured product or an automated issue-reproduction harness. This repository is the portal (`server.py` plus `static/`), **not** the older `../app.py` workbench. It shows timestamped AWS EC2/CloudFormation observations, keeps per-user Hermes conversations, records portal activity and requests, and offers exact pinned-instance start/stop controls. It does not check DAM product health or automatically provision new environments.

> **Trust boundary:** An admin-created Hermes session has the host Hermes profile, filesystem and broad AWS `AdministratorAccess`. The tester safe-mode worker is bounded by tool selection, **not** an OS/IAM sandbox. Do not publish this service or give untrusted users accounts. A GitHub repository is source distribution, not a deployable security boundary.

## What works

| Surface | Tester | Admin | Important limit |
| --- | --- | --- | --- |
| Lab inventory | View EC2 component state and MXHA stack status | Same | AWS observation time is shown; product check remains “Not checked”; no instance IDs or private IPs in API responses. |
| Existing lab controls | Start individual stopped components or stopped members of a pinned lab | Start and stop individual components or a lab | Six pinned EC2 instances in two labs; exact Name tags and entire pin set checked before mutation. Start incurs cost; stop can interrupt work or lose data. No auto-stop. |
| Hermes sessions | Private advisory chat, `todo` tool, two turns/70-second budget | Private full host Hermes (`-t all`), 40 turns/420-second budget, resumed on later messages | One active run per user; visible steps omit raw tool output. An admin can act outside request approvals. |
| Screenshot / website login | Not available | Owner-only run screenshot; exact-origin website login form | Screenshots are private portal artifacts, **not** a local-desktop capture. Login goes to the shared host Hermes vault, accessible to other full-host admins. Never put credentials or codes in chat. |
| Requests | Lab-access note or typed MX/MXHA environment request | Review and approve/deny; approved environment ticket can open a private full-Hermes fulfillment draft | No automatic access grant or provisioning. Another admin must approve the requester's ticket. Separate confirmation, uniqueness/license/cost/expiry/rollback review remain human work. |
| Activity / users | Own portal events and runs | Filtered cross-user metadata; user management | Cross-user chat text/steps are withheld. Portal does not ingest other Hermes channels. Password-only login; no SSO/MFA. |

The environment form accepts standalone MX or MXHA, 0–4 requested gateways, an existing-lab attachment or a new lab, MX product version and purpose. The derived `LabPilot-{user}-{topology}-{version}` is **proposed**, not allocated; slug collisions are possible. Database deployment is a separate, unavailable workflow. The form has no TTL or spend controls, and neither limit is enforced. Legacy versionless or note-only requests need resubmission; historical limits on older tickets are only displayed.

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
