# Private deployment and GitHub handoff

**Status: source handoff only, not a team/public deployment recipe.** This portal is a trusted-host pilot. It binds `127.0.0.1` and gives portal admins the host Hermes full toolset; on the current pilot host that includes broad AWS `AdministratorAccess`. Tester safe mode is not an OS/IAM isolation boundary. Do not change network exposure, launch new cloud resources or install on a second host just because the repository is published.

## What a working Hermes + AWS host gets from this repo

**Pointing Hermes at the checkout is not an installation step.** LabPilot is a separate Python web app, not a Hermes plugin or skill. On a host with a configured Hermes CLI/model and AWS credentials, clone this repo, install its Python dependency, create a portal login, and launch the server. The `hermes` and `aws` executables must be on the server process's `PATH`, using the intended host profile and AWS identity. Admin chat explicitly preloads `imperva-troubleshooting`; install that skill in the same Hermes profile (the separate team-skills handoff is one source). Node.js is needed only to run the UI tests.

| Capability after checkout | Additional requirement |
| --- | --- |
| Loopback UI, login, requests, local activity | Python/Pillow, an initial portal account, and a running `server.py`; no existing portal database needs to be copied. |
| Admin Hermes chat | Working `hermes` CLI/model/provider under the server's OS account, plus the Imperva skill for domain context. Full admin runs inherit that account's files and cloud authority. |
| Skill drafting, review and promotion | Working Hermes CLI/model for a separate bounded safe-mode draft worker; a completed owned portal conversation, explicit owner preview/submit, two distinct portal accounts (requester and trusted admin), an installed **owner-owned** `imperva-troubleshooting/SKILL.md` in the server's Hermes profile, and a human reviewer with access to current Thales/vendor documentation and authorized downloads. Approval writes to that host skill, **not this Git checkout**. |
| AWS inventory | Working `aws` CLI/credentials for `ap-southeast-1` and **existing** instances whose Name tags match `LAB_INSTANCE_NAMES` in `server.py`. AWS credentials alone do not create or discover arbitrary new labs. |
| Start/stop known lab components | In addition, the owner-only 0600 instance-pin file below, with the exact six existing IDs in source-defined slot order and matching Name tags. Missing/mismatched pins disable actions. |
| DB planning clarification and private file exchange | Working Hermes model for bounded clarification selection; a host-local private `uploads/` directory for admin-only files. No live vendor search or sourced version recommendation is implemented. Uploads are unscanned and must not be executed merely because they are present. |
| New lab provisioning, actual database deployment, end-to-end test/evidence/cleanup | **Not implemented** by this repository; an approved DB/MX request is a human planning handoff, not an executor. |

**Why this exists:** This is a vibe-coded, AI-assisted demo of a Hermes harness agent's potential in a lab workflow, not a certified portal, production authorization layer, or fully automated build → test → prove → cleanup system. A portal chat request launches a **new Hermes CLI subprocess**, not a continuation of a Telegram/gateway conversation. The app adds per-user ownership, one-active-run limits, per-message turn/time budgets, sanitized progress and screenshot access checks; the gateway follows its own configured conversation and approval lifecycle. Those app checks are useful demo guardrails, **not** separate OS users, scoped IAM, token quotas, or mandatory cloud approval. Full portal admins retain the server account's effective host/cloud access and can bypass request tickets. The current pilot's headless Hermes approval mode denies gated commands rather than asking in the portal; check the new host's own config before relying on that behavior. Details: [portal agent versus Hermes gateway](ARCHITECTURE.md#portal-agent-versus-hermes-gateway).

For a trusted private pilot, from a **fresh checkout**:

```sh
git clone https://github.com/zihan15/LabPilot.git
cd LabPilot
python -m pip install -r requirements.txt
python -m unittest -v test_portal test_features
node --test test_ui.mjs                 # optional; requires Node.js
node --check static/app.js             # optional; requires Node.js
python server.py create-user --username your-username  # prompts for a 16+ character password; tester by default
python server.py serve --port 8090
```

The server always binds `127.0.0.1`; `--port` defaults to 8090. `--role admin` exists for `create-user` but must be reserved for explicitly trusted host/cloud operators. CLI `--db <path>` is for an authorized private store, not a shared repository file. This checkout omits private resource pins, the host profile/vault, accounts and credentials; do **not** copy a prior portal database or secrets into Git to make it work.

Host-specific state is **outside Git**:

- `~/.local/share/labpilot/portal.sqlite` (0600) and its adjacent `portal-artifacts/` screenshot directory (0700) contain account/chat/run data and screenshot artifacts. Do not copy these into Git or a handoff ZIP.
- The adjacent `uploads/` directory (0700) contains UUID-named, 0600, **untrusted binary** files; `portal_files` in SQLite records original names, size and digest. Back up together if authorized, never publish or execute automatically. Maximum 256 MiB/file and 1 GiB total; no malware scanning, signature verification, file deletion/retention policy, or entitlement verification is implemented.
- `~/.config/labpilot-portal/instance-allowlist.private.json` must be an owner-owned, 0600 file listing exactly three pinned EC2 IDs for each of `dam-standalone` and `dam-mxha`, **in the source-defined component order**. The runtime checks all six IDs and exact Name tags before any start/stop. This is an operator-managed private configuration, **not an invitation to invent IDs or paste them into documentation**. If it is absent or mismatched, action availability is blocked.
- Initial owner bootstrap credentials, if present on an existing host, stay in its private operator store. Never include them in a README, issue, screenshot, GitHub secret example or chat. The website-login vault belongs to the host Hermes profile and is shared by all full-host admins.
- Skill proposals, requester evidence, review notes and status are in the private portal SQLite database. An approved proposal is also a `references/portal-approved-<id>.md` file and `SKILL.md` pointer in the installed Imperva skill folder (normally `~/.hermes/skills/cybersecurity/imperva-troubleshooting`, or under the server process's `HERMES_HOME`). This mutation is intentionally outside Git; back up and review it as host state. No unreviewed proposal is copied there. A single process serializes writes, but this is not a clustered skill registry or a guarantee that free-text evidence has been independently verified.

Use an authenticated SSH tunnel from a trusted workstation, e.g. `ssh -N -L 8090:127.0.0.1:8090 <ssh-user>@<private-host>`, then visit `http://127.0.0.1:8090`. If local port 8090 is occupied, select another **local** forwarding port. Do not bind `0.0.0.0`, open an inbound security-group port, reverse-proxy this pilot to teammates or put the tunnel endpoint on an untrusted workstation. `GET /api/health` says the process is ready only; it does not probe AWS, Hermes, product health or independent cleanup.

## Safe GitHub handoff

1. Review the intended paths in this checkout: `README.md`, `ARCHITECTURE.md`, `USER-GUIDE.md`, `DEPLOYMENT.md`, `docs/architecture.html`, source/tests, and the static licensed font. Private-pilot screenshots are excluded; if adding images later, review pixels for account names, cloud state, private URLs and identifiers before sharing.
2. Check `git status --short`, `git diff --check`, `git diff --stat`, and `git ls-files`. Inspect **both tracked and untracked** content; ignored/private files may still be manually added with `-f`. Scan staged text for credentials, IDs, private IPs and machine-specific host details. `.gitignore` is a guardrail, not a proof of no secrets.
3. The source can be committed to an approved repository after an exact staged-content review. Confirm repository visibility and access controls before any push; the included application checks do not make a public endpoint safe.
4. A GitHub upload is not a working deployment, cloud backup or permission model. Do not publish a cloned private runtime directory or the older workbench by accident.

## Gates before broader access

- Isolate tester workers and privileged admin execution under separate OS identities and scoped IAM; prevent unintended host file/profile access and block unneeded IMDS/network access. App-level safe-mode/toolset flags and pinned IDs are not sandboxes.
- Replace password-only pilot authentication with reviewed HTTPS, SSO/MFA and operator/role policy; add audit retention, abuse testing and an independent authorization boundary for cloud mutation. Admin full-tool sessions can currently bypass request tickets.
- For automatic or tester-facing provisioning, require a reviewed typed plan, isolated execution identity, verified license/template/secret/network feasibility, explicit entitlement, spend ceiling, expiry and independent cleanup. The current form records neither TTL nor spend and performs **no** provisioning or teardown. Confirm proposed-name uniqueness before resource creation; normalization may collide.
- Verify restricted read-only tester DB/product transport before offering queries. No such broker exists today; do not substitute host shell, keys or broad AWS credentials. EC2 observations/start acknowledgements are not DAM or database health checks.
- Have an operator assess live start/stop cost, workload disruption and data-loss risk, and verify actual EC2 state after uncertain outcomes. Tests use mocks and do not authorize live mutations.

See [ARCHITECTURE.md](ARCHITECTURE.md) and the [offline architecture diagram](docs/architecture.html) for exact current flows, and [USER-GUIDE.md](USER-GUIDE.md) for role-specific operation.
