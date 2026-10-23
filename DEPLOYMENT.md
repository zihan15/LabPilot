# Private deployment and GitHub handoff

**Status: source handoff only, not a team/public deployment recipe.** This portal is a trusted-host pilot. It binds `127.0.0.1` and gives portal admins the host Hermes full toolset and broad AWS `AdministratorAccess`. Tester safe mode is not an OS/IAM isolation boundary. Do not change network exposure, launch new cloud resources or install on a second host just because the repository is published.

## Reproduce the private pilot only with an authorized operator

The source needs Python, `pip`, `Pillow` (`requirements.txt`), Node.js for the UI test only, AWS CLI and an already configured host AWS identity for **live** inventory/actions, and a working host Hermes CLI/profile (including the Imperva troubleshooting skill for full-admin chat). Without AWS CLI/credentials, inventory reports an error and controls are unavailable. Without Hermes, chats fail. This checkout alone is **not** a portable deployment: it omits private resource pins, host profile/vault, accounts and credentials.

```sh
cd /path/to/labpilot-portal
python -m pip install -r requirements.txt
python -m unittest -v test_portal test_features
node --test test_ui.mjs
node --check static/app.js
python server.py serve --port 8090
```

The server always binds `127.0.0.1`; `--port` defaults to 8090. `python server.py create-user --username <name>` creates a tester in the default private database and prompts for a 16+ character password. `--role admin` exists but must be reserved for explicitly trusted host/cloud operators. CLI `--db <path>` is for an authorized private store, not a shared repository file. No user or password is created by simply running the server on a fresh checkout.

Host-specific state is **outside Git**:

- `~/.local/share/labpilot/portal.sqlite` (0600) and its adjacent `portal-artifacts/` screenshot directory (0700) contain account/chat/run data and screenshot artifacts. Do not copy these into Git or a handoff ZIP.
- `~/.config/labpilot-portal/instance-allowlist.private.json` must be an owner-owned, 0600 file listing exactly three pinned EC2 IDs for each of `dam-standalone` and `dam-mxha`, **in the source-defined component order**. The runtime checks all six IDs and exact Name tags before any start/stop. This is an operator-managed private configuration, **not an invitation to invent IDs or paste them into documentation**. If it is absent or mismatched, action availability is blocked.
- Initial owner bootstrap credentials, if present on an existing host, stay in its private operator store. Never include them in a README, issue, screenshot, GitHub secret example or chat. The website-login vault belongs to the host Hermes profile and is shared by all full-host admins.

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
