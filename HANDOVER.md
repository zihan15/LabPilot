# LabPilot portal: handover for Hermes users

This is a **private, vibe-coded proof of concept**, not a Hermes plugin, a production multi-tenant service, or an end-to-end DAM test executor. The published repository contains reviewed source and documentation; a working portal also needs a separately configured Hermes host, private accounts, optional AWS access, an installed domain skill, and operator-controlled lab state. Start with [README.md](README.md), [ARCHITECTURE.md](ARCHITECTURE.md), [USER-GUIDE.md](USER-GUIDE.md), and [DEPLOYMENT.md](DEPLOYMENT.md).

## 1. What exists, and where the private data is

The published source is `zihan15/LabPilot` on GitHub. On the pilot host, the portal checkout is an operator-managed local directory; the HTTP service binds **only** `127.0.0.1:8090`. A GitHub checkout is not a copy of the running lab.

| Host location | Contents and handover rule |
| --- | --- |
| `~/.local/share/labpilot/portal.sqlite` | Account records, password hashes, login sessions, conversations, agent runs/retained steps, activity, environment requests, file metadata and skill proposals. Private 0600 database; **never** publish, email or copy into a fresh installation by default. |
| `~/.local/share/labpilot/portal-artifacts/` | Private per-run browser PNGs. Access through the portal's owner-checked route; do not treat them as cleared demo images. |
| `~/.local/share/labpilot/uploads/` | Admin-uploaded, UUID-named installer/patch blobs. The SQLite file table supplies names and SHA-256. Back up database and blobs together only with owner approval; do not execute or publish them. |
| `~/.config/labpilot-portal/instance-allowlist.private.json` | Owner-only pin set for **existing** EC2 instances. Contains private resource identifiers; not part of Git. |
| `~/.config/labpilot-portal/bootstrap-admin.private` (if present) | Initial operator credential material on this pilot host. **Do not distribute or reproduce its contents.** New installations create new accounts. |
| `$HERMES_HOME` (or `~/.hermes`) | Host model/provider configuration, vault/auth state, sessions and installed skills; the portal's approved Imperva lessons are written under `skills/cybersecurity/imperva-troubleshooting/`. These are outside the Git repository and may be shared by other full-host Hermes users. |

The pilot's local `screenshots/overview-desktop.png` and `screenshots/overview-mobile.png` are **not in the published GitHub snapshot**. The desktop image contains a portal username and both show observed lab state, so neither is cleared for public sharing. Review any proposed video or screenshot frame by frame before adding it to the demo.

## 2. Choose the safe scope before installation

- **Local UI and requests** need Python, Pillow and a portal account. They do not require copying the pilot database.
- **Agent chat** needs a working `hermes` CLI/model/provider under the **server process's OS identity**. Admin conversations preload the installed `imperva-troubleshooting` skill; install and review a legitimate copy in that same Hermes profile if you want that behavior. The repository does not ship the pilot host's installed skill, private vault or model credentials.
- **AWS inventory** requires the intended AWS CLI identity and the source's fixed region, known EC2 Name tags and MXHA stack names. **Start/stop** additionally requires an operator-created 0600 pin file with the two exact source-defined lab keys and three matching instance IDs per lab in component order. The app refuses mismatches; never invent IDs or weaken the check to make a button appear.
- **Full admin chat** runs Hermes with the host toolset and inherits the server user's filesystem, vault and effective cloud permissions. A portal `admin` account is therefore a **trusted host/cloud operator**, not just a UI administrator. Non-admin portal sessions and run history are inaccessible, but the optional typed DB-planning worker still shares the host OS identity and is not an OS/IAM sandbox. Do not give untrusted teammates accounts on this shared-identity host.
- **Other products or labs:** change the fixed lab IDs, component map, expected Name tags, stack labels, region/filter logic, pin-file contract and associated tests together. This checkout is deliberately **not** a generic AWS discovery or arbitrary-instance control panel. Do not reuse the pilot's licenses, credentials, pins or cloud resources without fresh authorization.

The [Hermes documentation](https://hermes-agent.nousresearch.com/docs/) covers model/provider and skill setup; its [messaging guide](https://hermes-agent.nousresearch.com/docs/user-guide/messaging) covers Telegram, Slack and WhatsApp. A messaging gateway's user authorization, tools and conversation history are **separate** from the LabPilot portal. Connecting Hermes to a chat platform does not expose this portal there or inherit its roles and review gates.

## 3. Reproduce a private source-only pilot

On an **approved, isolated host**, use a fresh checkout and new private state. Do not run these commands on the current shared host as a second portal instance without an operator plan.

```sh
git clone https://github.com/zihan15/LabPilot.git
cd LabPilot
python -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
python -m unittest -q test_portal test_features
node --test test_ui.mjs          # optional Node.js UI tests
node --check static/app.js       # optional syntax check
python server.py create-user --username operator --role admin
python server.py serve --port 8090
```

`create-user` prompts interactively for a new 16+ character password; do not put it on the command line or in chat. Create additional users as **tester** by default. Confirm `GET http://127.0.0.1:8090/api/health` returns 200 and that the listener is **127.0.0.1 only**; health is not an AWS, model or product check. Reach it from a trusted workstation through an authenticated SSH/SSM tunnel. For example, forward an unused *local* port to the host's loopback port:

```sh
ssh -N -o ExitOnForwardFailure=yes -L 127.0.0.1:18090:127.0.0.1:8090 <approved-user>@<approved-host>
```

Then browse `http://127.0.0.1:18090`. The workstation must have its own approved SSH authentication; do not copy the pilot host's private keys. Keep the tunnel open. Do **not** bind the service to `0.0.0.0`, open an inbound web port or assume password login is sufficient for Internet exposure.

Before enabling live AWS actions, have an authorized operator check the host identity, exact Name tags, pin-file ownership/mode, region, budget and workload impact. Tests mock cloud/agent effects and do not authorize a live start/stop. For a different lab, adapt the source and tests instead of copying this host's private pin file.

## 4. Implementation map for another Hermes developer

- `server.py`: threaded loopback HTTP server, static allowlist, SQLite migrations/store, account/session/CSRF checks, private files and screenshots, AWS observation/pinned EC2 control, and the `hermes chat` subprocess bridge. `static/index.html`, `static/app.js` and `static/operate.css` provide the UI; `ARCHITECTURE.md` documents the boundaries.
- Each admin portal message starts its **own** bounded `hermes chat --query-file - --format stream-json` process. Admin turns preload `imperva-troubleshooting`, use full tools and may resume their *own* linked Hermes CLI history. Non-admin agent sessions are disabled; historical advisory conversations are read-only to owners promoted to admin. The code parses tool events into **sanitized summaries**, not raw output. One active run per admin; logout/role revocation checks cancel the privileged process group, but cannot undo a cloud call already issued.
- **Activity** shows at most 100 retained steps per run, allowlisted commands only, and an owner-only session link. Other admins see run metadata and aggregate retained tool-attempt/error counts, not another person's chat, commands, output or screenshot. A tool attempt or returned event is not proof of a successful side effect.
- **Requests** are typed and pending human decisions. Approval alone launches nothing. An approved standalone MX ticket offers the assigned admin an **unsent launch-authorization draft**; sending it can incur cloud charges. MXHA and database tickets offer planning drafts only. The portal does not enforce expiry/spend or perform automatic teardown. The database advice worker selects a clarification from a bounded list; it does not validate exact DB/OS/Agent compatibility or download entitlement.
- **Files** are admin-only untrusted exchange: 256 MiB per upload and 1 GiB total, private UUID storage, digest-checked download. There is no malware scanning, vendor-signature verification, auto-installation, delete UI or retention job.
- **Skills**: an admin requests a private draft from an owned full-mode session, previews and explicitly submits it; a *different* active admin reviews/edits it before publication to the installed host skill. Non-admins can view earlier proposals and discard their private drafts, but cannot generate or submit new ones. Model-generated claims and citations are not independent vendor evidence. Do not silently install a draft or make the publication directory writable by untrusted users.

## 5. Acceptance and handover checks

1. **Source:** inventory the exact repository tree and dependencies; run both Python and Node suites plus `node --check static/app.js` and `git diff --check`. Review new static assets and pixels before adding any media.
2. **Identity:** create two disposable accounts on an isolated test instance (owner/tester and separate trusted admin). Verify login, CSRF, ownership, disabled-user revocation, self-approval denial, cross-user step/screenshot denial and tester file denial. All trusted admins share the private Files catalog. Do not use the pilot's live accounts as fixtures.
3. **Agent bridge:** with a harmless request, verify the server process can launch the installed Hermes CLI, receives a real `stream-json` result, attributes the run and respects the configured limits. Verify logout/demotion during a run. Never interpret a mocked test as a live AWS or DAM check.
4. **AWS boundary:** first test inventory read-only. Only with explicit lab-owner authorization, verify the exact pin/tag mapping and a narrowly scoped start/stop; check EC2 state after action. Do not grant testers broad AWS or host-shell access to compensate for missing instance brokers.
5. **Persistence:** verify SQLite/file ownership and backups privately; check orphaned-upload recovery, file hash rejection and proposal-publication reconciliation on restart. Back up approved skill references separately from the source checkout. Never include runtime files, pins, vault/auth data or screenshots in a public bundle.
6. **Demo:** record a synthetic/non-secret or explicitly cleared session, inspect every captured frame and audio track, remove names/IDs/private URLs/cloud state not approved for publication, then add only reviewed media. A repository README link to `127.0.0.1` works only after a tunnel and is not a public demo URL.

## 6. Gaps before team-wide or public access

Separate OS identities and scoped IAM for advisory versus privileged workers; enforced broker approvals for cloud writes; HTTPS, SSO/MFA and audit retention; network/IMDS restrictions; independent spend/expiry/cleanup controls; actual DB/OS/Agent coverage validation and entitled-media checks; a tested product/SQL evidence path; and malware/signature handling for uploads. Until then, keep the portal loopback-only with a small set of explicitly trusted operators. The present proof of concept is useful for demonstrating a workflow, **not** as a security boundary for arbitrary teammates.
