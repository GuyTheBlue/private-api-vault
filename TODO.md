# private-api-vault — BUILD PLAN (source of truth)
# Consolidated from QUESTIONS.md answers. Design locked. Real keys NOT loaded.
# Checkboxes: [x] = built + verified. Updated as reality changes — a stale plan
# misleads every agent, so keep this current before starting anything.

## THE DESIGN IN ONE PARAGRAPH
The vault (aka "secure api proxy") holds every secret ENCRYPTED. Agents
never hold a key. To make any API call an agent sends a request
{http, reason, expiry} to the vault; the vault checks the deny list, then
an active lease, then — only if needed — asks Batman on Telegram. On a YES
it swaps the held secret into the request string and sends it, returning
the HTTP result. Secrets never leave, never log, never return to an agent.

## STATUS (accurate as of 2026-09-25)
- STAGE 1 (data model + store + decision gate): DONE, verified by `regression.sh`.
- STAGE 2 (decision loop: pending index, variable wait, telegram-stub verdicts, resolve): DONE, verified.
- STAGE 3 (agnostic substitute+send, verified against local stub): DONE, verified.
- STAGES 4-6 + MIGRATION: NOT STARTED.
- Real keys NOT loaded.
- Regression suite: `regression.sh` - 16 checks, all passing. EXTEND IT for
  every stage below before marking that stage done.

========================================================
## BUILD STAGES (in order)
========================================================

### STAGE 1 — DATA MODEL + STORE + DECISION GATE  ✅ DONE
- [x] deny list: ONE blanket list. Agents on it = denied, reason given.
      Seeded with `robin`. Only Batman (passphrase) edits via `deny`.
- [x] deny list is TAMPER-EVIDENT: HMAC-signed with the passphrase. Direct
      edit OR delete -> TAMPER DETECTED, fail-closed (agent DENIED). Robots
      running as the same user can't forge (no passphrase).
- [x] request record shape: {http, reason, expiry}. expiry 0 = no lift,
      1+ = minutes requested.
- [x] decision gate (`request <agent> <http> <expiry> <reason>`):
      deny list first -> live lease -> else stage a UNIQUE request key + ask
      Batman. NO pass-through.
- [x] lease file: ACTIVE grants only; entry purged the moment it expires
      (file never grows). Live lease short-circuits -> Batman not asked.
- [x] ledger: append-only history with a unique request key per pending ask.
      Secrets NEVER in the ledger.
- [x] encrypted key store (AES-256) + off-site recovery key.
- [x] no plaintext in keys/deny/leases/ledger (regression-checked).

### STAGE 2 — FINISH THE DECISION LOOP  ✅ DONE
- [x] PENDING index: staged requests keyed by a unique request key, signed
      like the deny/lease files (tamper-evident, fail-closed on edit/delete).
- [x] variable wait window (env `VAULT_WAIT_MIN`, default 5 min) so short
      timeouts make testing instant instead of waiting on a clock.
- [x] TELEGRAM STUB for now: `decide <req_key> yes|no|other [msg]` stands in
      for Batman's button answer so index/lookup logic is testable with no
      live Telegram. Real buttons land in Stage 5.
- [x] resolve <req_key>: agent returns with the key; vault looks it up.
      pending+in-window -> come back later; pending+past-window -> not
      approved; yes -> create lease + call; no -> deny; other -> deny +
      Batman's message verbatim to the agent.
- [x] regression.sh 11-15 cover stage/pending/decide/resolve for all verdicts.
- [x] account: `update` changes the passphrase (old dead, new live) while the
      recovery key keeps working — add_key was re-keying BADLY (minted a new
      data key, orphaning the recovery escrow); fixed with `rekey_passphrase`
      that re-wraps ONLY the passphrase layer. Covered by regression 17.

### IDENTITY — who is knocking? (.env keys + HOME env)  ✅ built
- SIMPLIFIED (Batman): NO deny list, NO robin special-casing. The program is
  generic. Vault decides WHO purely from HOME env (HERMES_HOME -> who's
  running) + the .env key it presents.
- `keygen <profile>` (Batman) mints a .env key; vault stores its HASH in
  .vault/access.json (signed like lease/pending). Plaintext shown once.
- `access list|add|remove` manages the map under the passphrase.
- `request` REQUIRES VAULT_AGENT_KEY + HERMES_HOME. A profile with no key
  (robin is simply never issued one) owns nothing in the list and can't pass;
  flashing another profile's key -> ACCESS SNEAK, denied + logged.
- `request` signature is now `request <http> <expiry_min> <reason>` - agent
  identity is DERIVED from the environment, never claimed as an argument.
- Deny list REMOVED (overkill). Robin handled purely by "never given a key".
- Covered by regression 3-5.

### STAGE 3 — THE CALL (agnostic substitute + send)  ✅ DONE
- [x] vault `call <method> <url> [--header 'Name:[key_name]'] [--data <json>]`:
      caller supplies the FULL request; vault swaps each [key_name] for the
      held secret, sends as-is, returns the raw response. Provider-agnostic —
      vault does NOT know fal/DO/Bearer (that was the old Bearer-only path).
- [x] verified against stub_endpoint.py (local HTTP stub): secret substituted
      into header AND body, endpoint sees the real value, nothing leaks to disk.
- [x] stub_endpoint.py added: local echo server for testing the call path with
      no live API / no real key.
- [x] regression.sh 16 covers substitute+send vs the stub; all pass.

### STAGE 4 — ACCESS / API
- [ ] Agents: read-only API only. Can LIST key NAMES (never secrets), view
      ledger, view lease status. Cannot edit anything.
- [ ] Batman: login-gated. See/update/remove secrets, edit deny list, view
      full ledger + lease file.
- [ ] agents CANNOT: edit deny list, set/approve own lease, approve self,
      read secret values, modify ledger/lease files directly.
- [ ] regression.sh: add read-only-vs-batman boundary tests.

### STAGE 5 — TELEGRAM SIGN-OFF (Batman)
- [ ] ask goes to Batman's Telegram (buttons: YES / NO / other). NEVER
      terminal input.
- [ ] NO = batman_said_no. OTHER = always denied + Batman's typed message
      relayed verbatim to the agent.
- [ ] silent -> timeout behavior (Stage 2) kicks in.
- [ ] regression.sh: add a verdict-resolution test (mock YES/NO/other).

### STAGE 6 — protect on boot
- [ ] macOS Keychain auto-unlock so no passphrase typing each session.

================================================================
## MIGRATION (AFTER it's proven working — needs Batman present)
- [ ] load real keys into the encrypted store.
- [ ] verify end-to-end: log in, see secrets, update, make a real call.
- [ ] only WHEN satisfied: delete the plaintext secrets from keykeeper/.env.

================================================================
## IRON RULES
- Secrets NEVER: returned by the API, logged, written to ledger/lease,
  or left on an agent's disk. Encrypted at rest; in memory for one call.
- No pass-through. Every grant needs Batman (unless a live lease covers it).
- Agents cannot self-approve, self-lease, self-deny or read secrets.
- No SQL. Simple files: append-only ledger + purge-on-expiry lease list.
- Vault alone writes. Everything reads through the vault API.
- Real-key steps need Batman present + explicit go.
- A stage is done only when `regression.sh` covers it and passes.