# private-api-vault — BUILD PLAN (source of truth)
# Consolidated from QUESTIONS.md answers. Design locked. Real keys NOT loaded.

## THE DESIGN IN ONE PARAGRAPH
The vault (aka "secure api proxy") holds every secret ENCRYPTED. Agents
never hold a key. To make any API call an agent sends a request
{http, reason, expiry} to the vault; the vault checks the deny list, then
an active lease, then — only if needed — asks Batman on Telegram. On a YES
it swaps the held secret into the request string and sends it, returning
the HTTP result. Secrets never leave, never log, never return to an agent.

## STATUS
Encrypted store, rules gate, recovery, old Bearer-only call: WORKING (built).
Everything below matching THIS design: NOT BUILT YET.

========================================================
## BUILD STAGES (in order)
========================================================

### STAGE 1 — DATA MODEL + STORE
- [ ] deny list: ONE blanket list. Agents on it = denied, reason given.
      Field per entry: agent, reason. Seeded with `robin`. Stored in vault
      store JSON (not repo). Only Batman (via login) edits.
- [ ] request record shape: {http, reason, expiry}
      - expiry 0 = no lift requested (default)
      - expiry 1+ = minutes the agent asks to keep this active
- [ ] ledger: append-only history. Each entry gets a UNIQUE request key.
      Fields: unique_key, agent, service/key, request http, action taken,
      verdict, timestamp. Secrets NEVER in the ledger.
- [ ] lease file: ACTIVE grants only. Fields: unique_key, agent, api key,
      expiry timestamp. Entry DELETED on expiry so the file never grows.

### STAGE 2 — THE DECISION LOGIC (the vault's one job)
- [ ] agent request  -> 1. deny list? on it -> DENY with reason (stop).
- [ ] 2. lease file? active + unexpired lease for agent+key -> make the
      call, return result (Batman NOT bothered). time up? purge entry.
- [ ] 3. no lease -> log to ledger with UNIQUE request key -> ask Batman.
- [ ] timeout: if Batman silent ~1 min -> tell agent "come back no sooner
      than 5 minutes" + hand the unique key. Agent returns later with it;
      vault looks it up: YES->call, NO->deny, pending->re-issue key.
- [ ] verdicts: YES -> create lease (respect requested expiry or grant),
      make call, return result. NO -> deny, reason "Batman said no".
      OTHER -> deny, BUT pass Batman's message verbatim to the agent.
- [ ] lease expiry reached -> purge entry -> next request asks Batman fresh.

### STAGE 3 — THE CALL (agnostic)
- [ ] agent hands the full request string with [key_name] placeholders.
- [ ] vault decrypts the named secret(s), swaps each into the string,
      sends as-is, returns the HTTP response. Does NOT parse the result.
- [ ] vault is lazy about the outcome: a bad response is the agent's
      problem to fix and retry. Vault only returns what the endpoint said.
- [ ] key values exist only in that one call's memory; never logged,
      never returned, never written to any file.

### STAGE 4 — ACCESS / API
- [ ] Agents: read-only API only. Can LIST available keys (names, NOT
      secrets), view ledger, view lease status. Cannot edit anything,
      cannot request beyond the {http, reason, expiry} shape.
- [ ] Batman: login-gated. Can see/update/remove secrets, edit deny list,
      view full ledger + lease file.
- [ ] agents CANNOT: edit deny list, set/approve their own lease, approve
      themselves, read secret values, modify ledger/lease files directly.

### STAGE 5 — TELEGRAM SIGN-OFF (Batman)
- [ ] ask goes to Batman's Telegram (buttons: YES / NO / other). Never
      terminal input.
- [ ] NO = batman_said_no. OTHER = always denied + Batman's typed message
      relayed verbatim to the agent.
- [ ] silent -> timeout behavior (Stage 2) kicks in.

### STAGE 6 — protect on boot
- [ ] macOS Keychain auto-unlock so no passphrase typing each session.

================================================================
## MIGRATION (AFTER it's proven working — needs Batman present)
- [ ] load real keys into the encrypted store.
- [ ] verify end-to-end: log in, see secrets, update, make a real call.
- [ ] only WHEN satisfied: delete the plaintext secrets from keykeeper/.env.

========================================================
## IRON RULES
- Secrets NEVER: returned by the API, logged, written to ledger/lease,
  or left on an agent's disk. Encrypted at rest; in memory for one call.
- No pass-through. Every grant needs Batman (unless a live lease covers it).
- Agents cannot self-approve, self-leasе, self-deny or read secrets.
- No SQL. Simple files: append-only ledger + purge-on-expiry lease list.
- Vault alone writes. Everything reads through the vault API.
- Real-key steps need Batman present + explicit go.