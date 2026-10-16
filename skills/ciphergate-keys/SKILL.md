---
name: ciphergate-keys
description: Use when a job needs a service key. CipherGate is the vault gate — agents ask, the gate decides, keys never leave. Install once, then request keys via the gate, never read raw values.
---

# CipherGate — the key-vault gate

CipherGate is a single Python file (ciphergate.py, ~93 KB) that holds API keys encrypted and makes the calls for you. You never see a raw key. You ask the gate, the gate checks who you are, what you want, and whether it is allowed. If yes, the gate makes the call and hands you the result. If no, it tells you why and logs it.

That is the whole point: keys stay locked, every call waits on the gate.

## Install it (once)

CipherGate runs on macOS or Linux. It needs Python 3 and the `openssl` command (already on macOS and most Linux). Nothing else to install — no pip, no database, no daemon.

Install it as a command, then run it by name:

```bash
pipx install git+https://github.com/GuyTheBlue/private-api-vault
ciphergate --help

# First run: set the passphrase and mint the off-site recovery key
ciphergate init
```

(`uv tool install git+https://github.com/GuyTheBlue/private-api-vault` does the same job; `pipx run git+...` runs it once without installing.)

No-install fallback — the file runs straight from a clone (PEP 394 form, `python3`, run from the repo folder so it finds the `.vault/` beside it):

```bash
git clone https://github.com/GuyTheBlue/private-api-vault.git
cd private-api-vault
python3 ciphergate.py init
```

Every command in this skill is written as the bare `ciphergate <cmd>`. Wherever you see that, the fallback is `python3 ciphergate.py <cmd>` (Windows: the installed `ciphergate` command, or `py ciphergate.py <cmd>` — `python3` usually does not exist there).

The store is a `.vault/` folder; CipherGate looks for it in `$VAULT_DIR`, then beside the program, then in the folder you are standing in (or the nearest one up the tree).

The passphrase unlocks the vault. The recovery key is printed once — print it, put it somewhere safe off-site (a password manager, a safe deposit box, a trusted human). Lose both, lose the vault. That is the safety we chose.

## How an agent uses it (the request/lease flow)

You are a Hermes agent. You need to call an API that requires a key. You do not have the key. You ask the gate.

### Step 1 — present your keypass

When your profile was set up, you were given a `.env` key (a keypass). It is a string like `CG_KEYPASS_abc123...`. You present it to prove who you are. The gate hashes it and checks the access map (access.json) to see which profile owns it. No keypass, or flashing someone else's — ACCESS SNEAK — is a hard no.

### Step 2 — make the request

```bash
ciphergate request <method> <url> <expiry_min> <reason> \
  [--keys k1,k2] \
  [--header "Name:[key_name]"] \
  [--data <json>] \
  [--timeout <secs>]
```

- `<method>` — GET, POST, PUT, DELETE, etc.
- `<url>` — the full API endpoint you want to call
- `<expiry_min>` — how many minutes you need the lease for (short is better)
- `<reason>` — why you need it (written to the ledger)
- `--keys k1,k2` — which stored keys this call needs (e.g. `openai,anthropic`)
- `--header "Authorization:[openai]"` — substitute `[openai]` with the stored key value in the header
- `--data <json>` — the request body
- `--timeout <secs>` — how long to wait for the response

The gate then runs four checks:

1. **Identity** — who are you? (via the keypass)
2. **Sensitivity** — is this a credential/admin/token-mint endpoint? (hard no, even under a live lease)
3. **Lease** — do you already have a valid lease for this key + endpoint?
4. **Verdict** — if no lease, the request is staged with a unique key and handed to Batman (the human) for approval

### Step 3 — wait for the verdict (if needed)

If the gate needs human approval, it returns a request key (a unique ID). You call `resolve` to pick up the verdict:

```bash
ciphergate resolve <request_key>
```

The gate tells you: yes (lease granted) or no (denied, with the reason). Every decision is logged.

### Step 4 — the call happens (if approved)

If the lease is granted, the gate makes the call internally. It substitutes the key names in your headers/data with the real values (which you never see), sends the request, and returns the HTTP result to you. The lease is short-lived and narrow: this key, this endpoint, this expiry. When it expires, it is purged.

## What you MUST NOT do

- **Never read raw keys.** You do not have access to the `.vault/` directory, the `keys.json` file, or any plaintext. Do not try to read it. Do not try to decrypt it. The gate holds the keys; you hold the request.
- **Never bypass the gate.** Do not try to call the API directly. Do not try to extract the key from the process memory. Do not try to guess the passphrase. The gate is the only path.
- **Never log the keypass.** The keypass is presented once per session (via environment or secure prompt). Do not write it to a file, do not echo it, do not include it in a log. It is your identity, not a secret to be shared.
- **Never ignore a refusal.** If the gate says no, it logs the reason. Do not retry with a different profile, a different keypass, a different endpoint. The ledger is append-only; every attempt is recorded.

## What the gate does (so you understand the logic)

The gate's job is to say "fuck off" (with the reason) or "here is the HTTP result". It never hands you a key.

1. Who asked? (identity via keypass)
2. Is this allowed for this profile + request? (sensitivity check)
3. Is there a valid lease? (if yes, make the call)
4. If no lease, ask Batman (the human) for permission
5. Batman's answer: yes (grant a short lease, make the call) or no (refuse, log it)

Every decision is written to the ledger. The ledger is append-only. The vault is encrypted at rest. The `.vault/` directory is gitignored — it is never committed.

## Commands (for reference)

You will mostly use `request` and `resolve`. The others are for the vault owner (Batman):

- `init` — first run, set passphrase, mint recovery key
- `add <service>` — store an encrypted key (Batman only)
- `list` — names only, never values
- `keygen <profile>` — mint a .env keypass for a profile (shown once)
- `access list|add|remove` — manage the keypass map (passphrase required)
- `request <method> <url> <expiry_min> <reason>` — the gate (you use this)
- `pending` — staged requests waiting on Batman (passphrase required)
- `decide <req_key> yes|no|other [msg]` — Batman's verdict (passphrase required)
- `resolve <req_key>` — pick up the verdict (you use this)
- `call <method> <url>` — test/regression only, skips all gates (do not use)
- `lease` — active leases (passphrase required)
- `ledger` — audit history (read-only)
- `recover` — set new passphrase via recovery key
- `update` — change the passphrase (needs current pass)
- `status` — state overview

## The point

You are an agent. You need keys to do your job. The gate holds the keys. You ask, the gate decides, you get the result. Keys never leave the vault. Every call is logged. Every refusal is logged. The ledger is the record; the vault is the safe; the gate is the door.

That is the whole system.
