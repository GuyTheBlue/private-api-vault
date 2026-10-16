# CipherGate

Terminal API-key vault for the Gsquared Productions fleet.

The logo is a **keyhole with a bar through it** — nothing gets past until the
gate (Batman) opens it. That's the whole point: keys stay locked, every call
waits on the gate.

Holds API keys encrypted, keeps a signed access map (profile -> hash of its
.env key), tracks active leases, keeps an audit ledger, and — when allowed —
decrypts a key internally and makes the HTTPS call itself, returning only
the result. A key is never handed to an agent, never written mid-session,
never shown, never returned by the API.

## Install (once) — then run the bare `ciphergate` command

```bash
pipx install git+https://github.com/GuyTheBlue/private-api-vault
ciphergate --help
```

[pipx](https://pipx.pypa.io/) is the standard way to install a standalone
Python CLI: it puts `ciphergate` on your PATH and keeps it in its own
environment, so it can't clash with anything else you have installed.

Prefer uv? Same thing, different installer:

```bash
uv tool install git+https://github.com/GuyTheBlue/private-api-vault
```

Try it without installing anything:

```bash
pipx run git+https://github.com/GuyTheBlue/private-api-vault --help
```

First run — set the passphrase and mint the off-site recovery key:

```bash
ciphergate init
```

**Windows:** use the installed `ciphergate` command — but CipherGate encrypts
by shelling out to `openssl`, and Windows does not ship openssl, so it fails at
the first key it tries to store. The straightforward path is **WSL**, a Linux
environment, where Python and openssl both exist. (`python3` usually does not
exist on Windows either; for the no-install route in CMD/PowerShell, use
`py ciphergate.py <cmd>` — same openssl caveat.)

## No-install fallback

Nothing to install? Clone the repo and run the file directly (PEP 394 form —
`python3`, never bare `python`):

```bash
git clone https://github.com/GuyTheBlue/private-api-vault.git
cd private-api-vault
python3 ciphergate.py init
python3 ciphergate.py list
```

Run the file from the repo folder and it uses the `.vault/` next to it.

## Where the vault lives

The store is a `.vault/` folder. CipherGate looks for it in this order:
`$VAULT_DIR`, then `.vault` beside the program, then `.vault` in the folder you
are standing in (or the nearest one up the tree). If none exists it creates
`.vault` in the current folder. So `ciphergate list` run from your vault folder
just works; elsewhere, point it there:

```bash
VAULT_DIR=~/my-vault/.vault ciphergate list
```

## Commands (all terminal)

```
ciphergate init                              first run: set passphrase, mint off-site recovery key
ciphergate add  <service>                    store an encrypted key
ciphergate list                              names only, never values
ciphergate keygen <profile>                  mint a .env key for a profile (shown once)
ciphergate access list|add|remove            manage .env-key map (passphrase)
ciphergate request <method> <url> <mins> <reason>   run the decision gate (identity from env)
ciphergate pending                           show staged requests (passphrase)
ciphergate decide <req_key> yes|no|other [msg]   Batman's verdict (terminal alternative to Telegram)
ciphergate resolve <req_key>                 agent returns and picks up the verdict
ciphergate call <method> <url> [--header "Name:[key_name]"] [--data <json>]  substitute+send (test only)
ciphergate lease                             active leases (passphrase)
ciphergate ledger                            audit history (read-only)
ciphergate recover                           set new passphrase via off-site recovery key
ciphergate update                            change the passphrase (needs current pass; recovery key survives)
ciphergate status                            state overview
```

The decision gate (`request`) first verifies WHO is knocking: the running
profile (from HOME env) must present a `.env` key registered to it — no key,
or flashing another profile's key (ACCESS SNEAK), is denied and logged.
Every request is then classified for sensitivity: credential/admin/token-mint
endpoints are a hard NO-USE (refused outright, even under a live lease), and
account/billing/team calls are FLAGGED for Batman before approval. A clean
request flows to the lease check, then is staged with a unique key and handed
to Batman. The agent returns with that key (`resolve`) to pick up the verdict.
Telegram buttons carry the live approvals; `decide` is the terminal stand-in.

## Security model
- Keys are ciphertext at rest (`.vault/` is gitignored — never pushed).
- access.json + leases.json are HMAC-signed with the passphrase, so a direct
  edit or delete FAILS CLOSED (tamper detected) instead of silently resetting.
- Passphrase (or macOS Keychain, later) + an off-site recovery key are the
  two pieces that can unwrap; neither sits in the repo.
- Only the program touches plaintext keys, and only inside a single call.

## Files
- `ciphergate.py` — the program (installs as the `ciphergate` command)
- `pyproject.toml` — packaging: the console-script entry point that gives you
  `ciphergate`
- `access.json` — profile -> hash of its .env key (signed, under `.vault/`)
- `.vault/` — encrypted store, signed access/lease/pending, ledger (**never committed**)
- `regression.sh` — automated regression suite (no real keys, isolated scratch)
- `stub_endpoint.py` — local HTTP echo server to test the call path with no live API

## Tests
Run `bash regression.sh` after any change — verifies encryption at rest,
the identity gate (no key / ACCESS SNEAK), tamper fail-closed, lease purge,
the sensitivity gate (no-use / flag), and no plaintext anywhere.

## Licence
MIT — see [`LICENSE`](LICENSE). The software comes **as is**, with no warranty
of any kind: use it, ship it, just keep the copyright notice with it.
