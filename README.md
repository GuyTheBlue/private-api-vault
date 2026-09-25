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

## Commands (all terminal)

```
python3 ciphergate.py init                              first run: set passphrase, mint off-site recovery key
python3 ciphergate.py add  <service>                    store an encrypted key
python3 ciphergate.py list                              names only, never values
python3 ciphergate.py keygen <profile>                  mint a .env key for a profile (shown once)
python3 ciphergate.py access list|add|remove            manage .env-key map (passphrase)
python3 ciphergate.py request <http> <expiry_min> <reason>   run the decision gate (identity from env)
python3 ciphergate.py pending                           show staged requests (passphrase)
python3 ciphergate.py decide <req_key> yes|no|other [msg]   TELEGRAM STUB: set Batman's verdict
python3 ciphergate.py resolve <req_key>                 agent returns and picks up the verdict
python3 ciphergate.py call <method> <url> [--header "Name:[key_name]"] [--data <json>]  substitute+send
python3 ciphergate.py lease                             active leases (passphrase)
python3 ciphergate.py ledger                            audit history (read-only)
python3 ciphergate.py recover                           set new passphrase via off-site recovery key
python3 ciphergate.py update                           change the passphrase (needs current pass; recovery key survives)
python3 ciphergate.py status                            state overview
```

The decision gate (`request`) first verifies WHO is knocking: the running
profile (from HOME env) must present a `.env` key registered to it — no key,
or flashing another profile's key (ACCESS SNEAK), is denied and logged.
Every request is then classified for sensitivity: credential/admin/token-mint
endpoints are a hard NO-USE (refused outright, even under a live lease), and
account/billing/team calls are FLAGGED for Batman before approval. A clean
request flows to the lease check, then is staged with a unique key and handed
to Batman. The agent returns with that key (`resolve`) to pick up the verdict.
While Telegram buttons land in Stage 5, `decide` stands in for Batman's answer
so the index/lookup logic is testable instantly (no live wait).

## Security model
- Keys are ciphertext at rest (`.vault/` is gitignored — never pushed).
- access.json + leases.json are HMAC-signed with the passphrase, so a direct
  edit or delete FAILS CLOSED (tamper detected) instead of silently resetting.
- Passphrase (or macOS Keychain, later) + an off-site recovery key are the
  two pieces that can unwrap; neither sits in the repo.
- Only the program touches plaintext keys, and only inside a single call.

## Files
- `ciphergate.py` — the program
- `access.json` — profile -> hash of its .env key (signed, under `.vault/`)
- `.vault/` — encrypted store, signed access/lease/pending, ledger (**never committed**)
- `regression.sh` — automated regression suite (no real keys, isolated scratch)
- `stub_endpoint.py` — local HTTP echo server to test the call path with no live API

## Tests
Run `bash regression.sh` after any change — verifies encryption at rest,
the identity gate (no key / ACCESS SNEAK), tamper fail-closed, lease purge,
the sensitivity gate (no-use / flag), and no plaintext anywhere. Full plan
+ status in `TODO.md`.