# private-api-vault

Terminal API-key vault for the Gsquared Productions fleet.

Holds API keys encrypted, keeps a tamper-evident deny list, tracks active
leases, keeps an audit ledger, and — when allowed — decrypts a key
internally and makes the HTTPS call itself, returning only the result. A
key is never handed to an agent, never written mid-session, never shown,
never returned by the API.

## Commands (all terminal)

```
python3 vault.py init                              first run: set passphrase, mint off-site recovery key
python3 vault.py add  <service>                    store an encrypted key
python3 vault.py list                              names only, never values
python3 vault.py deny list|add|remove              manage the ONE deny list (passphrase)
python3 vault.py request <agent> <http> <expiry_min> <reason>   run the decision gate
python3 vault.py lease                             active leases (passphrase)
python3 vault.py ledger                            audit history (read-only)
python3 vault.py recover                           set new passphrase via off-site recovery key
python3 vault.py status                            state overview
```

The decision gate (`request`) checks the deny list first, then a live
lease; only a clean request is handed to Batman for a sign-off.

## Security model
- Keys are ciphertext at rest (`.vault/` is gitignored — never pushed).
- deny.json + leases.json are HMAC-signed with the passphrase, so a direct
  edit or delete FAILS CLOSED (tamper detected) instead of silently resetting.
- Passphrase (or macOS Keychain, later) + an off-site recovery key are the
  two pieces that can unwrap; neither sits in the repo.
- Only the program touches plaintext keys, and only inside a single call.

## Files
- `vault.py` — the program
- `deny.json` — ONE blanket deny list (signed, under `.vault/`)
- `.vault/` — encrypted store, signed deny/lease, ledger (**never committed**)
- `regression.sh` — automated regression suite (no real keys, isolated scratch)

## Tests
Run `bash regression.sh` after any change — verifies encryption at rest,
the deny gate, tamper fail-closed (edit + delete), lease purge, and no
plaintext anywhere. Full plan + status in `TODO.md`.