# private-api-vault

Terminal API-key vault for the Gsquared Productions fleet.

Holds API keys **encrypted** (AES-256-CBC). Applies rules, keeps a ledger,
and — when allowed — decrypts a key **internally** and makes the HTTPS call
itself, returning only the result. **A key is never handed to an agent, never
written mid-session, never shown.**

## Commands (all terminal)

```
python3 vault.py init       first run: set passphrase, mint off-site recovery key
python3 vault.py add  <svc> store an encrypted key
python3 vault.py list       names only, never values
python3 vault.py allow <svc> <agent> [reason]   decide/grant per rules
python3 vault.py call  <svc> <url>    decrypt + https call internally
python3 vault.py recover  set new passphrase via off-site recovery key
python3 vault.py ledger    the audit
python3 vault.py status    state overview
```

## Security model
- Keys are ciphertext at rest (`.vault/` is gitignored — never pushed).
- Passphrase (or macOS Keychain) + an **off-site recovery key** are the two
  pieces that can unwrap; neither sits in the repo.
- Only the program touches plaintext keys, and only inside a single call.

## Files
- `vault.py` — the program
- `rules.json` — policy (created on first run, gitignored store dir)
- `.vault/` — encrypted store + ledger (**never committed**)