#!/usr/bin/env python3
"""
ciphergate.py - the Gsquared Productions API-key vault (terminal).

WHAT IT IS
  A single terminal program that HOLDS the API keys ENCRYPTED, keeps a signed
  ACCESS list (profile -> hash of its .env key), a lease file, a pending
  index, and a LEDGER, and when allowed decrypts a key INTERNALLY and makes
  the https call itself, returning only the RESULT. A key is never handed to
  an agent, never written mid-session, never shown, never returned.

WHO IS KNOCKING (the gate)
  The vault decides identity purely from the HOME env (HERMES_HOME -> which
  profile is running) plus the .env key that profile presents. Batman puts a
  key in each profile's .env and registers its hash in the access list. A
  profile without a key (robin) simply owns nothing in the list and can't
  pass; one that flashes someone else's key is caught (running profile !=
  key owner) -> ACCESS SNEAK, denied + logged. No deny list needed.

THE DECISION
  A request decides like this:
    1. WHO: running profile must present a key registered to it, else DENIED.
    2. active unexpired lease for agent -> make the call (Batman NOT asked).
    3. otherwise -> write a PENDING entry with a UNIQUE request key, log it,
       and ask Batman. When the agent returns with the key, the vault
       resolves it: pending -> come back later; YES -> lease + call; NO or
       other -> deny (other passes Batman's message verbatim).
  There is NO pass-through / "go as usual".

STAGE-2 TELEGRAM STUB (for now)
  Real Telegram buttons come in Stage 5. Today `decide <key> yes|no|other
  [msg]` stands in for Batman's answer so the index/lookup logic can be
  tested instantly. Wait window is variable via env VAULT_WAIT_MIN.

TAMPER-EVIDENCE
  access/lease/pending JSON carry an HMAC keyed to the vault PASSphrase.
  Agents don't hold the passphrase, so a direct edit or delete FAILS CLOSED.
  True process isolation is Stage 4.

USAGE (all terminal)
  python3 ciphergate.py init                            first run: set passphrase, mint recovery key
  python3 ciphergate.py add    <service>                add/update an encrypted key
  python3 ciphergate.py list                             names only, never values
  python3 ciphergate.py keygen <profile>                mint a .env key for a profile (shown once)
  python3 ciphergate.py access list|add|remove          manage .env-key map (passphrase)
  python3 ciphergate.py request <http> <expiry_min> <reason>   run the decision gate (identity from env)
  python3 ciphergate.py pending                         show pending requests (passphrase)
  python3 ciphergate.py decide  <req_key> <yes|no|other> [msg]   TELEGRAM STUB: set verdict
  python3 ciphergate.py resolve <req_key>               agent returns: pick up the verdict
  python3 ciphergate.py lease                           active leases (passphrase)
  python3 ciphergate.py ledger                          audit history (read-only)
  python3 ciphergate.py recover                         new passphrase via off-site recovery key
  python3 ciphergate.py update                          change the passphrase (needs current pass)
  python3 ciphergate.py status                          where things live + counts

DIRECTORY (all .vault/ gitignored)
  .vault/keys.json       the encrypted key store
  .vault/access.json     profile -> key-hash map (signed, passphrase-keyed)
  .vault/leases.json     ACTIVE grants only, signed, purged on expiry
  .vault/pending.json    staged requests by unique key, signed
  .vault/ledger.jsonl    append-only history
  vault_recovery.key     NOT stored here - printed once at init, kept OFF-SITE.
"""
import sys, os, json, base64, getpass, hmac as _hmac, hashlib as _hl, subprocess, datetime, urllib.request, secrets, time

BASE = os.path.dirname(os.path.abspath(__file__))
VT   = os.path.join(BASE, ".vault")
KF   = os.path.join(VT, "keys.json")
AF   = os.path.join(VT, "access.json")
LF_  = os.path.join(VT, "leases.json")
PF   = os.path.join(VT, "pending.json")
LG   = os.path.join(VT, "ledger.jsonl")

_LEASE_TAG  = "gsq-vault-lease-v1"
_PENDING_TAG = "gsq-vault-pending-v1"
_ACCESS_TAG = "gsq-vault-access-v1"
WAIT_MIN    = int(os.environ.get("VAULT_WAIT_MIN", "5"))   # variable wait window

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def now_epoch():
    return time.time()

def log_event(ev):
    os.makedirs(VT, exist_ok=True)
    ev = dict(ev); ev["t"] = now_iso()
    with open(LG, "a") as f:
        f.write(json.dumps(ev) + "\n")

# ---------- AES (stdlib hashlib + openssl CLI, no pip deps) ----------
def aes_crypt(key_hex, iv_hex, data, decrypt=False):
    cmd = ["openssl", "enc", "-aes-256-cbc", "-d" if decrypt else "-e",
           "-K", key_hex, "-iv", iv_hex, "-nosalt"]
    p = subprocess.run(cmd, input=data, capture_output=True)
    if p.returncode != 0:
        raise RuntimeError("aes failed: " + p.stderr.decode(errors="replace"))
    return p.stdout

def derive_key(secret, salt, iters=200000):
    return _hl.pbkdf2_hmac("sha256", secret.encode(), salt, iters, 32).hex()

def new_rec_key():
    return os.urandom(32).hex()

def valid_rec_key(k):
    """A recovery key is a 64-char hex string (32 bytes = AES-256 key). Returns
    True only if it's non-empty hex of the right length. A wrong key (garbage
    or non-hex) should fail CLEANLY, not blow up mid-encrypt with a traceback."""
    if not k or len(k) != 64:
        return False
    try:
        bytes.fromhex(k)
        return True
    except ValueError:
        return False

# ---------- store ----------
def load_store():
    if not os.path.exists(KF):
        return {}
    return json.load(open(KF))

def save_store(store):
    os.makedirs(VT, exist_ok=True)
    json.dump(store, open(KF, "w"))

def add_key(service, value, passphrase, rec_key, keep_rec=None):
    store = load_store()
    salt = os.urandom(16)
    pk = derive_key(passphrase, salt)
    dk = os.urandom(32).hex()
    iv1, iv2 = [os.urandom(16).hex() for _ in range(2)]
    ct = aes_crypt(dk, iv1, value.encode())
    dk_pass = aes_crypt(pk, iv2, bytes.fromhex(dk))
    if keep_rec is not None and "dk_rec" in keep_rec:
        dk_rec = keep_rec["dk_rec"]    # preserve original recovery escrow
        iv3    = keep_rec["iv3"]
    else:
        iv3 = os.urandom(16).hex()
        dk_rec = base64.b64encode(aes_crypt(rec_key, iv3, bytes.fromhex(dk)))
    store[service] = {
        "ct": base64.b64encode(ct).decode(),
        "iv1": iv1, "salt": base64.b64encode(salt).decode(),
        "dk_pass": base64.b64encode(dk_pass).decode(), "iv2": iv2,
        "dk_rec": dk_rec.decode() if isinstance(dk_rec, bytes) else dk_rec, "iv3": iv3,
        "created": now_iso(), "note": ""
    }
    save_store(store)

def update_value(service, value, passphrase):
    """OVERWRITE an existing key's VALUE but PRESERVE its data key + recovery
    escrow. A naive reuse of add_key mints a NEW data key and keeps the OLD
    recovery escrow wrapping the OLD key — so after an edit the recovery key
    decrypts a stale key and returns garbage (the exact bug fixed here). This
    recovers the current dk via the passphrase, re-encrypts the new value under
    the SAME dk, and leaves dk/dk_rec/iv3 IDENTICAL. Requires the key to exist."""
    store = load_store()
    e = store[service]
    salt = base64.b64decode(e["salt"])
    pk = derive_key(passphrase, salt)
    dk = aes_crypt(pk, e["iv2"], base64.b64decode(e["dk_pass"]), decrypt=True).hex()
    iv1 = os.urandom(16).hex()
    ct = aes_crypt(dk, iv1, value.encode())
    e["ct"] = base64.b64encode(ct).decode()
    e["iv1"] = iv1
    e["note"] = (e.get("note", "") + " updated " + now_iso()).strip()
    store[service] = e
    save_store(store)

def rekey_passphrase(service, old_pass, new_pass):
    """Change ONLY the passphrase layer of a key. Keeps the data key, the
    ciphertext, iv1, and the recovery escrow IDENTICAL so the recovery key
    still works after a passphrase change."""
    e = load_store()[service]
    salt_old = base64.b64decode(e["salt"])
    pk_old = derive_key(old_pass, salt_old)
    dk = aes_crypt(pk_old, e["iv2"], base64.b64decode(e["dk_pass"]), decrypt=True).hex()
    salt_new = os.urandom(16)
    pk_new = derive_key(new_pass, salt_new)
    iv2_new = os.urandom(16).hex()
    dk_pass_new = aes_crypt(pk_new, iv2_new, bytes.fromhex(dk))
    e["salt"] = base64.b64encode(salt_new).decode()
    e["dk_pass"] = base64.b64encode(dk_pass_new).decode()
    e["iv2"] = iv2_new
    e["note"] = (e.get("note", "") + " rekeyed " + now_iso()).strip()
    store = load_store()
    store[service] = e
    save_store(store)

def unwrap(service, passphrase):
    e = load_store()[service]
    salt = base64.b64decode(e["salt"])
    pk = derive_key(passphrase, salt)
    dk = aes_crypt(pk, e["iv2"], base64.b64decode(e["dk_pass"]), decrypt=True).hex()
    ct = aes_crypt(dk, e["iv1"], base64.b64decode(e["ct"]), decrypt=True)
    return ct.decode()

def unwrap_rec(service, rec_key):
    e = load_store()[service]
    dk = aes_crypt(rec_key, e["iv3"], base64.b64decode(e["dk_rec"]), decrypt=True).hex()
    ct = aes_crypt(dk, e["iv1"], base64.b64decode(e["ct"]), decrypt=True)
    return ct.decode()

# ---------- passphrase-derived signing (tamper-evident files) ----------
def sign_key(passphrase, tag):
    return _hmac.new(tag.encode(), passphrase.encode(), _hl.sha256).digest()

def _canon(data):
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode()

def _bundle(data, key):
    return {"data": data, "sig": _hmac.new(key, _canon(data), _hl.sha256).hexdigest()}

def _check_bundle(raw, key):
    if not isinstance(raw, dict):
        return None
    sig = raw.get("sig"); data = raw.get("data")
    if not sig or data is None:
        return None
    mine = _hmac.new(key, _canon(data), _hl.sha256).hexdigest()
    return data if _hmac.compare_digest(mine, sig) else None

def _signed_load(path, passphrase, tag, default):
    """Load (data, status). status 'ok'|'missing'|'tampered'."""
    if not os.path.exists(path):
        return default, "missing"
    try:
        raw = json.load(open(path))
    except Exception:
        return default, "tampered"
    data = _check_bundle(raw, sign_key(passphrase, tag))
    if data is None:
        return default, "tampered"
    return data, "ok"

def _signed_save(path, data, passphrase, tag):
    json.dump(_bundle(data, sign_key(passphrase, tag)), open(path, "w"), indent=2)
    os.chmod(path, 0o600)

# ---------- access map (profile -> hash of its .env key) ----------
def load_access(passphrase):
    """Return (keys_map, status). Signed + fail-closed like the other files."""
    data, st = _signed_load(AF, passphrase, _ACCESS_TAG, {})
    return data.get("keys", {}), st

def save_access(keys, passphrase):
    _signed_save(AF, {"keys": keys}, passphrase, _ACCESS_TAG)

def key_hash(k):
    return _hl.sha256(k.encode()).hexdigest()

# ---------- lease file (ACTIVE grants only; tamper-evident, purged) ----------
def load_leases(passphrase):
    return _signed_load(LF_, passphrase, _LEASE_TAG, [])

def save_leases(leases, passphrase):
    _signed_save(LF_, leases, passphrase, _LEASE_TAG)

def purge_expired(passphrase):
    now = now_epoch()
    ls, st = load_leases(passphrase)
    if st != "ok":
        return [], st
    keep = [l for l in ls if float(l.get("expires_at", 0)) > now]
    if len(keep) != len(ls):
        save_leases(keep, passphrase)
    return keep, "ok"

def active_lease(agent, keys, passphrase):
    """Return the live lease covering THIS agent for ALL of the given keys.
    keys is a list of secret names (e.g. ['CLOUDFLARE_R2_ACCESS_KEY_ID',
    'CLOUDFLARE_R2_SECRET_ACCESS_KEY']). A lease is scoped to the exact secret
    names it was granted for — NEVER '*'. So a CLOUDFLARE lease never covers
    DOCKER_TOKEN."""
    active, st = purge_expired(passphrase)
    if st != "ok":
        return None
    keyset = set(keys)
    for l in active:
        if l.get("agent") != agent:
            continue
        granted = set(l.get("keys", []))
        if keyset and granted and keyset <= granted:   # lease covers ALL requested keys
            return l
    return None

# ---------- pending index (staged by unique request key) ----------
def load_pending(passphrase):
    data, st = _signed_load(PF, passphrase, _PENDING_TAG, {})
    return data, st

def save_pending(pending, passphrase):
    _signed_save(PF, pending, passphrase, _PENDING_TAG)

# ---------- CLI ----------
def ask(env, prompt):
    return os.environ.get(env) or getpass.getpass(prompt)

def _pass():
    return ask("VAULT_PASS", "Vault passphrase: ")

def cmd_init():
    os.makedirs(VT, exist_ok=True)
    if os.path.exists(KF):
        print("Store already exists. Use `recover` to reset, or delete .vault/keys.json to wipe.")
        return 1
    p1 = ask("VAULT_PASS", "Choose vault passphrase: ")
    p2 = ask("VAULT_PASS", "Repeat passphrase: ")
    if p1 != p2:
        print("Mismatch."); return 1
    rk = new_rec_key()
    save_store({})
    save_access({}, p1)
    save_leases([], p1)
    save_pending({}, p1)
    log_event({"ev":"INIT","by":"batman","recovery_minted":True})
    print("\n" + "="*60)
    print("STORE THIS RECOVERY KEY OFF-SITE - shown ONCE, never again, not saved here:")
    print(rk)
    print("="*60)
    os.chmod(VT, 0o700)
    print("Vault initialised. `add <service>` to store a key; `keygen <profile>` to issue an agent key.")
    return 0

def cmd_add(argv, passphrase):
    if len(argv) < 1: print("usage: vault.py add <service>"); return 1
    service = argv[0]
    value = ask("VAULT_VALUE", "Paste the API key value (hidden): ")
    store = load_store()
    if service in store:
        # OVERWRITE: preserve the data key + recovery escrow so the recovery key
        # still decrypts the new value (update_value recovers dk via passphrase).
        update_value(service, value, passphrase)
        log_event({"ev":"KEY_UPDATE","service":service})
        print(f"UPDATED {service} ENCRYPTED ({len(value)} chars); recovery escrow unchanged.")
        return 0
    rk = ask("VAULT_REC", "Recovery key (store value, once): ")
    if not valid_rec_key(rk):
        print("INVALID recovery key: it must be the 64-char hex key printed at init. Not stored.")
        return 1
    add_key(service, value, passphrase, rk)
    log_event({"ev":"KEY_ADD","service":service})
    print(f"Stored {service} ENCRYPTED ({len(value)} chars).")
    return 0

def cmd_list():
    st = load_store()
    if not st: print("(store empty)"); return 0
    for s, e in st.items():
        print(f"{s}  (encrypted, {len(base64.b64decode(e['ct']))} bytes, added {e['created']})")
    return 0

# ---------- bot config (Telegram token + chat id) ----------
# Stored like any key (encrypted at rest). `bot_clear` removes them. The
# TOKEN VALUE IS NEVER PRINTED — `bot info` only masks it. The chat id is a
# non-secret handle and may be shown.
BOT_TOKEN_SVC = "telegram_bot"
BOT_CHAT_SVC   = "telegram_bot_chat"

def bot_token(passphrase):
    if BOT_TOKEN_SVC not in load_store():
        return ""
    return unwrap(BOT_TOKEN_SVC, passphrase)

def bot_chat(passphrase):
    if BOT_CHAT_SVC not in load_store():
        return ""
    return unwrap(BOT_CHAT_SVC, passphrase)

def _mask(s):
    if not s: return "(not set)"
    if len(s) <= 4: return "*" * len(s)
    return f"{s[:3]}**...**{s[-3:]}" if len(s) > 10 else "*" * len(s)

def cmd_bot(argv, passphrase):
    """bot set|info|update|clear  — manage the Telegram bot config.
    token + chat id live in the encrypted store; the token is never printed."""
    if not argv:
        print("usage: ciphergate.py bot set|info|update|clear"); return 1
    sub = argv[0].lower()
    tid = bot_token(passphrase)
    cid = bot_chat(passphrase)

    if sub == "info":
        print("Telegram bot config (login required — you're unlocked):")
        print(f"  token   : {_mask(tid)}")
        print(f"  chat id : {cid or '(not set)'}")
        print(f"  configured: {'YES' if tid and cid else 'NO (set it with `bot set`)'}")
        return 0

    if sub in ("set", "update"):
        tok = ask("VAULT_BOT_TOKEN", "Paste the Telegram bot token (hidden): ")
        oid = ask("VAULT_BOT_CHAT", "Your Telegram chat id (the \"Sent from my iPhone\" you): ")
        if not tok or not oid:
            print("ABORT: both token and chat id are required."); return 1
        store = load_store()
        for svc, val in ((BOT_TOKEN_SVC, tok), (BOT_CHAT_SVC, oid)):
            if svc in store:
                update_value(svc, val, passphrase)      # keep dk + recovery escrow
            else:
                rk = ask("VAULT_REC", "Recovery key (new bot config; store escrow): ")
                if not valid_rec_key(rk):
                    print("INVALID recovery key: it must be the 64-char hex key printed at init. Not stored.")
                    return 1
                add_key(svc, val, passphrase, rk)
        log_event({"ev":"BOT_CONFIG","action":"set","by":"batman"})
        print("Bot config stored ENCRYPTED.")
        print(f"  token   : {_mask(tok)}")
        print(f"  chat id : {oid}")
        return 0

    if sub == "clear":
        store = load_store()
        for svc in (BOT_TOKEN_SVC, BOT_CHAT_SVC):
            if svc in store:
                del store[svc]
        save_store(store)
        log_event({"ev":"BOT_CONFIG","action":"clear","by":"batman"})
        print("Bot config cleared.")
        return 0

    print("usage: ciphergate.py bot set|info|update|clear"); return 1

def who_is_running():
    """Answer 'who launched this?' from the Hermes HOME env. Caveat: env can
    be forged by a determined same-user process (Stage 4 is the real wall);
    this trips up sloppy/lying agents, which is its purpose."""
    hh = os.environ.get("HERMES_HOME", "")
    if "profiles/" in hh:
        return hh.split("profiles/")[-1].strip("/")
    if hh:
        return "default"
    return ""

def verify_identity(passphrase):
    """Return (runner, ok, reason). The vault decides WHO is knocking purely
    from HOME env (HERMES_HOME -> runner) + the key it presents. A profile
    only ever has the key Batman put in its .env; a profile without one
    (robin) owns nothing in the list and can't pass. Flash another profile's
    key and the running profile won't own it -> ACCESS SNEAK."""
    runner = who_is_running()
    keys, st = load_access(passphrase)
    if st != "ok":
        return runner, False, "TAMPER DETECTED: access map unverifiable. Fail-closed: DENIED."
    presented = os.environ.get("VAULT_AGENT_KEY", "").strip()
    if not presented:
        return runner, False, "No .env key presented - access denied."
    if not runner:
        return runner, False, "Cannot identify which profile is running (no HERMES_HOME). Access denied."
    ph = key_hash(presented)
    if keys.get(runner) != ph:
        owner = next((p for p, h in keys.items() if h == ph), None)
        if owner and owner != runner:
            return runner, False, f"ACCESS SNEAK: you flashed {owner}'s key while running as {runner}. That key is not yours."
        return runner, False, f"No key registered for {runner}. Access denied."
    return runner, True, ""

def cmd_keygen(argv, passphrase):
    # keygen <profile>  -> mint a .env key for a profile, register its hash
    if len(argv) < 1: print("usage: vault.py keygen <profile>"); return 1
    prof = argv[0]
    keys, st = load_access(passphrase)
    if st != "ok":
        print("TAMPER DETECTED: access map unverifiable."); return 4
    new = secrets.token_urlsafe(24)
    keys[prof] = key_hash(new)
    save_access(keys, passphrase)
    log_event({"ev":"KEY_AUTH","profile":prof,"by":"batman"})
    print(f"Registered .env key for {prof}. ADD THIS LINE to {prof}'s .env (shown once):")
    print(f"VAULT_AGENT_KEY={new}")
    print(f"(stored as hash {keys[prof][:8]}... - plaintext never saved)")
    return 0

def cmd_access(argv, passphrase):
    if not argv:
        print("usage: vault.py access list|add <profile> <key>|remove <profile>"); return 1
    sub, rest = argv[0], argv[1:]
    keys, st = load_access(passphrase)
    if st != "ok":
        print("TAMPER DETECTED: access map unverifiable."); return 4
    if sub == "list":
        if not keys: print("(no registered .env keys)")
        for p, h in keys.items():
            print(f"{p}   (hash {h[:8]}...)")
        return 0
    if sub == "add":
        if len(rest) < 2: print("usage: vault.py access add <profile> <key>"); return 1
        keys[rest[0]] = key_hash(rest[1]); save_access(keys, passphrase)
        log_event({"ev":"KEY_AUTH","profile":rest[0],"by":"batman","mode":"add"})
        print(f"Registered .env key for {rest[0]}.")
        return 0
    if sub == "remove":
        if not rest: print("usage: vault.py access remove <profile>"); return 1
        if rest[0] in keys:
            del keys[rest[0]]; save_access(keys, passphrase)
            log_event({"ev":"KEY_AUTH","profile":rest[0],"by":"batman","mode":"remove"})
            print(f"Removed .env access for {rest[0]}.")
        else:
            print(f"no .env key registered for {rest[0]}.")
        return 0
    print("usage: vault.py access list|add <profile> <key>|remove <profile>"); return 1

def classify_request(http):
    """Classify a request URL/substring against sensitive-API patterns.

    Returns (verdict, detail): verdict is 'no_use' (refuse outright), 'flag'
    (warn Batman before approval), or 'ok'. Built from analysing cloud-API
    scopes that mint tokens, expose credentials, or touch account/team/security.
    Matching is on substrings in the request string, so it catches the endpoint
    regardless of the exact host or path formatting."""
    low = http.lower()
    NO_USE = [
        # credential / secret exposure
        ("database/view_credentials", "database credential access"),
        ("/databases/", "managed-database endpoint"),
        ("spaces_key/create_credentials", "creates a Spaces access key AND returns its secret"),
        ("kubernetes/access_cluster", "downloads cluster credentials (kubeconfig)"),
        ("kubeconfig", "cluster credentials"),
        ("/credentials", "credential endpoint"),
        ("access_token", "token issuance"),
        ("create_token", "token creation"),
        ("refresh_token", "token refresh/rotation"),
        ("oauth", "OAuth token flow"),
        ("/auth/", "authentication endpoint"),
        # admin / full-access
        ("function:admin", "serverless admin"),
        ("functions:admin", "serverless admin"),
        ("droplet:admin", "droplet console access"),
        (":admin", "admin-level scope"),
        # inference token minting
        ("inference_token", "inference token management"),
    ]
    for pat, why in NO_USE:
        if pat in low:
            return "no_use", f"no-use rule hit ({why})"
    FLAG = [
        ("account:", "account details"),
        ("/account", "account details"),
        ("billing", "billing/invoice"),
        ("organization", "organization/team"),
        ("team_membership", "team membership"),
        ("spaces_key", "Spaces key management"),
        ("ssh_key", "SSH key management"),
        ("/projects", "project management"),
        ("/tokens", "token endpoints"),
        ("/keys", "key endpoints"),
    ]
    for pat, why in FLAG:
        if pat in low:
            return "flag", f"sensitive scope ({why})"
    return "ok", ""

def cmd_request(argv, passphrase):
    if len(argv) < 3:
        print("usage: vault.py request <method> <http> <expiry_min> <reason> [--keys k1,k2] [--header 'N:[k]']... [--data <json>]")
        return 1
    method = argv[0].upper()
    http = argv[1]
    try:
        expiry = int(argv[2])
    except ValueError:
        print("expiry must be minutes (0 = one-off, no lease requested)"); return 1
    reason = " ".join(argv[3:]) if len(argv) > 3 else ""
    # optional flags: --keys a,b | --header "Name:[key]" | --data <json>
    keys, headers, data = [], {}, None
    i = 0
    parts = []
    while i < len(argv[3:]):
        a = argv[3:][i]
        if a == "--keys":
            keys = [k.strip() for k in argv[3:][i+1].split(",") if k.strip()]; i += 2
        elif a == "--header":
            nv = argv[3:][i+1].split(":", 1)
            headers[nv[0].strip()] = nv[1].strip() if len(nv) > 1 else ""; i += 2
        elif a == "--data":
            data = argv[3:][i+1]; i += 2
        else:
            parts.append(a); i += 1
    if keys:
        # confirm every requested key EXISTS in the store (fail closed if a name is invented)
        st = load_store()
        missing = [k for k in keys if k not in st]
        if missing:
            log_event({"ev":"BAD_KEYS","runner":who_is_running(),"missing":"/".join(missing),"outcome":"DENY"})
            print(f"DENIED: unknown key(s) requested: {', '.join(missing)}. 'Not in my city.'")
            return 1
    if reason == "" and parts:
        reason = " ".join(parts)

    # WHO is knocking? runner derives from HOME env; its key must own it.
    runner, ok_id, why = verify_identity(passphrase)
    if not ok_id:
        log_event({"ev":"ACCESS_DENIED","runner":runner,"outcome":"DENY","why":why})
        print(f"DENIED: {why} 'Not in my city.'")
        return 3
    agent = runner   # identity IS the running profile
    log_event({"ev":"IDENTITY","agent":agent,"outcome":"OK"})

    # SENSITIVITY GATE: hard NO-USE vs flag-for-Batman. Runs BEFORE the lease
    # so a live lease can't be used to smuggle a credential-mint call through.
    verdict, detail = classify_request(http)
    if verdict == "no_use":
        log_event({"ev":"NO_USE","agent":agent,"http":http,"why":detail,"outcome":"DENY"})
        print(f"DENIED: {detail}. 'Not in my city.'")
        return 9
    flagged = verdict == "flag"

    # LEASE: if a live lease covers agent+ALL requested keys, use it (no ask).
    if keys:
        lease = active_lease(agent, keys, passphrase)
        if lease:
            if flagged:
                log_event({"ev":"DECIDE","agent":agent,"http":http,"outcome":"LEASE_FLAG",
                           "keys":keys,"why":detail})
                print(f"WARNING: live lease would cover {agent} for {','.join(keys)}, but this is FLAGGED: {detail}")
                print("Refusing without Batman. Ask again or get explicit approval.")
                return 9
            log_event({"ev":"DECIDE","agent":agent,"http":http,"outcome":"LEASE",
                       "keys":keys,"expires":lease.get("expires_iso")})
            print(f"ACTIVE LEASE covers {agent} for [{','.join(keys)}] (expires {lease['expires_iso']}).")
            _exec_call(method, http, headers, data, keys, passphrase, agent)
            return 0

    # No lease -> stage a PENDING entry with a UNIQUE key, ask Batman.
    req_key = secrets.token_hex(8)
    pending, st = load_pending(passphrase)
    if st != "ok":
        log_event({"ev":"TAMPER","file":"pending","agent":agent,"outcome":"FAIL_CLOSED"})
        print("TAMPER DETECTED: pending index unverifiable. Fail-closed: DENIED.")
        return 4
    pending[req_key] = {
        "agent": agent, "method": method, "http": http, "reason": reason,
        "expiry_min": expiry, "keys": keys, "headers": headers, "data": data,
        "asked_at": now_iso(), "asked_epoch": now_epoch(), "status": "pending",
        "msg": "", "lease_created": False,
        "flag": detail if flagged else "",
    }
    save_pending(pending, passphrase)
    log_event({"ev":"PENDING","agent":agent,"method":method,"http":http,"reason":reason,
               "expiry_min":expiry,"keys":keys,"req_key":req_key,"outcome":"ASK_BATMAN",
               "flag":detail if flagged else ""})
    flag_txt = f"  [FLAGGED: {detail} - Batman, look before you approve]" if flagged else ""
    key_txt = f"  keys: [{','.join(keys)}]" if keys else ""
    print(f"{agent}: no lease. Staged request key {req_key}.{key_txt} Handed to Batman to approve.{flag_txt}")
    print(f"(wait window = {WAIT_MIN} min; TELEGRAM STUB: `vault.py decide {req_key} yes|no|other [msg]`)")
    return 0

def cmd_pending(passphrase):
    pending, st = load_pending(passphrase)
    if st != "ok":
        print("TAMPER DETECTED: pending index unverifiable.")
        return 4
    if not pending: print("(no pending requests)"); return 0
    now = now_epoch()
    for k, e in sorted(pending.items()):
        age = max(0, int((now - e["asked_epoch"]) // 60))
        w = "PENDING" if e["status"] == "pending" else e["status"].upper()
        print(f"{k}  {e['agent']}  {e['http']}  {w}  asked {age}m ago  {e.get('msg','')}")
    return 0

def cmd_decide(argv, passphrase):
    # decide <req_key> <yes|no|other> [msg]   — TELEGRAM STUB
    if len(argv) < 2:
        print("usage: vault.py decide <req_key> <yes|no|other> [msg]"); return 1
    req_key, verdict = argv[0], argv[1].lower()
    msg = " ".join(argv[2:])
    if verdict not in ("yes", "no", "other"):
        print("verdict must be yes|no|other"); return 1
    pending, st = load_pending(passphrase)
    if st != "ok":
        print("TAMPER DETECTED: pending index unverifiable.")
        return 4
    if req_key not in pending:
        print(f"No pending entry for {req_key}."); return 1
    e = pending[req_key]
    e["status"] = verdict
    e["msg"] = msg
    e["answered_at"] = now_iso()
    save_pending(pending, passphrase)
    log_event({"ev":"VERDICT","req_key":req_key,"agent":e["agent"],"verdict":verdict,"by":"batman-stub","msg":msg})
    print(f"{req_key}: {e['agent']} -> {verdict.upper()}" + (f" (msg: {msg})" if msg else ""))
    return 0

def cmd_resolve(argv, passphrase):
    # resolve <req_key>  — agent returns and picks up the verdict
    if len(argv) < 1: print("usage: vault.py resolve <req_key>"); return 1
    req_key = argv[0]
    pending, st = load_pending(passphrase)
    if st != "ok":
        log_event({"ev":"TAMPER","file":"pending","outcome":"FAIL_CLOSED"})
        print("TAMPER DETECTED: pending index unverifiable. Fail-closed: DENIED.")
        return 4
    if req_key not in pending:
        log_event({"ev":"RESOLVE","req_key":req_key,"outcome":"UNKNOWN_KEY"})
        print(f"No pending entry for {req_key}. The request may have been superseded.")
        return 1
    e = pending[req_key]
    # variable-wait timeout: if still pending and past the window, tell agent to wait.
    if e["status"] == "pending":
        age_min = (now_epoch() - e["asked_epoch"]) / 60
        if age_min < WAIT_MIN:
            still = e["asked_epoch"] + WAIT_MIN * 60 - now_epoch()
            print(f"Still waiting on Batman. Come back in ~{int(still//60)}m (or {WAIT_MIN}min window); key {req_key} is yours.")
            log_event({"ev":"RESOLVE","req_key":req_key,"outcome":"STILL_PENDING","agent":e["agent"]})
            return 0
        # past window but no verdict -> re-ask / tell agent to try again later
        log_event({"ev":"RESOLVE","req_key":req_key,"outcome":"PENDING_TIMEOUT","agent":e["agent"]})
        print(f"Batman hasn't answered in {WAIT_MIN} min. Not approved. Come back later with key {req_key}.")
        return 0

    # verdict decided
    e2 = pending.pop(req_key) if e["status"] in ("yes", "no", "other") else e
    if e2["status"] == "yes":
        keys = e2.get("keys") or []
        # no lease requested (expiry=0) -> ONE call, then done. No lease record.
        if not keys:
            print(f"Approved [{req_key}] {e2['agent']}. One-off call ({e2['http']}).")
            _exec_call(e2.get("method","GET"), e2["http"], e2.get("headers") or {},
                       e2.get("data"), [], passphrase, e2["agent"])
            return 0
        # keys requested: if a lease was asked for (expiry>0) and BATMAN approved,
        # record agent+keys+expiry. If no expiry granted (0), it's a one-off call on
        # the granted keys with NO lease.
        if e2.get("expiry_min", 0) > 0:
            leases, lst = load_leases(passphrase)
            if lst != "ok":
                save_pending(pending, passphrase)
                print("TAMPER DETECTED: lease file unverifiable."); return 4
            dur = e2["expiry_min"]
            lease = {"agent": e2["agent"], "keys": keys,
                     "expires_at": now_epoch() + dur * 60,
                     "expires_iso": (datetime.datetime.now(datetime.timezone.utc) +
                                     datetime.timedelta(minutes=dur)).strftime("%Y-%m-%dT%H:%M:%SZ")}
            leases.append(lease)
            save_leases(leases, passphrase)
            log_event({"ev":"GRANT","req_key":req_key,"agent":e2["agent"],"by":"batman",
                       "keys":keys,"lease_min":dur,"expires":lease["expires_iso"]})
            print(f"Approved [{req_key}] {e2['agent']} for [{','.join(keys)}]. Lease {dur} min.")
        else:
            log_event({"ev":"GRANT","req_key":req_key,"agent":e2["agent"],"by":"batman",
                       "keys":keys,"lease_min":0,"note":"one-off, no lease"})
            print(f"Approved [{req_key}] {e2['agent']} for [{','.join(keys)}]. One-off call, no lease.")
        _exec_call(e2.get("method","GET"), e2["http"], e2.get("headers") or {},
                   e2.get("data"), keys, passphrase, e2["agent"])
        return 0
    if e2["status"] == "no":
        log_event({"ev":"REJECT","req_key":req_key,"agent":e2["agent"],"by":"batman"})
        print(f"Denied [{req_key}] {e2['agent']}. 'Denied. Back to the Batcave.'")
        return 3
    # other: always denied, but pass Batman's message verbatim
    log_event({"ev":"REJECT","req_key":req_key,"agent":e2["agent"],"by":"batman","why":"other","msg":e2["msg"]})
    print(f"Denied [{req_key}] {e2['agent']}. Batman says: \"{e2['msg']}\"")
    return 3

def cmd_lease(passphrase):
    active, st = purge_expired(passphrase)
    if st != "ok":
        print("TAMPER DETECTED: lease file unverifiable.")
        return 4
    if not active: print("(no active leases)")
    for l in active:
        keys = ",".join(l.get("keys") or []) or "*"
        print(f"{l['agent']}  keys=[{keys}]  http={l.get('http','')}  expires {l.get('expires_iso')}")
    return 0

def _exec_call(method, url, headers, data, keys, passphrase, agent):
    """Substitute+send scoped to ONLY the granted keys. `keys` is the list of
    secret names this call/lease is permitted to use. Any [name] placeholder in
    a header or body that is NOT in `keys` is LEFT AS-IS (never substituted),
    so an agent can't smuggle an ungranted secret into the call. Returns status."""
    st = load_store()
    def sub(s):
        if isinstance(s, str) and "[" in s:
            out = s
            for name in keys:                      # ONLY granted names
                if name in st:
                    out = out.replace("[" + name + "]", unwrap(name, passphrase))
            return out
        return s
    final_headers = {k: sub(v) for k, v in headers.items()}
    final_data = data
    if data and isinstance(data, str) and "[" in data:
        txt = data
        for name in keys:
            if name in st:
                txt = txt.replace("[" + name + "]", unwrap(name, passphrase))
        final_data = txt
    body = final_data.encode() if isinstance(final_data, str) else (final_data or bytes())
    req = urllib.request.Request(url, data=body or None, headers=final_headers, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            rbody = resp.read().decode(errors="replace")
        log_event({"ev":"CALL","agent":agent,"method":method,"url":url,
                   "keys":keys,"status":resp.status})
        print("STATUS:", resp.status)
        print("RESULT:"); print(rbody[:2000])
        return resp.status
    except Exception as ex:
        log_event({"ev":"CALL_FAIL","agent":agent,"method":method,"url":url,
                   "keys":keys,"why":str(ex)[:120]})
        print("CALL FAILED:", ex)
        return None

def cmd_call(argv, passphrase):
    # call <method> <url> --header "Name:[key_name]" ... [--data <json>]
    # Provider-agnostic substitute+send, same as the request path but run
    # MANUALLY by a caller (secrets never leave the vault). Only the keys named
    # in the header/body placeholders are substituted.
    if len(argv) < 3:
        print("usage: vault.py call <method> <url> [--header 'Name:[key_name]']... [--data <json>]")
        return 1
    method = argv[0].upper()
    url = argv[1]
    headers = {}
    data = None
    keys = []
    i = 2
    while i < len(argv):
        if argv[i] == "--header":
            nv = argv[i+1].split(":", 1)
            headers[nv[0].strip()] = nv[1].strip(" ") if len(nv) > 1 else ""
            if "[" in headers.get(nv[0].strip(), "") and nv[0] != "":
                pass
            i += 2
        elif argv[i] == "--data":
            data = argv[i+1]; i += 2
        else:
            i += 1
    if method in ("POST", "PUT", "PATCH") and data is None:
        data = ""
    st = load_store()
    # derive required keys from placeholders in header values + body
    for v in headers.values():
        if "[" in v:
            for name in st:
                if ("[" + name + "]") in v and name not in keys:
                    keys.append(name)
    if data and "[" in data:
        for name in st:
            if ("[" + name + "]") in data and name not in keys:
                keys.append(name)
    _exec_call(method, url, headers, data, keys, passphrase, "--manual")
    return 0

def cmd_recover():
    if not os.path.exists(KF): print("No store."); return 1
    rk = ask("VAULT_REC", "Off-site recovery key: ").strip()
    try:
        one = next(iter(load_store()))
        unwrap_rec(one, rk)
    except Exception:
        print("Recovery key rejected."); return 1
    p1 = ask("VAULT_PASS", "New passphrase: "); p2 = ask("VAULT_PASS", "Repeat: ")
    if p1 != p2: print("Mismatch."); return 1
    for s in list(load_store().keys()):
        plain = unwrap_rec(s, rk)
        add_key(s, plain, p1, rk)
    keys, ak = load_access(rk)
    save_access(keys if ak == "ok" else {}, p1)
    save_leases([], p1)
    save_pending({}, p1)
    log_event({"ev":"RECOVER","by":"batman"})
    print("Recovered. Keys + signed files re-encrypted/re-signed under new passphrase.")
    return 0

def cmd_update(passphrase):
    # update-password: change the vault passphrase (needs the CURRENT one).
    if not os.path.exists(KF):
        print("No store. Run `init` first."); return 1
    store = load_store()
    if not store:
        print("Store has no keys yet - cannot validate current passphrase. Add a key first.")
        return 1
    try:
        first = next(iter(store))
        unwrap(first, passphrase)
    except Exception:
        print("Current passphrase rejected. It must match the one the keys were stored under.")
        return 1
    leases, lst = purge_expired(passphrase)
    pending, pst = load_pending(passphrase)
    if lst != "ok" or pst != "ok":
        print("TAMPER DETECTED: lease or pending file invalid. Cannot update (fail-closed)."); return 4
    p1 = ask("VAULT_NEW_PASS", "New passphrase: "); p2 = ask("VAULT_NEW_PASS", "Repeat: ")
    if p1 != p2: print("Mismatch."); return 1
    if p1 == passphrase:
        print("New passphrase is identical to current - no change made.")
        return 1
    for s in list(store.keys()):
        rekey_passphrase(s, passphrase, p1)
    save_leases(leases, p1)
    save_pending(pending, p1)
    access_keys, ast = load_access(passphrase)
    save_access(access_keys if ast == "ok" else {}, p1)
    log_event({"ev":"UPDATE_PASS","by":"batman","keys":len(store)})
    print(f"Passphrase updated. {len(store)} key(s) re-encrypted; lease/pending/access re-signed.")
    print("The OLD passphrase no longer works; the recovery key still does.")
    return 0

def cmd_status(passphrase):
    st = load_store()
    keys, ast = load_access(passphrase)
    leases, lst = purge_expired(passphrase)
    pending, pst = load_pending(passphrase)
    print(f"vault dir      : {VT}")
    print(f"services       : {len(st)}")
    print(f"access keys    : {', '.join(keys.keys()) or '(none)'}  [{ast}]")
    print(f"active leases  : {len(leases)}  [{lst}]")
    print(f"pending asks   : {len(pending)}  [{pst}]")
    print(f"ledger lines   : {sum(1 for _ in open(LG)) if os.path.exists(LG) else 0}")
    return 0

def cmd_ledger():
    if not os.path.exists(LG): print("(empty)"); return 0
    for line in open(LG):
        try:
            e = json.loads(line)
        except Exception:
            continue
        print(e.get("t"), e.get("ev"), e.get("agent",""), e.get("outcome",""),
              e.get("req_key",""), e.get("service",""), e.get("why",""))
    return 0

CYAN = "\033[38;5;51m"
RESET = "\033[0m"

def _print_cyan(logo_lines):
    for line in logo_lines:
        print(f"{CYAN}{line}{RESET}")

def _banner():
    """CipherGate intro: render Batman's keyhole art (keyhole_art.txt) in cyan
    phosphor, no clear, no leading blank lines — the keyhole prints first thing.
    The art file is the source of truth; edits change the banner directly."""
    art = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keyhole_art.txt")
    try:
        with open(art, encoding="utf-8") as f:
            raw = [ln.rstrip("\n") for ln in f]
        # strip leading + trailing blank lines so ONLY the art prints first
        while raw and raw[0] == "":
            raw.pop(0)
        while raw and raw[-1] == "":
            raw.pop()
        logo_lines = [ln for ln in raw if ln.strip()]
        print("\n\n")                        # breathing space: two blank lines above the keyhole
        _print_cyan(logo_lines)
        print()
        print(f"{CYAN}   Secure API Routing — API keys held encrypted; every call waits on the gate.{RESET}\n")
        return
    except Exception:
        logo_lines = [
            "                                  ,▄▄▓██████▓▄▄,",
            "                              ▄▓██████████████████▓▄",
            "                            ▄██████████▀▀▀▀██████████▄",
            "                           ████████▀          ▀████████",
            "                          ████████              ████████",
            "                         ████████                ████████",
            "                         ████████                ████████",
            "                          ████████              ████████",
            "                           ████████▄          ▄████████",
            "                            ▀█████████▄    ▄█████████▀",
            "                              ▀████████    ████████▀",
            "                               ████████    ████████",
            "                              ████████      ████████",
            "                             ████████        ████████",
            "                            ████████          ████████",
            "                           ████████            ████████",
            "                          ████████              ████████",
            "                         ████████████████████████████████",
            "                         ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀",
            "",
            " ██████╗██╗██████╗ ██╗  ██╗███████╗██████╗  ██████╗  █████╗ ████████╗███████╗",
            "██╔════╝██║██╔══██╗██║  ██║██╔════╝██╔══██╗██╔════╝ ██╔══██╗╚══██╔══╝██╔════╝",
            "██║     ██║██████╔╝███████║█████╗  ██████╔╝██║  ███╗███████║   ██║   █████╗  ",
            "██║     ██║██╔═══╝ ██╔══██║██╔══╝  ██╔══██╗██║   ██║██╔══██║   ██║   ██╔══╝  ",
            "╚██████╗██║██║     ██║  ██║███████╗██║  ██║╚██████╔╝██║  ██║   ██║   ███████╗",
            " ╚══════╝╚═╝╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝",
        ]
        print("\n\n")                        # breathing space above the fallback keyhole too
        _print_cyan(logo_lines)
        print()
        print(f"{CYAN}   Secure API Routing — API keys held encrypted; every call waits on the gate.{RESET}\n")

def main():
    os.chmod(VT, 0o700) if os.path.exists(VT) else None
    if len(sys.argv) < 2:
        _banner(); print("no command given. Try `python3 ciphergate.py --help`:")
        print(__doc__); return 0
    c = sys.argv[1]
    if c == "--help":
        _banner(); print(__doc__); return 0
    args = sys.argv[2:]
    no_pass = c in ("init", "list", "ledger")
    passphrase = "" if no_pass else _pass()
    table = {
        "init": lambda: cmd_init(),
        "add": lambda: cmd_add(args, passphrase),
        "list": lambda: cmd_list(),
        "keygen": lambda: cmd_keygen(args, passphrase),
        "access": lambda: cmd_access(args, passphrase),
        "request": lambda: cmd_request(args, passphrase),
        "pending": lambda: cmd_pending(passphrase),
        "decide": lambda: cmd_decide(args, passphrase),
        "resolve": lambda: cmd_resolve(args, passphrase),
        "lease": lambda: cmd_lease(passphrase),
        "call": lambda: cmd_call(args, passphrase),
        "recover": lambda: cmd_recover(),
        "update": lambda: cmd_update(passphrase),
        "status": lambda: cmd_status(passphrase),
        "bot": lambda: cmd_bot(args, passphrase),
        "ledger": lambda: cmd_ledger(),
    }
    fn = table.get(c)
    if not fn: print("unknown cmd"); return 1
    return fn()

if __name__ == "__main__":
    sys.exit(main() or 0)