#!/usr/bin/env python3
"""
ciphergate.py - CipherGate, the Gsquared Productions API-key vault.

== WHAT THIS IS, IN PLAIN ENGLISH ==
CipherGate is a vault that keeps your API keys (like the fal.ai token or the
DigitalOcean token) SAFE. It holds them ENCRYPTED, so they are never stored in
plain text. When an agent (a Hermes profile like spielberg or link) needs to
call a service, it does NOT get the key. Instead CipherGate makes the call
ITSELF, using the key from its own encrypted store, and hands back only the
result. The key is never shown to the agent, never written to its files,
never sent in chat, and never printed.

== WHO IS ALLOWED TO ASK (the gate) ==
CipherGate decides who is knocking by looking at two things together:
  1. HERMES_HOME (which profile is running, e.g. spielberg), and
  2. the secret .env key that profile presents (set up once by Batman).
Every profile that is allowed has its own .env key, and CipherGate stores only
a scrambled fingerprint of it (its hash), never the key itself. A profile with
no key (like robin) can't pass. If one profile tries to use ANOTHER profile's
key, CipherGate spots the mismatch and refuses, logging it. No deny-list needed.

== HOW AN APPROVAL HAPPENS (the flow) ==
When an agent asks for a call, CipherGate decides like this:
  1. WHO: the running profile must show a key registered to it, else DENIED.
  2. If there is a still-valid lease (a standing grant) for this agent and the
     exact key names, the call goes ahead WITHOUT asking Batman.
  3. Otherwise CipherGate stages the request (a pending entry with a unique
     request key), logs it, and asks Batman to approve.
Batman approves from Telegram with the inline YES / NO / OTHER buttons:
     YES   -> the call happens now (and a lease is granted if one was asked).
     NO    -> the agent is refused.
     OTHER -> the agent is refused AND gets a message from Batman
             (the reason, typed into Telegram, comes back to the agent verbatim).
There is no "pass-through" — no request ever skips the gate.

== TELEGRAM APPROVAL ==
CipherGate pushes the approval ask to Batman's Telegram with real buttons.
You tap, the vault acts. (The older `decide <key> yes|no|other [msg]` command
still works for the same purpose from the terminal.)

== THE HTTP API (what agents call — server model) ==
`ciphergate run` starts a LOCAL server that a real agent process calls over
HTTP. The agent never runs the CLI itself, has no passphrase, and never sees a
secret. The agent sends WHO it is (agent name + the secret .env key, which stays
in the agent's own profile) and the call it wants; the vault verifies, gets
Batman's approval if needed, substitutes the token in memory, makes the call,
and returns the result. Endpoints (all localhost, default port 18200):
  GET  /health    -> {"status":"up","vault":".vault"}
  POST /request   -> stage a call and WAIT for the verdict (the main one)
  POST /resolve   -> pick up a verdict later, using a request key (come-back-later case)
The /request body (the shape an AGENT sends an API call through):
  {
    "agent": "spielberg",                 # who is asking
    "key": "$VAULT_AGENT_KEY",            # that agent's .env key, proves identity
    "method": "POST",                     # GET / POST / PUT / DELETE / PATCH
    "url": "https://<endpoint>",
    "expiry": 0,                          # 0 = one-off, no lease; N = lease N minutes
    "reason": "honest statement of why",
    "keys": ["FAL_API_KEY"],              # stored key NAMES to activate
    "headers": {"Authorization": "Bearer [FAL_API_KEY]", "Content-Type": "application/json"},
    "data": { ... },                      # optional JSON body the API takes
    "timeout": 300                        # optional; per-call read timeout in seconds
  }
The `[KEY_NAME]` bracket markers are the ONLY thing substituted — the vault swaps
the real token where the marker sits: in a header value, a query string in the
URL, or inside the body. Put the marker exactly where the target API wants the
token, and keep the brackets. Any data/header/URL field without brackets is
forwarded verbatim. `timeout` defaults to 300s (override per call with an
integer; set it high enough for slow jobs like image generation). The server is
multi-threaded, so one agent's slow call never blocks another's — they run on
separate threads and each waits only on its own Batman approval.

== TAMPER-PROOFING ==
The state files (access / lease / pending) carry a secret signature (HMAC)
keyed to the vault passphrase. Only someone with the passphrase can write/alter
them. If a file is hand-edited or tampered with, CipherGate sees the signature
no longer matches, refuses to trust the file, and logs a TAMPER event to the
ledger so it is never silent.

== THE REQUEST KEY — what it is for (important to know) ==
A request key is ONLY needed in ONE situation: Batman has not answered within
the wait window, so the vault sends a "come back later" (timeout) reply. In that
one case you keep the key and use it to check back for the verdict.
In every other case the request key is not something you act on:
  - approved  -> the result comes straight back in your call; the key in the
                reply is informational only, the request is already DONE.
  - denied    -> no key at all; the request is refused and finished.
Rule: approved or denied = the request is resolved (finished). Only a timeout
leaves it open, and only then does the key matter.

== `request` vs `call` — the difference ==
  ciphergate request   is the GATED path: goes through identity check, the
  sensitivity gate, the lease check, and (if no live lease) asks Batman for
  approval on Telegram. This is what a real agent uses to make a call from
  inside the vault's rules. Returns the result.
  ciphergate call      is the UNGATED, manual helper: it does the substitution
  and sends immediately, with NO identity check, NO lease, NO Batman approval.
  It exists ONLY for quick manual tests and the regression suite - you would
  NOT use it for a real agent request, because it skips every gate.

== HOW TO USE IT (all from a terminal) ==
  ciphergate init                                 first run: set a passphrase, get your off-site recovery key
  ciphergate add    <service>                     add or update an encrypted key (e.g. add FAL_API_KEY)
  ciphergate list                                  show key NAMES only (never values) - no passphrase needed
  ciphergate show <service>                        [Batman only] show ONE stored key's real VALUE (passphrase-gated, to verify a key)
  ciphergate keygen <profile>                     mint a .env key for a profile (shown once)
  ciphergate access list|add|remove               manage which profiles are allowed
  ciphergate request <method> <url> <mins> <reason> [--keys k1,k2] [--header "N:[key]"] [--data <json>] [--timeout <secs>]
                                                 ask the gate to make a call for an agent
  ciphergate pending                             show requests waiting for approval (or `pending clear` to wipe the wait list)
  ciphergate decide  <req_key> <yes|no|other> [msg]   approve/refuse a pending request (terminal alternative to the Telegram buttons)
  ciphergate resolve <req_key>                   [TEST/REGRESSION only] agent picks up a verdict - you normally will not use this
  ciphergate lease                               show active leases (standing grants)
  ciphergate call <method> <url> [--header "N:[key]"] [--data <json>] [--timeout <secs>]   [TEST/REGRESSION only] manual substitute+send, skips all gates
  ciphergate ledger                              read the full audit history
  ciphergate recover                             set a new passphrase using the off-site recovery key
  ciphergate rotate-recovery-key                 retire the OLD recovery key for a brand-new one (use if a key is compromised)
  ciphergate update                              change the passphrase (needs the current one)
  ciphergate status                              where the store lives + how many keys
  ciphergate run --port 18200                    start the local server agents call over HTTP
  ciphergate bot set|info|clear                     configure the Telegram approval bot (token + chat id, stored encrypted; `info` masks the token, `clear` removes it)

== WHERE FILES LIVE (all inside .vault/, kept out of git) ==
  .vault/keys.json       the encrypted key store
  .vault/access.json     who is allowed (profile -> key fingerprint), signed
  .vault/leases.json     currently active grants only, signed, auto-expire
  .vault/pending.json    requests waiting for approval, signed
  .vault/ledger.jsonl    the append-only history log
  The recovery key is NOT stored here - it is printed ONCE at init and is
  yours to keep somewhere safe and separate (a password manager, a printed
  copy). If you lose both the passphrase and this key, the vault cannot be
  unlocked again - that is by design.

== HOW YOUR VAULT STOWS AND SECURES YOUR DATA ==
(explanation + diagram: see images/2 secrets_vault.jpg)

To keep your information completely private, our system uses a two-step lock
system - similar to a high-security bank vault.

1. The Core Secret Lockbox
When you save secrets in the system, the program creates a unique, one-time
Data Key.
  - The system uses this Data Key to lock your secrets inside a digital lockbox.
  - Your actual secrets are completely scrambled and unreadable without this
    specific key.

2. The Two Protective Envelopes
To keep that Data Key safe, the system makes a copy of it and seals it inside
two separate, highly secure envelopes. You only need to open one of these
envelopes to get your secrets back.
  - Envelope 1 (The Passphrase Envelope): this envelope can only be opened when
    you type in your Original Passphrase (the main password you created when
    you set up your account).
  - Envelope 2 (The Recovery Envelope): this envelope can only be opened using
    your Recovery Key (your emergency backup code).

HOW YOU OPEN YOUR VAULT
Because of this design, the system itself never knows or stores your actual
master password. Instead, when you want to look at your data, the program
decrypts it using one of two independent pathways:
  - Normal Access:       You enter your Passphrase. It opens Envelope 1, grabs
                         the Data Key, and unlocks your secrets.
  - Emergency Recovery:  You enter your Recovery Key. It bypasses the password
                         entirely, opens Envelope 2, grabs the Data Key, and
                         unlocks your secrets.

WHY THIS MATTERS TO YOU
  - If you lose your password: you will not lose your data. As long as you
    have your Recovery Key, you can open the second envelope and safely get
    back inside.
  - If you change your password: the system does not need to re-lock all your
    files. It simply destroys the old Envelope 1 and creates a brand-new one
    with your new password. Your data stays safe and untouched throughout.
  - Copying the vault folder and setting a NEW passphrase will NOT unlock it:
    the secrets are locked to the ORIGINAL passphrase and recovery key. The
    only two keys that can open the vault are the two from the original setup.
"""
import sys, os, json, base64, getpass, hmac as _hmac, hashlib as _hl, subprocess, datetime, urllib.request, secrets, time, threading

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
CALL_TIMEOUT = int(os.environ.get("VAULT_CALL_TIMEOUT", "300"))  # upstream HTTP read timeout (default 300s; set lower for quick health checks)
# A single lock guards ALL signed state-file read-modify-write. The per-save
# lock inside _signed_save only protects the write; the RACE that matters (two
# agents staging a pending entry at the same instant both load, add, then save
# - last writer wins, one entry lost) needs the WHOLE modify held under one lock.
# Hold _STATE_LOCK across every load->mutate->save sequence on pending/leases.
_STATE_LOCK = threading.RLock()

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

def rekey_recovery_key(service, old_rec, new_rec):
    """Change ONLY the recovery-key layer of a key. Recovers the data key via
    the OLD recovery key, then re-wraps dk_rec with the NEW recovery key.
    The secret (ct), data key, passphrase envelope, and iv1 stay IDENTICAL, so
    this never touches the actual secrets and the passphrase still works."""
    e = load_store()[service]
    dk = aes_crypt(old_rec, e["iv3"], base64.b64decode(e["dk_rec"]), decrypt=True).hex()
    iv3_new = os.urandom(16).hex()
    dk_rec_new = aes_crypt(new_rec, iv3_new, bytes.fromhex(dk))
    e["dk_rec"] = base64.b64encode(dk_rec_new).decode()
    e["iv3"] = iv3_new
    e["note"] = (e.get("note", "") + " rec-rekey " + now_iso()).strip()
    store = load_store()
    store[service] = e
    save_store(store)

def _verify_passphrase(passphrase):
    """Attempt to prove the passphrase can decrypt the store. Raises RuntimeError
    if it can't (used at server startup so a wrong passphrase fails cleanly)."""
    store = load_store()
    if not store:
        return True  # empty store — nothing to decrypt yet, passphrase is untested
    svc = next(iter(store))          # any stored entry
    unwrap(svc, passphrase)          # raises RuntimeError if the passphrase is wrong
    return True

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
    with _STATE_LOCK:
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
    """Write atomically: temp file + rename, under the state lock, so two
    concurrent threads (agents) can't interleave into a corrupt/partial file."""
    with _STATE_LOCK:
        payload = json.dumps(_bundle(data, sign_key(passphrase, tag)), indent=2)
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            f.write(payload)
        os.replace(tmp, path)
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

def cmd_show(argv, passphrase):
    """`show <service>`  — Batman-only: view a stored key's VALUE. Requires the
    vault passphrase (agents never have it), so only the owner can see secrets.
    Used to verify a key was stored/updated correctly."""
    if len(argv) < 1:
        print("usage: ciphergate show <service>\n  Shows the real value of one stored key. Passphrase-gated (Batman only).")
        return 1
    service = argv[0]
    st = load_store()
    if service not in st:
        print(f"No key stored as '{service}'. Use `ciphergate list` to see the names.")
        return 1
    try:
        value = unwrap(service, passphrase)
    except Exception:
        print("Could not decrypt - is the passphrase correct?")
        return 1
    print(f"{service} = {value}")
    log_event({"ev":"SHOW_VALUE","by":"batman","service":service,"len":len(value)})
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
    try:
        return unwrap(BOT_TOKEN_SVC, passphrase)
    except Exception:
        return ""   # wrong passphrase / bad decrypt -> treated as unconfigured, not a crash

def bot_chat(passphrase):
    if BOT_CHAT_SVC not in load_store():
        return ""
    try:
        return unwrap(BOT_CHAT_SVC, passphrase)
    except Exception:
        return ""   # wrong passphrase / bad decrypt -> treated as unconfigured, not a crash

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
    key and the running profile won't own it -> ACCESS SNEAK.

    This runs on the AGENT path (request/resolve) which has NO vault passphrase,
    so it reads the access map's registration DATA directly rather than requiring
    the passphrase to verify an HMAC. Identity is: does the presented key's hash
    match what's registered for the running profile?"""
    runner = who_is_running()
    # raw read of the registration map (works without the passphrase)
    try:
        raw = json.load(open(AF))
        keys = raw.get("data", {}).get("keys", {})
    except Exception:
        keys, st = {}, "missing"
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
        log_event({"ev":"TAMPER","file":"access","cmd":"keygen","outcome":"FAIL_CLOSED"})
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
        log_event({"ev":"TAMPER","file":"access","cmd":"access","outcome":"FAIL_CLOSED"})
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

def cmd_request(argv, passphrase, agent_override=None, presented_key=None):
    """`request <method> <http> <expiry_min> <reason> [--keys ..] [--header ..] [--data ..]`
    `agent_override`+`presented_key` are the multi-thread-safe path: the SERVER
    already verified agent+key (via _verify_agent_key) and passes them in, so
    this function does NOT touch the process-global os.environ. When they are
    None (CLI path), identity is derived from HERMES_HOME + the .env key as usual."""
    if len(argv) < 3:
        print("usage: vault.py request <method> <http> <expiry_min> <reason> [--keys k1,k2] [--header 'N:[k]']... [--data <json>] [--timeout <secs>]")
        return 1
    method = argv[0].upper()
    http = argv[1]
    try:
        expiry = int(argv[2])
    except ValueError:
        print("expiry must be minutes (0 = one-off, no lease requested)"); return 1
    # optional flags: --keys a,b | --header "Name:[key]" | --data <json>; the
    # leftover words form the REASON (flags must not pollute it).
    keys, headers, data = [], {}, None
    timeout = None
    parts = []
    i = 3
    while i < len(argv):
        a = argv[i]
        if a == "--keys":
            keys = [k.strip() for k in argv[i+1].split(",") if k.strip()]; i += 2
        elif a == "--header":
            nv = argv[i+1].split(":", 1)
            headers[nv[0].strip()] = nv[1].strip() if len(nv) > 1 else ""; i += 2
        elif a == "--data":
            data = argv[i+1]; i += 2
        elif a == "--timeout":
            try:
                timeout = int(argv[i+1])
            except (ValueError, IndexError):
                print("--timeout needs whole seconds (integer)"); return 1
            i += 2
        else:
            parts.append(a); i += 1
    reason = " ".join(parts)

    # WHO is knocking? The CLI derives runner from HOME env; its key must own
    # it. The server path passes agent_override (already verified by
    # _verify_agent_key) so it never touches shared os.environ under threads.
    if agent_override:
        runner, ok_id, why = agent_override, True, ""
    else:
        runner, ok_id, why = verify_identity(passphrase)
    if not ok_id:
        log_event({"ev":"ACCESS_DENIED","runner":runner,"outcome":"DENY","why":why})
        print(f"DENIED: {why} 'Not in my city.'")
        return 3
    agent = runner   # identity IS the running profile
    log_event({"ev":"IDENTITY","agent":agent,"outcome":"OK"})

    # validate requested keys EXIST, but only AFTER identity passes — so an
    # unauthenticated caller can't probe key names (fail closed if invented).
    if keys:
        st = load_store()
        missing = [k for k in keys if k not in st]
        if missing:
            log_event({"ev":"BAD_KEYS","runner":agent,"missing":"/".join(missing),"outcome":"DENY"})
            print(f"DENIED: unknown key(s) requested: {', '.join(missing)}. 'Not in my city.'")
            return 1

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
            res = _exec_call(method, http, headers, data, keys, passphrase, agent, timeout)
            return res if isinstance(res, dict) else 0   # return the RESULT so the server can relay it

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
        "timeout": timeout,
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
    # push the inline YES/NO/OTHER button to Batman on Telegram (real approval, no typing)
    try:
        ok = tg_approval_button(passphrase, req_key, agent, http, keys, reason)
        print("Telegram approval button " + ("sent." if ok else "NOT sent (check `bot info`)."))
    except Exception as ex:
        log_event({"ev":"TG_SEND_ERR","req_key":req_key,"why":str(ex)[:120]})
        print("Telegram approval send failed:", ex)
    print(f"(wait window = {WAIT_MIN} min; TELEGRAM STUB: `vault.py decide {req_key} yes|no|other [msg]`)")
    return 0

def cmd_pending(argv, passphrase):
    pending, st = load_pending(passphrase)
    if st != "ok":
        log_event({"ev":"TAMPER","file":"pending","cmd":"pending","outcome":"FAIL_CLOSED"})
        print("TAMPER DETECTED: pending index unverifiable.")
        return 4
    if argv and argv[0].lower() == "clear":
        n = len(pending)
        save_pending({}, passphrase)
        log_event({"ev":"PENDING_CLEAR","by":"batman","cleared":n})
        print(f"Cleared {n} pending request(s).\n"
              f"(This only removes the waiting list. If you also saw those requests "
              f"go out as Telegram approvals, that's expected - they were asked and "
              f"never answered; clearing just tidies the store.)")
        return 0
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
    return _apply_verdict(passphrase, req_key, verdict, msg)

def _apply_verdict(passphrase, req_key, verdict, msg=""):
    """Shared: write Batman's YES/NO/OTHER verdict into a pending entry. Used by
    the CLI `decide` command AND the Telegram inline-button poller, so both
    paths write the SAME signed state. Returns 0 on success, else exit code."""
    pending, st = load_pending(passphrase)
    if st != "ok":
        log_event({"ev":"TAMPER","file":"pending","cmd":"decide","outcome":"FAIL_CLOSED"})
        print("TAMPER DETECTED: pending index unverifiable.")
        return 4
    if req_key not in pending:
        print(f"No pending entry for {req_key}."); return 1
    e = pending[req_key]
    e["status"] = verdict
    e["msg"] = msg
    e["answered_at"] = now_iso()
    save_pending(pending, passphrase)
    log_event({"ev":"VERDICT","req_key":req_key,"agent":e["agent"],"verdict":verdict,
               "by":"batman-stub:" + verdict, "msg":msg})
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
        retries = e.get("retries", 0)
        # incremental backoff: each failed check-back waits longer (base * 2^retries, capped at 10 min)
        backoff = min(WAIT_MIN * (2 ** retries), 10) if WAIT_MIN > 0 else 0
        if age_min < WAIT_MIN:
            still = e["asked_epoch"] + WAIT_MIN * 60 - now_epoch()
            print(f"Still waiting on Batman. Come back in ~{int(still//60)}m (or {WAIT_MIN}min window); key {req_key} is yours.")
            log_event({"ev":"RESOLVE","req_key":req_key,"outcome":"STILL_PENDING","agent":e["agent"]})
            return 0
        # past the first window but no verdict -> count this retry, tell the agent
        # to wait incrementally longer before the NEXT check-back.
        e["retries"] = retries + 1
        save_pending(pending, passphrase)
        log_event({"ev":"RESOLVE","req_key":req_key,"outcome":"PENDING_RETRY","agent":e["agent"],
                   "retries":retries + 1,"backoff_min":backoff})
        print(f"Batman hasn't answered in {WAIT_MIN} min. Not approved yet. "
              f"Wait {backoff} min, then retry with key {req_key} (retry #{retries + 1}).")
        return 0

    # verdict decided
    e2 = pending.pop(req_key) if e["status"] in ("yes", "no", "other") else e
    save_pending(pending, passphrase)   # PERSIST the pop so a re-resolve can't replay the grant
    if e2["status"] == "yes":
        keys = e2.get("keys") or []
        # no lease requested (expiry=0) -> ONE call, then done. No lease record.
        if not keys:
            print(f"Approved [{req_key}] {e2['agent']}. One-off call ({e2['http']}).")
            res = _exec_call(e2.get("method","GET"), e2["http"], e2.get("headers") or {},
                       e2.get("data"), [], passphrase, e2["agent"], e2.get("timeout"))
            return res if isinstance(res, dict) else 0
        # keys requested: if a lease was asked for (expiry>0) and BATMAN approved,
        # record agent+keys+expiry. If no expiry granted (0), it's a one-off call on
        # the granted keys with NO lease.
        if e2.get("expiry_min", 0) > 0:
            leases, lst = load_leases(passphrase)
            if lst != "ok":
                save_pending(pending, passphrase)
                log_event({"ev":"TAMPER","file":"lease","cmd":"resolve","outcome":"FAIL_CLOSED"})
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
            lease_info = {"granted":True,"minutes":dur,"expires":lease["expires_iso"],
                          "keys":keys}   # token NAMES only, never values
        else:
            log_event({"ev":"GRANT","req_key":req_key,"agent":e2["agent"],"by":"batman",
                       "keys":keys,"lease_min":0,"note":"one-off, no lease"})
            print(f"Approved [{req_key}] {e2['agent']} for [{','.join(keys)}]. One-off call, no lease.")
            lease_info = {"granted":False,"minutes":0,"keys":keys}
        res = _exec_call(e2.get("method","GET"), e2["http"], e2.get("headers") or {},
                   e2.get("data"), keys, passphrase, e2["agent"], e2.get("timeout"))
        if isinstance(res, dict):
            res["lease"] = lease_info    # tell the agent about the lease (names only)
        return res if isinstance(res, dict) else 0
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
        log_event({"ev":"TAMPER","file":"lease","cmd":"lease","outcome":"FAIL_CLOSED"})
        print("TAMPER DETECTED: lease file unverifiable.")
        return 4
    if not active: print("(no active leases)")
    for l in active:
        keys = ",".join(l.get("keys") or []) or "*"
        print(f"{l['agent']}  keys=[{keys}]  http={l.get('http','')}  expires {l.get('expires_iso')}")
    return 0

def _exec_call(method, url, headers, data, keys, passphrase, agent, timeout=None):
    """Substitute+send scoped to ONLY the granted keys. `keys` is the list of
    secret names this call/lease is permitted to use. Any [name] placeholder in
    a header or body that is NOT in `keys` is LEFT AS-IS (never substituted),
    so an agent can't smuggle an ungranted secret into the call.

    SECRET HYGIENE ON RETURN: the response body is returned to the agent, but a
    target that ECHOES the request back (test stubs, httpbin) will reflect the
    real secret we substituted. Before returning, every secret VALUE this call
    actually substituted is masked to [REDACTED] so it can NEVER leak to the
    agent in the response."""
    st = load_store()
    # resolve the real secret values we are permitted to substitute (kept for
    # the return-mask; never logged, never returned raw)
    secret_values = [unwrap(name, passphrase) for name in keys if name in st]
    def _redact(rbody):
        if not secret_values:
            return rbody
        for v in secret_values:
            if v and v in rbody:
                rbody = rbody.replace(v, "[REDACTED]")
        return rbody
    # GUARD: detect a bare (unbracketed) granted key name in a header value or
    # body. If the agent wrote "Bearer FAL_API_KEY" or "FAL_API_KEY" instead of
    # "[FAL_API_KEY]", CipherGate would forward it literally and the call fails
    # auth silently. Refuse loudly and tell them the right form. This check runs
    # over the URL (query string) too — a token that belongs in ?api_key= must
    # also use brackets, and a bare name there is caught the same way.
    suspicious = []
    for name in keys:
        if name in st and ("[" + name + "]") not in url and name in url:
            suspicious.append(("url", name))
    for hn, hv in headers.items():
        for name in keys:
            if name in st and ("[" + name + "]") not in hv and name in hv:
                suspicious.append((hn, name))
    sdata = json.dumps(data) if isinstance(data, (dict, list)) else (data if isinstance(data, str) else "")
    for name in keys:
        if name in st and ("[" + name + "]") not in sdata and name in sdata:
            suspicious.append(("body", name))
    if suspicious:
        spots = ", ".join(f"{hn}→{name}" for hn, name in suspicious)
        log_event({"ev":"CALL_REJECT","agent":agent,"method":method,"url":url,
                   "why":f"bare key name (no [ ] brackets): {spots}"})
        print(f"REFUSED: found a key name WITHOUT [ ] brackets in {spots}. "
              f"Write it as [KEY_NAME] (e.g. Bearer [FAL_API_KEY]) so CipherGate swaps the real token.")
        return {"status": None, "body": "REFUSED: bare key name, missing [ ] brackets"}
    def sub(s):
        if isinstance(s, str) and "[" in s:
            out = s
            for name in keys:                      # ONLY granted names
                if name in st:
                    out = out.replace("[" + name + "]", unwrap(name, passphrase))
            return out
        return s
    final_headers = {k: sub(v) for k, v in headers.items()}
    final_url = sub(url)                          # query-string token substitution
    final_data = data
    if isinstance(final_data, (dict, list)):      # serialize object body before substitution
        final_data = json.dumps(final_data)
    if isinstance(final_data, str) and "[" in final_data:
        txt = final_data
        for name in keys:
            if name in st:
                txt = txt.replace("[" + name + "]", unwrap(name, passphrase))
        final_data = txt
    body = final_data.encode() if isinstance(final_data, str) else (final_data or bytes())
    req = urllib.request.Request(final_url, data=body or None, headers=final_headers, method=method)
    try:
        use_tmo = timeout if timeout is not None else CALL_TIMEOUT
        with urllib.request.urlopen(req, timeout=use_tmo) as resp:
            rbody = resp.read().decode(errors="replace")
        log_event({"ev":"CALL","agent":agent,"method":method,"url":url,
                   "keys":keys,"status":resp.status})
        print("STATUS:", resp.status)
        print("RESULT:"); print(_redact(rbody)[:2000])
        return {"status": resp.status, "body": _redact(rbody)}   # REDACTED so echoes can't leak secrets
    except Exception as ex:
        log_event({"ev":"CALL_FAIL","agent":agent,"method":method,"url":url,
                   "keys":keys,"why":str(ex)[:120]})
        print("CALL FAILED:", ex)
        return {"status": None, "body": f"CALL FAILED: {ex}"}

def cmd_call(argv, passphrase):
    # call <method> <url> --header "Name:[key_name]" ... [--data <json>]
    # Provider-agnostic substitute+send, same as the request path but run
    # MANUALLY by a caller (secrets never leave the vault). Only the keys named
    # in the header/body placeholders are substituted.
    if len(argv) < 3:
        print("usage: vault.py call <method> <url> [--header 'Name:[key_name]']... [--data <json>] [--timeout <secs>]")
        return 1
    method = argv[0].upper()
    url = argv[1]
    headers = {}
    data = None
    keys = []
    timeout = None
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
        elif argv[i] == "--timeout":
            try:
                timeout = int(argv[i+1])
            except (ValueError, IndexError):
                print("--timeout needs whole seconds (integer)"); return 1
            i += 2
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
    _exec_call(method, url, headers, data, keys, passphrase, "--manual", timeout)
    return 0

def cmd_recover():
    if not os.path.exists(KF): print("No store."); return 1
    rk = ask("VAULT_REC", "Off-site recovery key: ").strip()
    try:
        one = next(iter(load_store()))
        unwrap_rec(one, rk)
    except Exception:
        print("Recovery key rejected."); return 1
    p1 = ask("VAULT_NEW_PASS", "New passphrase: "); p2 = ask("VAULT_NEW_PASS", "Repeat: ")
    if p1 != p2: print("Mismatch."); return 1
    for s in list(load_store().keys()):
        plain = unwrap_rec(s, rk)
        add_key(s, plain, p1, rk)
    # Preserve the access map. Its HMAC is keyed to the LOST passphrase, so we
    # can't verify it here — but possession of the valid recovery key (proven
    # above by unwrap_rec) is the ownership gate. Read the raw data and re-sign
    # it under the new passphrase rather than wiping every agent registration.
    try:
        raw = json.load(open(AF))
        keys = raw.get("data", {}).get("keys", {})
    except Exception:
        keys = {}
    save_access(keys, p1)
    save_leases([], p1)
    save_pending({}, p1)
    log_event({"ev":"RECOVER","by":"batman","access_preserved":len(keys)})
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
        log_event({"ev":"TAMPER","file":"pending_or_lease","cmd":"update","outcome":"FAIL_CLOSED"})
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

def cmd_rotate_recovery_key(passphrase):
    """rotate-recovery-key  — retire a (possibly compromised) recovery key.
    Needs the vault passphrase (to prove it's Batman) + the OLD recovery key
    (to prove possession) + a NEW one (generated fresh). Re-wraps ONLY the
    recovery escrow on every key — the secrets and the passphrase envelope are
    untouched, so no secret is re-entered. The new key is printed once; keep it
    off-site and destroy the old copy."""
    if not os.path.exists(KF):
        print("No store. Run `init` first."); return 1
    store = load_store()
    if not store:
        print("The store is empty - nothing to rotate."); return 1
    # prove the passphrase is correct (same gate as `update`)
    try:
        first = next(iter(store))
        unwrap(first, passphrase)
    except Exception:
        print("Passphrase rejected. Start again with the correct vault passphrase.")
        return 1
    old_rk = ask("VAULT_REC", "OLD recovery key (the one being retired): ").strip()
    try:
        # prove the OLD recovery key currently unlocks a real entry
        unwrap_rec(next(iter(store)), old_rk)
    except Exception:
        print("OLD recovery key rejected - it does not unlock the store. Nothing changed.")
        return 1
    new_rk = new_rec_key()   # fresh 64-hex key, printed once
    if not valid_rec_key(new_rk):
        print("Could not mint a new recovery key. Nothing changed.")
        return 1
    for s in list(store.keys()):
        rekey_recovery_key(s, old_rk, new_rk)
    log_event({"ev":"ROTATE_RECOVERY_KEY","by":"batman","keys":len(store)})
    print(f"Recovery key rotated. {len(store)} key(s) re-wrapped (secrets untouched).")
    print(f"NEW RECOVERY KEY - keep this OFF-SITE (shown once):\n{new_rk}")
    print("The OLD recovery key no longer works. Destroy any saved copy of it.")
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

def _split(line):
    import shlex
    try:
        return shlex.split(line)
    except Exception:
        return line.split()

def _verify_agent_key(agent, key):
    """Verify an (agent, key) pair against the access map without needing the
    passphrase. Returns (ok, reason)."""
    try:
        raw = json.load(open(AF))
        keys = raw.get("data", {}).get("keys", {})
    except Exception:
        keys = {}
    if not key:
        return False, "No .env key presented - access denied."
    if not agent:
        return False, "No agent name given."
    ph = key_hash(key)
    if keys.get(agent) != ph:
        owner = next((p for p, h in keys.items() if h == ph), None)
        if owner and owner != agent:
            return False, f"ACCESS SNEAK: you flashed {owner}'s key as {agent}."
        return False, f"No key registered for {agent}."
    return True, ""

# ---------- Telegram inline approval (real YES/NO/OTHER buttons) ----------
def tg_post(token, method, payload):
    """One POST to the Telegram Bot API. Returns parsed JSON or None."""
    url = f"https://api.telegram.org/bot{token}/{method}"
    req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"},
                                 method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read().decode())
    except Exception as ex:
        log_event({"ev":"TG_ERR","method":method,"why":str(ex)[:120]})
        return None

def tg_send(passphrase, text, buttons=None, parse_mode=None):
    """Send a Telegram message to Batman. buttons = [[cb,label],...] renders an
    inline keyboard. No bot configured -> no-op (logs TG_UNCONFIGURED)."""
    tok = bot_token(passphrase)
    cid = bot_chat(passphrase)
    if not tok or not cid:
        log_event({"ev":"TG_UNCONFIGURED","text":text[:60]})
        return False
    payload = {"chat_id": cid, "text": text}
    if parse_mode: payload["parse_mode"] = parse_mode
    if buttons:
        payload["reply_markup"] = {"inline_keyboard": [
            [{"text": lbl, "callback_data": cb} for cb, lbl in buttons]]}
    return bool(tg_post(tok, "sendMessage", payload))

def tg_approval_button(passphrase, req_key, agent, http, keys, reason):
    """Push the approval ask to Batman with YES/NO/OTHER inline buttons.
    Sends as PLAIN TEXT (no HTML) so URLs with & ? etc never break parsing."""
    lines = ["CipherGate — approve this?",
             "",
             f"agent : {agent}",
             f"call  : {http}",
             f"keys  : {', '.join(keys) or '-'}",
             f"reason: {reason or '-'}",
             f"req   : {req_key}"]
    return tg_send(passphrase, "\n".join(lines), buttons=[
        (f"c:{req_key}:yes", "YES"),
        (f"c:{req_key}:no", "NO"),
        (f"c:{req_key}:other", "OTHER"),
    ], parse_mode=None)

def tg_poll_loop(passphrase, stop_event):
    """Background thread: long-poll Telegram getUpdates; on an inline-button
    callback (c:<req_key>:<yes|no|other>) from Batman, apply the verdict via the
    SAME shared path as `decide`. Runs until stop_event is set.

    OTHER is a two-step: the button tap alone cannot carry a typed reason. On an
    OTHER tap the vault asks Batman to type the reason, then the NEXT text
    message from him is captured as the `msg` and applied (agent sees
    "Batman says: <reason>")."""
    import time as _time
    offset = 0
    idle = 2
    awaiting_other = {}   # req_key -> the original callback message_id (for prompt edit)
    while not stop_event.is_set():
        tok = bot_token(passphrase)
        cid = bot_chat(passphrase)
        if not tok or not cid:
            _time.sleep(idle); idle = min(idle + 2, 10); continue
        # accept BOTH callback_query (button taps) and message (typed text)
        up = tg_post(tok, "getUpdates",
                     {"timeout": 15, "offset": offset,
                      "allowed_updates": ["callback_query", "message"]})
        if up is None:
            _time.sleep(idle); continue
        idle = 2
        for u in up.get("result", []):
            offset = u["update_id"] + 1
            # --- handle a typed MESSAGE (the OTHER reason) first ---
            msg = u.get("message")
            if msg is not None and awaiting_other:
                sender_id = str(msg.get("from", {}).get("id", ""))
                if sender_id == str(cid):
                    req_key, msg_id = next(iter(awaiting_other.items()))
                    reason = (msg.get("text") or "").strip()
                    del awaiting_other[req_key]
                    reason_txt = reason or "no reason given"
                    rc = _apply_verdict(passphrase, req_key, "other", reason_txt)
                    if rc == 0:
                        tg_post(tok, "sendMessage", {
                            "chat_id": cid,
                            "text": f"↩️ OTHER recorded — agent told: \"{reason_txt}\""})
                    else:
                        tg_post(tok, "sendMessage", {
                            "chat_id": cid,
                            "text": f"⚠️ could not record OTHER ({rc}). req {req_key}"})
                continue
            # --- handle a button callback (no-arg applies immediate verdict) ---
            cq = u.get("callback_query")
            if not cq: continue
            sender_id = str(cq.get("from", {}).get("id", ""))
            if sender_id != str(cid):
                log_event({"ev":"TG_FORGED","sender":sender_id,"outcome":"REFUSE"})
                continue
            data = cq.get("data", "")
            if not data.startswith("c:"): continue
            parts = data.split(":")
            if len(parts) < 3: continue
            req_key, verdict = parts[1], parts[2]
            if verdict not in ("yes", "no", "other"): continue
            cb_msg = cq.get("message", {})
            msg_id = cb_msg.get("message_id")
            chat_id = cb_msg.get("chat", {}).get("id") or cid
            if verdict == "other":
                # TWO-STEP: don't apply yet — ask Batman to type the reason
                awaiting_other[req_key] = msg_id
                tg_post(tok, "answerCallbackQuery",
                        {"callback_query_id": cq["id"], "text": "type the reason"})
                if msg_id:
                    tg_post(tok, "editMessageText", {
                        "chat_id": chat_id, "message_id": msg_id,
                        "text": f"↩️ OTHER for req {req_key} — TYPE your reason as the "
                                f"next message to this bot.\nThe agent will be told: "
                                f"\"Batman says: <your reason>\".",
                        "reply_markup": {"inline_keyboard": []}})
                continue
            # YES / NO apply immediately
            rc = _apply_verdict(passphrase, req_key, verdict)
            if rc == 0:
                decision = {"yes": "✅ APPROVED", "no": "❌ DENIED"}[verdict]
            else:
                decision = f"⚠️ error recording ({rc})"
            tg_post(tok, "answerCallbackQuery",
                    {"callback_query_id": cq["id"], "text": decision})
            if msg_id:
                tg_post(tok, "editMessageText", {
                    "chat_id": chat_id, "message_id": msg_id,
                    "text": f"{decision}\nreq {req_key}\n{verdict}",
                    "reply_markup": {"inline_keyboard": []}})

def cmd_run(argv, passphrase):
    """ciphergate run [--port N]  — CipherGate as a LOCAL SERVER for agents.

    Holds the vault passphrase ONCE, then listens on a local port (default
    18200). Real agent processes POST JSON requests to it; the server verifies
    each agent by (agent, key) against the access map, stages/decides/resolves,
    and answers JSON. This is how a REAL agent calls the vault — over the wire,
    not by typing into a terminal.

    Endpoints:
      POST /request   {"agent","key","method","url","expiry","reason","keys":[],"headers":{},"data"}
      POST /resolve   {"agent","key","req_key"}
      GET  /health
    """
    import http.server, threading
    if not passphrase:
        passphrase = _pass()
    port = 18200
    if argv and argv[0] == "--port" and len(argv) > 1:
        port = int(argv[1])

    # Verify the passphrase is right BEFORE starting the server: a wrong one would
    # make every later decrypt fail. Clean message + exit, no traceback.
    try:
        _verify_passphrase(passphrase)
    except RuntimeError as ex:
        print("WRONG PASSPHRASE — the process could not unlock the vault. "
              "Start again with the correct passphrase.")
        return 1

    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def _reply(self, code, obj):
            b = json.dumps(obj).encode()
            self.send_response(code); self.send_header("Content-Type","application/json")
            self.send_header("Content-Length", str(len(b))); self.end_headers()
            self.wfile.write(b)
        def _body(self):
            ln = int(self.headers.get("Content-Length", 0) or 0)
            d = self.rfile.read(ln) if ln else b""
            try: return json.loads(d.decode())
            except Exception: return {}
        def do_GET(self):
            if self.path.startswith("/health"):
                self._reply(200, {"status":"up","vault":VT})
            else:
                self._reply(404, {"error":"not found","hint":"POST /request or /resolve, GET /health"})
        def do_POST(self):
            p = self._body()
            if self.path == "/request":
                agent = p.get("agent",""); key = p.get("key","")
                ok, why = _verify_agent_key(agent, key)
                if not ok:
                    log_event({"ev":"ACCESS_DENIED","runner":agent,"via":"server","outcome":"DENY","why":why})
                    self._reply(403, {"ok":False,"denied":why})
                    return
                args = [p.get("method","GET").upper(), p.get("url",""), str(p.get("expiry",0))]
                if p.get("reason"): args.append(p["reason"])
                if p.get("keys"): args += ["--keys", ",".join(p["keys"])]
                for hn,hv in (p.get("headers") or {}).items():
                    args += ["--header", f"{hn}:{hv}"]
                if p.get("data") is not None:
                    args += ["--data", json.dumps(p["data"]) if isinstance(p["data"],(dict,list)) else str(p["data"])]
                if p.get("timeout") is not None:
                    args += ["--timeout", str(int(p["timeout"]))]
                # args are already clean per-token values from JSON; pass them
                # through as-is so substitution survives (headers must not be
                # re-split at internal spaces, which used to lose the placeholder).
                # THREAD-SAFE identity: _verify_agent_key(agent,key) above already
                # proved WHO this is, so pass it straight to cmd_request instead of
                # mutating the process-global os.environ (that would race across
                # concurrent agent threads). Each /request runs on its own thread
                # (ThreadingHTTPServer), so a long render on thread A does NOT
                # block agent B's request on thread B.
                with _STATE_LOCK:
                    rc = cmd_request(args, passphrase, agent_override=agent, presented_key=key)
                if isinstance(rc, dict):
                    # LEASE path already ran the call -> relay the RESULT now, no wait.
                    self._reply(rc.get("status") is not None and 200 or 502,
                                {"ok": rc.get("status") is not None,
                                 "outcome": "approved" if rc.get("status") is not None else "call_failed",
                                 "call_status": rc.get("status"),
                                 "result": rc.get("body")})
                    return
                if rc != 0:
                    self._reply(403, {"ok":False,"note":"denied before staging"})
                    return
                req_key = ""
                try:
                    pending, st = load_pending(passphrase)
                    for kk, ee in pending.items():
                        if ee.get("agent")==agent and ee.get("status")=="pending":
                            req_key = kk
                except Exception:
                    pass
                # SYNCHRONOUS WAIT: the agent's call blocks here until Batman
                # decides (within the wait window). This is the real flow:
                # agent sends, waits, gets the response. No separate resolve trip.
                deadline = now_epoch() + WAIT_MIN*60
                verdict = None
                while now_epoch() < deadline:
                    try:
                        pending, st = load_pending(passphrase)
                        e = pending.get(req_key)
                    except Exception:
                        e = None
                    if e and e.get("status") == "pending":
                        time.sleep(0.5); continue
                    if e and e.get("status") in ("yes","no","other"):
                        verdict = e["status"]; break
                    if e is None:
                        break  # entry gone -> verdict consumed
                    time.sleep(0.5)
                if verdict == "yes":
                    # resolve it here: pop + grant(if lease) + make the call.
                    # cmd_resolve identifies the agent from the pending entry, so
                    # no os.environ mutation here — this is thread-safe.
                    rr = cmd_resolve([req_key], passphrase)
                    # rr is now {"status":..,"body":..} when the call ran -> relay the RESULT to the agent
                    if isinstance(rr, dict):
                        self._reply(200, {"ok":True,"req_key":req_key,"outcome":"approved",
                                          "call_status":rr.get("status"),
                                          "result":rr.get("body"),
                                          "lease":rr.get("lease") or {}})
                    else:
                        self._reply(200, {"ok":True,"req_key":req_key,"outcome":"approved","rc":rr})
                elif verdict == "no" or verdict == "other":
                    # capture Batman's OTHER message BEFORE resolve pops the entry
                    deny_msg = ""
                    try:
                        pend_tmp, _st = load_pending(passphrase)
                        if req_key in pend_tmp:
                            deny_msg = pend_tmp[req_key].get("msg", "")
                    except Exception:
                        pass
                    # cmd_resolve identifies the agent from the pending entry, so
                    # no env mutation; thread-safe.
                    rrc = cmd_resolve([req_key], passphrase)
                    if verdict == "other":
                        # agent gets the written reason back, not an empty quote
                        self._reply(403, {"ok":False,"outcome":"denied","by_batman":deny_msg})
                    else:
                        self._reply(403, {"ok":False,"outcome":"denied"})
                else:
                    self._reply(408, {"ok":False,"req_key":req_key,
                        "outcome":"timeout",
                        "note":f"Batman hasn't answered yet. Wait then retry with this key: {req_key}"})
            elif self.path == "/resolve":
                agent = p.get("agent",""); key = p.get("key","")
                ok, why = _verify_agent_key(agent, key)
                if not ok:
                    self._reply(403, {"ok":False,"denied":why}); return
                req_key = p.get("req_key","")
                # cmd_resolve identifies the agent from the pending entry, so no
                # env mutation is needed and this is thread-safe.
                rc = cmd_resolve([req_key], passphrase)
                self._reply(200, {"ok":True,"rc":rc})
            else:
                self._reply(404, {"error":"unknown endpoint"})

    # ThreadingHTTPServer: each /request runs on its OWN thread, so one agent's
    # long upstream call (e.g. a 200s fal render) never blocks another agent's
    # request. The _STATE_LOCK guards the shared state files (pending/leases)
    # so concurrent staging / leasing is safe.
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", port), H)
    print(f"CipherGate server is running on http://127.0.0.1:{port}. "
          f"It holds the passphrase in memory, so keep this window open (Ctrl-C to stop).")
    print(f"Agents call it over this local address with their agent name + .env key.")
    stop = threading.Event()
    poll_t = threading.Thread(target=tg_poll_loop, args=(passphrase, stop), daemon=True)
    poll_t.start()
    print("Telegram inline-YES/NO poller started." if (bot_token(passphrase) and bot_chat(passphrase))
          else "No Telegram bot configured — approvals via `ciphergate decide <key> yes|no`. Configure with `ciphergate bot set`.")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    stop.set()
    return 0



def main():
    os.chmod(VT, 0o700) if os.path.exists(VT) else None
    if len(sys.argv) < 2:
        _banner(); print("\nNo command was given. CipherGate is the API-key vault.\n"
                         "Run `ciphergate --help` for the full plain-English guide,\n"
                         "or `ciphergate status` to see where things stand.")
        return 0
    c = sys.argv[1]
    if c in ("--help", "-h", "help"):
        _banner(); print(__doc__); return 0
    args = sys.argv[2:]
    no_pass = c in ("init", "list", "ledger", "recover", "run")
    passphrase = "" if no_pass else _pass()
    if c == "run":
        return cmd_run(args, passphrase)
    table = {
        "init": lambda: cmd_init(),
        "add": lambda: cmd_add(args, passphrase),
        "list": lambda: cmd_list(),
        "show": lambda: cmd_show(args, passphrase),
        "keygen": lambda: cmd_keygen(args, passphrase),
        "access": lambda: cmd_access(args, passphrase),
        "request": lambda: cmd_request(args, passphrase),
        "pending": lambda: cmd_pending(args, passphrase),
        "decide": lambda: cmd_decide(args, passphrase),
        "resolve": lambda: cmd_resolve(args, passphrase),
        "lease": lambda: cmd_lease(passphrase),
        "call": lambda: cmd_call(args, passphrase),
        "recover": lambda: cmd_recover(),
        "update": lambda: cmd_update(passphrase),
        "rotate-recovery-key": lambda: cmd_rotate_recovery_key(passphrase),
        "status": lambda: cmd_status(passphrase),
        "bot": lambda: cmd_bot(args, passphrase),
        "ledger": lambda: cmd_ledger(),
    }
    fn = table.get(c)
    if not fn: print("unknown cmd"); return 1
    r = fn()
    # some commands (resolve) return a dict to the SERVER so it can relay the
    # call result. For CLI use, treat a dict as success and print it; only ints
    # are exit codes.
    if isinstance(r, dict):
        print(r)
        return 0
    return r

if __name__ == "__main__":
    sys.exit(main() or 0)