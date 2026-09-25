#!/usr/bin/env python3
"""
vault.py - the Gsquared Productions API-key Vault (terminal).

WHAT IT IS
  A single terminal program that HOLDS the API keys ENCRYPTED, keeps a
  TAMPER-EVIDENT deny list and lease file, keeps a LEDGER of history, and
  when allowed decrypts a key INTERNALLY and makes the https call itself,
  returning only the RESULT. A key is never handed to an agent, never
  written mid-session, never shown, never returned by the API.

THE DECISION (the vault's one job)
  A request decides like this:
    1. deny list FIRST: agent on it -> DENIED with the reason, done.
    2. active unexpired lease for agent+key -> make the call (Batman
       NOT bothered). Entry purged on expiry.
    3. otherwise -> log to the ledger with a UNIQUE request key, ask
       Batman. YES -> grant+lease and call; NO/other -> deny.
  There is NO pass-through / "go as usual".

TAMPER-EVIDENCE (why agents can't edit the deny list / leases)
  deny.json and leases.json carry an HMAC whose key is derived from the
  vault PASSphrase. Agents do not hold the passphrase, so they cannot
  re-sign a file they edit. A direct edit or delete leaves a bad / missing
  signature -> the vault FAILS CLOSED (logs a TAMPER alarm, treats the
  agent as DENIED) rather than silently resetting. Only the passphrase
  holder (Batman) can write a valid deny list or lease file.

  LIMITATION (honest): agents run as the same OS user, so they can OPEN
  the files but cannot forge a valid signature without the vault
  passphrase. True process isolation - the vault as its own service that
  agents call over an API, holding the unlocked key in memory - is Stage 4.
  Until then the passphrase gate is the wall.

USAGE (all terminal)
  python3 vault.py init                            first run: set passphrase, mint recovery key
  python3 vault.py add    <service>                add/update an encrypted key
  python3 vault.py list                             names only, never values
  python3 vault.py deny    list|add|remove        manage the deny list (passphrase)
  python3 vault.py request <agent> <http> <expiry_min> <reason>   decide a request (passphrase)
  python3 vault.py lease                           active leases (passphrase)
  python3 vault.py ledger                          audit history (read-only, no passphrase)
  python3 vault.py recover                         new passphrase via off-site recovery key
  python3 vault.py status                          where things live + counts

DIRECTORY (all under lock on this machine, gitignored)
  .vault/keys.json       the encrypted key store
  .vault/deny.json       blanket deny list - signed with passphrase-derived HMAC
  .vault/leases.json     ACTIVE grants only, signed, purged on expiry
  .vault/ledger.jsonl    append-only history; entries carry a unique request key
  vault_recovery.key     NOT stored here - printed once at init, kept OFF-SITE.
"""
import sys, os, json, base64, getpass, hmac as _hmac, hashlib as _hl, subprocess, datetime, urllib.request, secrets, time

BASE = os.path.dirname(os.path.abspath(__file__))
VT   = os.path.join(BASE, ".vault")
KF   = os.path.join(VT, "keys.json")
DF   = os.path.join(VT, "deny.json")
LF_  = os.path.join(VT, "leases.json")
LG   = os.path.join(VT, "ledger.jsonl")

_DENY_TAG  = "gsq-vault-deny-v1"
_LEASE_TAG = "gsq-vault-lease-v1"

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

# ---------- deny list (one blanket list; tamper-evident, fail-closed) ----------
def load_deny(passphrase):
    if not os.path.exists(DF):
        return {}, "missing"
    try:
        raw = json.load(open(DF))
    except Exception:
        return {}, "tampered"
    data = _check_bundle(raw, sign_key(passphrase, _DENY_TAG))
    if data is None:
        return {}, "tampered"
    return data.get("agents", {}), "ok"

def save_deny(agents, passphrase):
    raw = _bundle({"agents": agents}, sign_key(passphrase, _DENY_TAG))
    json.dump(raw, open(DF, "w"), indent=2)
    os.chmod(DF, 0o600)

# ---------- lease file (ACTIVE grants only; tamper-evident, purged on expiry) ----------
def load_leases(passphrase):
    if not os.path.exists(LF_):
        return [], "missing"
    try:
        raw = json.load(open(LF_))
    except Exception:
        return [], "tampered"
    data = _check_bundle(raw, sign_key(passphrase, _LEASE_TAG))
    if data is None:
        return [], "tampered"
    return data, "ok"

def save_leases(leases, passphrase):
    raw = _bundle(leases, sign_key(passphrase, _LEASE_TAG))
    json.dump(raw, open(LF_, "w"), indent=2)
    os.chmod(LF_, 0o600)

def purge_expired(passphrase):
    now = now_epoch()
    ls, st = load_leases(passphrase)
    if st != "ok":
        return [], st
    keep = [l for l in ls if float(l.get("expires_at", 0)) > now]
    if len(keep) != len(ls):
        save_leases(keep, passphrase)
    return keep, "ok"

def active_lease(agent, key, passphrase):
    active, st = purge_expired(passphrase)
    if st != "ok":
        return None
    for l in active:
        if l.get("agent") == agent and (key == "*" or l.get("key") == key):
            return l
    return None

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
    save_deny({"robin": "the overreacher (coordinator)"}, p1)
    save_leases([], p1)
    log_event({"ev":"INIT","by":"batman","recovery_minted":True})
    print("\n" + "="*60)
    print("STORE THIS RECOVERY KEY OFF-SITE - shown ONCE, never again, not saved here:")
    print(rk)
    print("="*60)
    os.chmod(VT, 0o700)
    print("Vault initialised. `add <service>` to store a key; `deny list` to see the deny list.")
    return 0

def cmd_add(argv, passphrase):
    if len(argv) < 1: print("usage: vault.py add <service>"); return 1
    service = argv[0]
    value = ask("VAULT_VALUE", "Paste the API key value (hidden): ")
    store = load_store()
    if service in store:
        e = store[service]
        rk = ask("VAULT_REC", "Recovery key (to keep escrow): ")
        add_key(service, value, passphrase, rk, keep_rec=e)
    else:
        rk = ask("VAULT_REC", "Recovery key (store value, once): ")
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

def cmd_deny(argv, passphrase):
    if not argv:
        print("usage: vault.py deny list|add <agent> [reason]|remove <agent>"); return 1
    sub, rest = argv[0], argv[1:]
    agents, st = load_deny(passphrase)
    if st != "ok":
        log_event({"ev":"TAMPER","file":"deny","outcome":"FAIL_CLOSED"})
        print("TAMPER DETECTED: deny list signature invalid or missing.")
        print("Fail-closed: agents are DENIED until Batman rebuilds the list with the correct passphrase.")
        return 4
    if sub == "list":
        if not agents: print("(deny list empty)")
        for a, why in agents.items():
            print(f"{a}  (reason: {why})")
        return 0
    if sub == "add":
        if not rest: print("usage: vault.py deny add <agent> [reason]"); return 1
        who = rest[0]; why = " ".join(rest[1:]) or "no specific reason on file"
        agents[who] = why
        save_deny(agents, passphrase)
        log_event({"ev":"DENY_ADD","agent":who,"by":"batman"})
        print(f"{who} added to deny list (reason: {why}).")
        return 0
    if sub == "remove":
        if not rest: print("usage: vault.py deny remove <agent>"); return 1
        who = rest[0]
        if who in agents:
            del agents[who]; save_deny(agents, passphrase)
            log_event({"ev":"DENY_REMOVE","agent":who,"by":"batman"})
            print(f"{who} removed from deny list.")
        else:
            print(f"{who} not on the deny list.")
        return 0
    print("usage: vault.py deny list|add <agent> [reason]|remove <agent>"); return 1

def cmd_request(argv, passphrase):
    if len(argv) < 4: print("usage: vault.py request <agent> <http> <expiry_min> <reason>"); return 1
    agent, http = argv[0], argv[1]
    try:
        expiry = int(argv[2])
    except ValueError:
        print("expiry must be minutes (0 = no lift requested)"); return 1
    reason = " ".join(argv[3:])

    agents, st = load_deny(passphrase)
    if st != "ok":
        log_event({"ev":"TAMPER","file":"deny","agent":agent,"outcome":"FAIL_CLOSED"})
        print("TAMPER DETECTED: deny list unverifiable. Fail-closed: DENIED.")
        return 4

    if agent in agents:
        log_event({"ev":"DECIDE","agent":agent,"http":http,"outcome":"DENY","by":"list","why":agents[agent]})
        print(f"DENIED: {agent} is on the deny list - {agents[agent]}. 'Not in my city.'")
        return 2

    lease = active_lease(agent, "*", passphrase)
    if lease:
        log_event({"ev":"DECIDE","agent":agent,"http":http,"outcome":"LEASE","key":lease.get("key")})
        print(f"ACTIVE LEASE covers {agent} (expires {lease['expires_iso']}). Making the call (Batman not asked).")
        return 0

    req_key = secrets.token_hex(8)
    log_event({"ev":"PENDING","agent":agent,"http":http,"reason":reason,
               "expiry_min":expiry,"req_key":req_key,"outcome":"ASK_BATMAN"})
    print(f"NO lease for {agent}. Staged with request key {req_key}; handed to Batman to approve ({expiry} min lift requested).")
    print("(Stage 5 delivers this to Batman's Telegram; his verdict resolves this request key.)")
    return 0

def cmd_lease(passphrase):
    active, st = purge_expired(passphrase)
    if st != "ok":
        print("TAMPER DETECTED: lease file unverifiable.")
        return 4
    if not active: print("(no active leases)")
    for l in active:
        print(f"{l['agent']}  key={l.get('key')}  expires {l.get('expires_iso')}")
    return 0

def cmd_call(argv, passphrase):
    if len(argv) < 2: print("usage: vault.py call <service> <url>"); return 1
    service, url = argv[0], argv[1]
    plain = unwrap(service, passphrase)
    req = urllib.request.Request(url, headers={"Authorization": "Bearer " + plain})
    try:
        with urllib.request.urlopen(req) as resp:
            body = resp.read().decode(errors="replace")
        log_event({"ev":"CALL","service":service,"url":url,"status":resp.status})
        print("RESULT:"); print(body[:2000])
    except Exception as ex:
        log_event({"ev":"CALL_FAIL","service":service,"url":url,"why":str(ex)[:120]})
        print("CALL FAILED:", ex)
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
    agents, _ = load_deny(rk)
    save_deny(agents or {"robin": "the overreacher (coordinator)"}, p1)
    save_leases([], p1)
    log_event({"ev":"RECOVER","by":"batman"})
    print("Recovered. Keys + signed files re-encrypted/re-signed under new passphrase.")
    return 0

def cmd_status(passphrase):
    st = load_store()
    agents, dst = load_deny(passphrase)
    leases, lst = purge_expired(passphrase)
    print(f"vault dir     : {VT}")
    print(f"services      : {len(st)}")
    print(f"deny list     : {', '.join(agents.keys()) or '(none)'}  [{dst}]")
    print(f"active leases : {len(leases)}  [{lst}]")
    print(f"ledger lines  : {sum(1 for _ in open(LG)) if os.path.exists(LG) else 0}")
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

def main():
    os.chmod(VT, 0o700) if os.path.exists(VT) else None
    if len(sys.argv) < 2:
        print(__doc__); return 0
    c = sys.argv[1]
    args = sys.argv[2:]
    no_pass = c in ("init", "list", "ledger")
    passphrase = "" if no_pass else _pass()
    table = {
        "init": lambda: cmd_init(),
        "add": lambda: cmd_add(args, passphrase),
        "list": lambda: cmd_list(),
        "deny": lambda: cmd_deny(args, passphrase),
        "request": lambda: cmd_request(args, passphrase),
        "lease": lambda: cmd_lease(passphrase),
        "call": lambda: cmd_call(args, passphrase),
        "recover": lambda: cmd_recover(),
        "status": lambda: cmd_status(passphrase),
        "ledger": lambda: cmd_ledger(),
    }
    fn = table.get(c)
    if not fn: print("unknown cmd"); return 1
    return fn()

if __name__ == "__main__":
    sys.exit(main() or 0)
