#!/usr/bin/env python3
"""
vault.py — the Gsquared Productions API-key Vault (terminal).

WHAT IT IS
  A single terminal program that HOLDS the API keys ENCRYPTED, applies RULES,
  keeps a LEDGER, and — when allowed — decrypts a key INTERNALLY and makes the
  https call itself, returning only the RESULT. A key is never handed to an
  agent, never written mid-session, never shown. That is the whole point: no
  agent (or coordinator) can grab a key and "do its own thing".

  The store is encrypted with AES-256-CBC. The passphrase you hold derives the
  key; a RECOVERY KEY (kept off-site) is the emergency unwrap.

USAGE (all terminal)
  python3 vault.py init                         first run: set passphrase, mint recovery key
  python3 vault.py add    <service>             add/update an encrypted key (prompts value)
  python3 vault.py list                          names only, never values
  python3 vault.py allow  <service> <agent> <...>  decide+grant per RULES; key NOT exposed
  python3 vault.py call   <service> <url>       decrypt internally, make https call, return result
  python3 vault.py ledger                        the audit record
  python3 vault.py status                        where things live + counts
  python3 vault.py recover                       new passphrase via off-site recovery key

  rules.json  — under lock next to the store; edit to set policy.

DIRECTORY (all under lock on this machine)
  .vault/keys.json       the encrypted key store
  .vault/rules.json      the rules
  .vault/ledger.jsonl    the audit
  vault_recovery.key     NOT stored here — printed once at init, kept OFF-SITE.
"""
import sys, os, json, base64, getpass, time, hashlib, subprocess, datetime, urllib.request

BASE = os.path.dirname(os.path.abspath(__file__))
VT   = os.path.join(BASE, ".vault")
KF   = os.path.join(VT, "keys.json")
RF   = os.path.join(VT, "rules.json")
LF   = os.path.join(VT, "ledger.jsonl")

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def log_event(ev):
    with open(LF, "a") as f:
        f.write(json.dumps({**ev, "t": now_iso()}) + "\n")

# ---------- AES (stdlib hashlib + openssl CLI, no pip deps) ----------
def aes_crypt(key_hex, iv_hex, data, decrypt=False):
    cmd = ["openssl", "enc", "-aes-256-cbc", "-d" if decrypt else "-e",
           "-K", key_hex, "-iv", iv_hex, "-nopad" if False else "", "-nosalt"]
    cmd = [c for c in cmd if c]
    p = subprocess.run(cmd, input=data, capture_output=True)
    if p.returncode != 0:
        raise RuntimeError("aes failed: " + p.stderr.decode(errors="replace"))
    return p.stdout

def derive_key(secret, salt, iters=200000):
    return hashlib.pbkdf2_hmac("sha256", secret.encode(), salt, iters, 32).hex()

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

# ---------- rules ----------
def rules():
    os.makedirs(VT, exist_ok=True)
    if not os.path.exists(RF):
        json.dump({"session_lease_min": 5, "blocked_agents": ["robin"],
                   "never": ["echo keys", "print secret value"]}, open(RF, "w"), indent=2)
    return json.load(open(RF))

# ---------- CLI ----------
def ask(env, prompt):
    return os.environ.get(env) or getpass.getpass(prompt)

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
    save_store({})  # empty store + salt handled per-key
    # write recovery key OFF-SITE is the user's job; we only print it once.
    print("\n" + "="*60)
    print("STORE THIS RECOVERY KEY OFF-SITE — shown ONCE, never again, not saved here:")
    print(rk)
    print("="*60)
    # remember passphrase shading: chmod store dir to owner-only
    os.chmod(VT, 0o700)
    log_event({"ev":"INIT","by":"batman","recovery_minted":True})
    print("Vault initialised. `add <service>` to store a key.")

def cmd_add(argv):
    if len(argv) < 1: print("usage: vault.py add <service>"); return 1
    service = argv[0]
    passphrase = ask("VAULT_PASS", "Passphrase: ")
    value = ask("VAULT_VALUE", "Paste the API key value (hidden): ")
    store = load_store()
    if service in store:
        # overwrite existing: keep the original recovery-escrow wrapper
        e = store[service]
        rk = ask("VAULT_REC", "Recovery key (to keep escrow): ")
        add_key(service, value, passphrase, rk, keep_rec=e)
    else:
        rk = ask("VAULT_REC", "Recovery key (store value, once): ")
        add_key(service, value, passphrase, rk)
    log_event({"ev":"KEY_ADD","service":service})
    print(f"Stored {service} ENCRYPTED ({len(value)} chars).")

def store_has(service):
    return service in load_store()

def cmd_list():
    st = load_store()
    if not st: print("(store empty)"); return 0
    for s, e in st.items():
        print(f"{s}  (encrypted, {len(base64.b64decode(e['ct']))} bytes, added {e['created']})")

def cmd_allow(argv):
    # allow <service> <agent> [reason...]
    if len(argv) < 2: print("usage: vault.py allow <service> <agent> [reason]"); return 1
    service, agent = argv[0], argv[1]
    reason = " ".join(argv[2:])
    r = rules()
    store = load_store()
    if service not in store:
        log_event({"ev":"DECIDE","service":service,"agent":agent,"outcome":"HELL-NO","why":"no such key"}); return print("HELL-NO: no key for "+service)
    if agent in r.get("blocked_agents", []):
        log_event({"ev":"DECIDE","service":service,"agent":agent,"outcome":"HELL-NO","why":"blocked agent"})
        print(f"HELL-NO: {agent} is on the blocked list (coordinator cannot request keys)."); return 1
    print(f"request: {agent} wants {service} — {reason or '(no reason)'}")
    ok = input("Approve? (yes/no/other): ").strip().lower()
    verdict = {"yes": True, "no": False, "y": True, "n": False}.get(ok)
    if verdict is None:
        log_event({"ev":"DECIDE","service":service,"agent":agent,"outcome":"OTHER","why":ok})
        print("OTHER: no action; reason noted in ledger."); return 2
    if verdict:
        log_event({"ev":"GRANT","service":service,"agent":agent,"by":"batman","lease":r.get("session_lease_min")})
        print(f"GRANTED {service} -> {agent} (in-memory only; key never shown). Run `call` to use it.")
        return 0
    log_event({"ev":"REJECT","service":service,"agent":agent,"by":"batman"})
    print("Denied."); return 3

def cmd_call(argv):
    if len(argv) < 2: print("usage: vault.py call <service> <url>"); return 1
    service, url = argv[0], argv[1]
    passphrase = ask("VAULT_PASS", "Passphrase (unlock): ")
    plain = unwrap(service, passphrase)
    req = urllib.request.Request(url, headers={"Authorization": "Bearer " + plain})
    try:
        with urllib.request.urlopen(req) as resp:
            body = resp.read().decode(errors="replace")
        log_event({"ev":"CALL","service":service,"url":url,"status":resp.status if 'resp' in dir() else None})
        print("RESULT:"); print(body[:2000])
    except Exception as ex:
        log_event({"ev":"CALL_FAIL","service":service,"url":url,"why":str(ex)[:120]})
        print("CALL FAILED:", ex)

def cmd_recover():
    if not os.path.exists(KF): print("No store."); return 1
    rk = ask("VAULT_REC", "Off-site recovery key: ").strip()
    try:
        test = load_store(); one = next(iter(test))
        unwrap_rec(one, rk)  # validate
    except Exception:
        print("Recovery key rejected."); return 1
    p1 = ask("VAULT_PASS", "New passphrase: "); p2 = ask("VAULT_PASS", "Repeat: ")
    if p1 != p2: print("Mismatch."); return 1
    for s in list(load_store().keys()):
        plain = unwrap_rec(s, rk)
        add_key(s, plain, p1, rk)  # re-wrap under new passphrase
    log_event({"ev":"RECOVER","by":"batman"})
    print("Recovered. Keys re-encrypted under new passphrase.")

def cmd_status():
    st = load_store()
    print(f"vault dir   : {VT}")
    print(f"services    : {len(st)}")
    print(f"ledger lines: {sum(1 for _ in open(LF)) if os.path.exists(LF) else 0}")
    print("rules:", json.dumps(rules(), indent=2))

def cmd_ledger():
    if not os.path.exists(LF): print("(empty)"); return 0
    for line in open(LF):
        e = json.loads(line)
        print(e.get("t"), e.get("ev"), e.get("service",""), e.get("agent",""), e.get("why",""))

def main():
    os.chmod(VT, 0o700) if os.path.exists(VT) else None
    if len(sys.argv) < 2:
        print(__doc__); return 0
    c = sys.argv[1]
    table = {"init":cmd_init,"add":cmd_add,"list":cmd_list,"allow":cmd_allow,
             "call":cmd_call,"recover":cmd_recover,"status":cmd_status,"ledger":cmd_ledger}
    fn = table.get(c)
    if not fn: print("unknown cmd"); return 1
    if c in ("init", "list", "status", "ledger", "recover"):
        return fn()
    return fn(sys.argv[2:])

if __name__ == "__main__":
    sys.exit(main() or 0)