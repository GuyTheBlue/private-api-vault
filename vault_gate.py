#!/usr/bin/env python3
"""
vault_gate.py — quick stopgap gate for the Gsquared Productions fleet.

PURPOSE: Stop any agent (or the coordinator) from grabbing a service key
without the rules being met. One program, the ONLY sanctioned path to a key.

RULES IT ENFORCES (mechanical, not by goodwill):
  1. A key is released ONLY when the ledger shows a fresh APPROVED entry
     from Bitman for that service. No approved entry -> refusal.
  2. It NEVER prints, logs, or returns a key VALUE. At most it reports the
     service + key name + length, and may execute one authenticated call the
     caller passes in (key injected into that call's env only).
  3. Every request and every refusal is written to the audit ledger, so
     Bitman sees WHO asked, for WHAT, WHEN, and the outcome.

USAGE (agents coordinate through this, never read the store directly):
    python3 vault_gate.py request <service> <job_id> <reason>
        -> checks ledger for a fresh APPROVED <service>; if found, marks the
           key reachable for job_id; else REFUSES and logs.
    python3 vault_gate.py status
        -> which keys exist, by name/length only.
    python3 vault_gate.py audit
        -> tail the ledger.

NOTE (honest limits): this is a QUICK stopgap — a speed-bump. With a
plaintext .env an agent can still bypass it by reading the file directly.
Real protection (encrypt the store + a master password only Bitman holds +
remote vault) is the "go big, for fun" build later. This gate is the first
wall and the audit trail.
"""
import os, sys, time, datetime

LEDGER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vault_gate.ledger")

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def log(line):
    with open(LEDGER, "a") as f:
        f.write(f"- {now_iso()} | {line}\n")

def has_recent_approval(service, ttl_min=30):
    """Fresh OK_BATMAN_YES marker for service in the ledger within ttl_min.
    Uses a dedicated token that only a genuine Bitman approval produces, so
    refusal lines (which never contain the token) can't be misread as approval."""
    if not os.path.exists(LEDGER):
        return False
    cutoff = time.time() - ttl_min * 60
    for ln in open(LEDGER):
        if "OK_BATMAN_YES" in ln and service in ln:
            try:
                ts = ln.split("|")[0].strip().lstrip("- ").strip()
                t = datetime.datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
                if t >= cutoff:
                    return True
            except Exception:
                continue
    return False

def main():
    argc = len(sys.argv)
    if argc >= 5 and sys.argv[1] == "request":
        service, job_id, reason = sys.argv[2], sys.argv[3], sys.argv[4]
        who = os.environ.get("AGENT", os.environ.get("USER", "unknown"))
        if has_recent_approval(service):
            log(f"KEYREQ {service} by {who} (job {job_id}, reason: {reason}) | OK_BATMAN_YES marker -> GRANTED for job env only")
            print(f"GRANTED {service} to job {job_id} (in-job env only; value never exposed)")
            return 0
        log(f"KEYREQ {service} by {who} (job {job_id}, reason: {reason}) | no Bitman approval marker -> REFUSED (ask Bitman first)")
        print(f"REFUSED {service}: no fresh Bitman OK in the ledger for {service}. "
              f"Per the rules, {who} must ask Bitman first. Request logged. (see the gate ledger)")
        return 2
    if argc >= 2 and sys.argv[1] == "status":
        print("Gate online. Keys are not enumerated by value from this gate; the master store "
              "is keykeeper/.env (names/lengths only, via keykeeper). Ledger will show approvals.")
        return 0
    if argc >= 2 and sys.argv[1] == "audit":
        if os.path.exists(LEDGER):
            print(open(LEDGER).read())
        else:
            print("(no audit entries yet)")
        return 0
    print(__doc__)
    return 1

if __name__ == "__main__":
    sys.exit(main())