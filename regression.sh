#!/usr/bin/env bash
# Regression suite for vault.py — runs WITHOUT touching the real store (always
# copies to an isolated scratch dir). Run after ANY change to vault.py.
#   Usage: bash regression.sh [path/to/vault.py]
set -uo pipefail
VAULT_PY="${1:-/Volumes/Secure/private_api_vault/vault.py}"
SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT
cp "$VAULT_PY" "$SCRATCH/"
cd "$SCRATCH"
PASS=testpass123
FAIL=0
step() { printf '\n== %s ==\n' "$1"; }
ok()   { printf 'PASS: %s\n' "$1"; }
bad()  { printf 'FAIL: %s\n' "$1"; FAIL=1; }

# ---------- 1. init ----------
step "init"
REC=$(VAULT_PASS=$PASS python3 vault.py init | grep -A1 'RECOVERY KEY' | tail -1 | tr -d '[:space:]')
[ -n "$REC" ] && ok "init minted recovery key" || bad "init failed"

# ---------- 2. deny list seeded signed ----------
step "deny seeded"
OUT=$(VAULT_PASS=$PASS python3 vault.py deny list)
echo "$OUT" | grep -q robin && ok "deny list seeded with robin" || bad "robin not seeded"

# ---------- 3. denied agent refused ----------
step "denied agent refused"
VIR=$(VAULT_PASS=$PASS python3 vault.py request robin https://x 0 r; echo "rc=$?")
echo "$VIR" | grep -qi "DENIED" && ok "robin request denied" || bad "robin was not denied"

# ---------- 4. TAMPER: edit deny.json (strip robin) ----------
step "tamper via edit"
python3 - <<'PY'
import json
r=json.load(open('.vault/deny.json')); r['data']['agents'].pop('robin',None)
json.dump(r,open('.vault/deny.json','w'))
PY
E=$(VAULT_PASS=$PASS python3 vault.py request robin https://x 0 r; echo "rc=$?")
echo "$E" | grep -qi "TAMPER" && ok "edit detected, fail-closed" || bad "edit NOT detected"

# ---------- 5. TAMPER: delete deny.json ----------
step "tamper via delete"
rm -f .vault/deny.json
D=$(VAULT_PASS=$PASS python3 vault.py request robin https://x 0 r; echo "rc=$?")
echo "$D" | grep -qi "TAMPER" && ok "delete detected, fail-closed" || bad "delete NOT detected"

# ---------- 6. rebuilt deny accepts legit Batman add/remove ----------
step "legit deny re-sign"
python3 - <<'PY'
import json,hmac,hashlib
tag=b'gsq-vault-deny-v1'; key=hmac.new(tag,b'testpass123',hashlib.sha256).digest()
agents={"robin":"the overreacher (coordinator)"}
canon=json.dumps({"agents":agents},sort_keys=True,separators=(',',':')).encode()
sig=hmac.new(key,canon,hashlib.sha256).hexdigest()
json.dump({"data":{"agents":agents},"sig":sig},open('.vault/deny.json','w'),indent=2)
PY
A=$(VAULT_PASS=$PASS python3 vault.py deny add spielberg "needs oversight"; echo "rc=$?")
L=$(VAULT_PASS=$PASS python3 vault.py deny list)
echo "$L" | grep -q spielberg && ok "legit add re-signs" || bad "legit add failed"

# ---------- 7. no plaintext in any file ----------
step "no plaintext leak"
LEAK=""
for f in .vault/keys.json .vault/deny.json .vault/leases.json .vault/ledger.jsonl; do
  grep -q 'ABC123\|SECRETVALUE\|dummy' "$f" 2>/dev/null && LEAK="$LEAK $f"
done
[ -z "$LEAK" ] && ok "no plaintext in store/deny/leases/ledger" || bad "LEAK:$LEAK"

# ---------- 8. lease purge-on-expiry ----------
step "lease purge on expiry"
python3 - <<'PY'
import json,time,os
os.makedirs('.vault',exist_ok=True)
json.dump([{'agent':'link','key':'vast','expires_at':time.time()+3600,'expires_iso':'2099-01-01T00:00:00Z'}],
          open('.vault/leases.json','w'))
PY
# re-sign leases bundle (helper below writes raw list; rebuild signed)
python3 - <<'PY'
import json,hmac,hashlib,time
tag=b'gsq-vault-lease-v1'; key=hmac.new(tag,b'testpass123',hashlib.sha256).digest()
ls=[{'agent':'link','key':'vast','expires_at':time.time()+3600,'expires_iso':'2099-01-01T00:00:00Z'}]
canon=json.dumps(ls,sort_keys=True,separators=(',',':')).encode()
json.dump({'data':ls,'sig':hmac.new(key,canon,hashlib.sha256).hexdigest()},open('.vault/leases.json','w'),indent=2)
PY
LL=$(VAULT_PASS=$PASS python3 vault.py lease)
echo "$LL" | grep -q link && ok "live lease present (Batman not asked)" || bad "lease missing"

# ---------- 9. clean agent with live lease -> makes call, no Batman ----------
step "lease short-circuits to call"
CR=$(VAULT_PASS=$PASS python3 vault.py request link https://api.vast.ai 5 "grab box"; echo "rc=$?")
echo "$CR" | grep -qi "ACTIVE LEASE" && ok "lease covers link, Batman not asked" || bad "lease not used"

# ---------- 11. stage request -> pending entry with unique key ----------
step "stage request"
export VAULT_WAIT_MIN=0
K1=$(VAULT_PASS=$PASS python3 vault.py request oracle https://api.fal.ai/render 5 "render pic" \
     | grep -o 'request key [a-f0-9]*' | awk '{print $3}')
[ -n "$K1" ] && ok "request staged with unique key $K1" || bad "no request key"
PV=$(VAULT_PASS=$PASS python3 vault.py pending)
echo "$PV" | grep -q "$K1" && ok "pending shows staged entry" || bad "pending entry missing"

# ---------- 12. decide + resolve: YES -> lease ----------
step "verdict YES grants lease"
VAULT_PASS=$PASS python3 vault.py decide "$K1" yes >/dev/null
R1=$(VAULT_PASS=$PASS python3 vault.py resolve "$K1")
echo "$R1" | grep -qi "Approved" && ok "YES resolve approves + leases" || bad "YES resolve failed"
LV=$(VAULT_PASS=$PASS python3 vault.py lease)
echo "$LV" | grep -q oracle && ok "lease created for oracle" || bad "lease not created"

# ---------- 13. decide OTHER -> resolve denies + verbatim message ----------
step "verdict OTHER denies + verbatim message"
K2=$(VAULT_PASS=$PASS python3 vault.py request x_other https://api.vast.ai 10 'grab box' \
     | grep -o 'request key [a-f0-9]*' | awk '{print $3}')
MSG="message me on Instagram, tell me what's going on"
VAULT_PASS=$PASS python3 vault.py decide "$K2" other "$MSG" >/dev/null
R2=$(VAULT_PASS=$PASS python3 vault.py resolve "$K2")
echo "$R2" | grep -qi "Denied" && echo "$R2" | grep -qF "$MSG" \
  && ok "OTHER denies + relays Batman's message" || bad "OTHER path wrong"

# ---------- 14. decide NO -> resolve denies ----------
step "verdict NO denies"
K3=$(VAULT_PASS=$PASS python3 vault.py request x_no https://api.r2 5 verify \
     | grep -o 'request key [a-f0-9]*' | awk '{print $3}')
VAULT_PASS=$PASS python3 vault.py decide "$K3" no >/dev/null
R3=$(VAULT_PASS=$PASS python3 vault.py resolve "$K3")
echo "$R3" | grep -qi "Denied" && ok "NO resolve denies" || bad "NO resolve wrong"

# ---------- 15. resolve at WAIT_MIN=0 with no verdict -> not approved, come back ----------
step "pending timeout (window 0)"
K4=$(VAULT_PASS=$PASS python3 vault.py request x_timeout https://api.x 5 newthing \
     | grep -o 'request key [a-f0-9]*' | awk '{print $3}')
R4=$(VAULT_PASS=$PASS python3 vault.py resolve "$K4")
echo "$R4" | grep -qi "come back later" && ok "pending past window tells agent to come back" || bad "pending timeout wrong"

# ---------- 16. crypto: add key + substitute+send via LOCAL STUB ----------
step "crypto + substitute-send vs stub"
VAULT_PASS=$PASS VAULT_VALUE=dummy_fal_key_ABC123 VAULT_REC=$REC python3 vault.py add fal >/dev/null 2>&1
if grep -q 'ABC123' .vault/keys.json; then bad "key leaked at rest"; else ok "key encrypted at rest"; fi
# start the local stub endpoint on a scratch port
PORT=18191
cp /Volumes/Secure/private_api_vault/stub_endpoint.py .
(python3 stub_endpoint.py $PORT >/dev/null 2>&1 &) 
sleep 1
OUT=$(VAULT_PASS=$PASS python3 vault.py call GET "http://127.0.0.1:$PORT/anything" \
      --header "Authorization: Bearer [fal]" 2>/dev/null)
echo "$OUT" | grep -q 'Bearer dummy_fal_key_ABC123' && ok "secret substituted into header internally" \
  || bad "substitution into header failed"
pkill -f "stub_endpoint.py $PORT" 2>/dev/null
# secret must NOT be visible outside the call (still encrypted at rest)
if grep -q 'ABC123' .vault/keys.json; then bad "key leaked after call"; else ok "key still encrypted after call"; fi

echo
if [ "$FAIL" -eq 0 ]; then echo "ALL REGRESSION TESTS PASS ($SCRATCH, cleaned)"; else echo "REGRESSION FAILURES DETECTED"; exit 1; fi