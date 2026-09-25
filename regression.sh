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
export VAULT_REC=$REC
[ -n "$REC" ] && ok "init minted recovery key" || bad "init failed"

# mint a unique .env key for each agent the later tests impersonate
GKEY=$(VAULT_PASS=$PASS python3 vault.py keygen spielberg | grep '^VAULT_AGENT_KEY=' | cut -d= -f2)
>robinkey; >linkkey; >oraclekey; >xotherkey; >xnokey; >xtimekey
for who in robin link oracle x_other x_no x_timeout; do
  VAULT_PASS=$PASS python3 vault.py keygen "$who" 2>/dev/null | grep '^VAULT_AGENT_KEY=' | cut -d= -f2 > "/tmp/vk_$who"
done
RKEY=$(cat /tmp/vk_robin); LKEY=$(cat /tmp/vk_link); OKEY=$(cat /tmp/vk_oracle)
XOK=$(cat /tmp/vk_x_other); XNK=$(cat /tmp/vk_x_no); XTK=$(cat /tmp/vk_x_timeout)
green_key(){ export VAULT_AGENT_KEY=$1; }

# ---------- 2. deny list seeded signed ----------
step "deny seeded"
OUT=$(VAULT_PASS=$PASS python3 vault.py deny list)
echo "$OUT" | grep -q robin && ok "deny list seeded with robin" || bad "robin not seeded"

# ---------- 3. denied agent refused ----------
step "denied agent refused"
VIR=$(green_key "$RKEY"; VAULT_AGENT_KEY="$RKEY" VAULT_PASS=$PASS python3 vault.py request robin https://x 0 r; echo "rc=$?")
echo "$VIR" | grep -qi "DENIED" && ok "robin request denied" || bad "robin was not denied"

# ---------- 4. TAMPER: edit deny.json (strip robin) ----------
step "tamper via edit"
python3 - <<'PY'
import json
r=json.load(open('.vault/deny.json')); r['data']['agents'].pop('robin',None)
json.dump(r,open('.vault/deny.json','w'))
PY
E=$(green_key "$RKEY"; VAULT_AGENT_KEY="$RKEY" VAULT_PASS=$PASS python3 vault.py request robin https://x 0 r; echo "rc=$?")
echo "$E" | grep -qi "TAMPER" && ok "edit detected, fail-closed" || bad "edit NOT detected"

# ---------- 5. TAMPER: delete deny.json ----------
step "tamper via delete"
rm -f .vault/deny.json
D=$(green_key "$RKEY"; VAULT_AGENT_KEY="$RKEY" VAULT_PASS=$PASS python3 vault.py request robin https://x 0 r; echo "rc=$?")
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
CR=$(green_key "$LKEY"; VAULT_AGENT_KEY="$LKEY" VAULT_PASS=$PASS python3 vault.py request link https://api.vast.ai 5 "grab box"; echo "rc=$?")
echo "$CR" | grep -qi "ACTIVE LEASE" && ok "lease covers link, Batman not asked" || bad "lease not used"

# ---------- 11. stage request -> pending entry with unique key ----------
step "stage request"
export VAULT_WAIT_MIN=0
K1=$(green_key "$OKEY"; VAULT_AGENT_KEY="$OKEY" VAULT_PASS=$PASS python3 vault.py request oracle https://api.fal.ai/render 5 "render pic" \
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
K2=$(green_key "$XOK"; VAULT_AGENT_KEY="$XOK" VAULT_PASS=$PASS python3 vault.py request x_other https://api.vast.ai 10 'grab box' \
     | grep -o 'request key [a-f0-9]*' | awk '{print $3}')
MSG="message me on Instagram, tell me what's going on"
VAULT_PASS=$PASS python3 vault.py decide "$K2" other "$MSG" >/dev/null
R2=$(VAULT_PASS=$PASS python3 vault.py resolve "$K2")
echo "$R2" | grep -qi "Denied" && echo "$R2" | grep -qF "$MSG" \
  && ok "OTHER denies + relays Batman's message" || bad "OTHER path wrong"

# ---------- 14. decide NO -> resolve denies ----------
step "verdict NO denies"
K3=$(green_key "$XNK"; VAULT_AGENT_KEY="$XNK" VAULT_PASS=$PASS python3 vault.py request x_no https://api.r2 5 verify \
     | grep -o 'request key [a-f0-9]*' | awk '{print $3}')
VAULT_PASS=$PASS python3 vault.py decide "$K3" no >/dev/null
R3=$(VAULT_PASS=$PASS python3 vault.py resolve "$K3")
echo "$R3" | grep -qi "Denied" && ok "NO resolve denies" || bad "NO resolve wrong"

# ---------- 15. resolve at WAIT_MIN=0 with no verdict -> not approved, come back ----------
step "pending timeout (window 0)"
K4=$(green_key "$XTK"; VAULT_AGENT_KEY="$XTK" VAULT_PASS=$PASS python3 vault.py request x_timeout https://api.x 5 newthing \
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

# ---------- 17. update password: old dead, new live, recovery intact ----------
step "update password (re-key)"
python3 - <<'PY'
import json,base64,subprocess,os
def aes_crypt(k,iv,d,decrypt=False):
    p=subprocess.run(['openssl','enc','-aes-256-cbc','-d' if decrypt else '-e','-K',k,'-iv',iv,'-nosalt'],input=d,capture_output=True);return p.stdout
e=json.load(open('.vault/keys.json'))['fal']
dk=aes_crypt(os.environ['VAULT_REC'],e['iv3'],base64.b64decode(e['dk_rec']),decrypt=True).hex()
ct=aes_crypt(dk,e['iv1'],base64.b64decode(e['ct']),decrypt=True)
open('/tmp/rec_before.txt','w').write(ct.decode())
PY
U=$(VAULT_PASS=$PASS VAULT_NEW_PASS=passV2 python3 vault.py update)
echo "$U" | grep -qi "updated" && ok "update reported success" || bad "update failed"
# old pass must now FAIL on a pass-requiring command
OLD=$(VAULT_PASS=$PASS python3 vault.py deny list 2>&1)
echo "$OLD" | grep -qi "TAMPER\|rejected" && ok "old passphrase rejected after update" || bad "old passphrase still accepted"
# new pass must work
NEW=$(VAULT_PASS=passV2 python3 vault.py deny list 2>&1)
echo "$NEW" | grep -q robin && ok "new passphrase works / deny re-signed" || bad "new passphrase failed"
# ct + recovery escrow UNCHANGED => recovery key must still decrypt to same value
BEFORE=$(cat /tmp/rec_before.txt)
python3 - <<'PY'
import json,base64,subprocess,os
def aes_crypt(k,iv,d,decrypt=False):
    p=subprocess.run(['openssl','enc','-aes-256-cbc','-d' if decrypt else '-e','-K',k,'-iv',iv,'-nosalt'],input=d,capture_output=True);return p.stdout
e=json.load(open('.vault/keys.json'))['fal']
dk=aes_crypt(os.environ['VAULT_REC'],e['iv3'],base64.b64decode(e['dk_rec']),decrypt=True).hex()
ct=aes_crypt(dk,e['iv1'],base64.b64decode(e['ct']),decrypt=True)
open('/tmp/rec_after.txt','w').write(ct.decode())
PY
AFTER=$(cat /tmp/rec_after.txt)
if [ -z "$BEFORE" ] || [ -z "$AFTER" ]; then bad "recovery decrypt produced empty value"
elif [ "$BEFORE" = "$AFTER" ]; then ok "recovery key still decrypts same value after re-key"
else bad "recovery escrow broken by update"; fi
PASS=passV2

# ---------- 18. identity: legit .env key passes ----------
step "identity legit key"
VAULT_PASS=passV2 python3 vault.py access add testbot testbotkey123 2>/dev/null
A18=$(green_key "testbotkey123"; VAULT_AGENT_KEY=testbotkey123 VAULT_PASS=passV2 python3 vault.py request testbot https://api.y 5 "probe" 2>&1)
echo "$A18" | grep -qi "request key\|no lease" && ok "legit key lets request through to decision" || bad "legit key wrongly blocked: $A18"

# ---------- 19. identity: no key / wrong key denied ----------
step "identity no key denied"
A19=$(green_key ""; VAULT_AGENT_KEY= VAULT_PASS=passV2 python3 vault.py request testbot https://api.y 5 "probe" 2>&1)
echo "$A19" | grep -qi "DENIED\|Access denied" && ok "no key denied" || bad "no key NOT denied: $A19"
A19b=$(green_key "wrongkey"; VAULT_AGENT_KEY=wrongkey VAULT_PASS=passV2 python3 vault.py request testbot https://api.y 5 "probe" 2>&1)
echo "$A19b" | grep -qi "DENIED\|not yours\|not registered" && ok "wrong key denied" || bad "wrong key NOT denied: $A19b"

# ---------- 20. identity: ACCESS SNEAK (flash another profile's .env key) ----------
step "identity ACCESS SNEAK"
A20=$(green_key "testbotkey123"; VAULT_AGENT_KEY=testbotkey123 VAULT_PASS=passV2 python3 vault.py request evil https://api.y 5 "probe" 2>&1)
echo "$A20" | grep -qi "ACCESS SNEAK\|not yours" && ok "rogue key (evil flashing testbot's) denied + logged" || bad "ACCESS SNEAK not caught: $A20"

echo
if [ "$FAIL" -eq 0 ]; then echo "ALL REGRESSION TESTS PASS ($SCRATCH, cleaned)"; else echo "REGRESSION FAILURES DETECTED"; exit 1; fi