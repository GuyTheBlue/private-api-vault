#!/usr/bin/env bash
# Regression suite for ciphergate.py - runs WITHOUT touching the real store (always
# copies to an isolated scratch dir). Run after ANY change to ciphergate.py.
#   Usage: bash regression.sh [path/to/ciphergate.py]
set -uo pipefail
VAULT_PY="${1:-/Volumes/Secure/private_api_vault/ciphergate.py}"
SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT
cp "$VAULT_PY" "$SCRATCH/"
# legacy alias so the helper fns' `python3 vault.py` invocations still resolve
cp "$VAULT_PY" "$SCRATCH/vault.py"
cd "$SCRATCH"
PASS=testpass123
FAIL=0
step() { printf '\n== %s ==\n' "$1"; }
ok()   { printf 'PASS: %s\n' "$1"; }
bad()  { printf 'FAIL: %s\n' "$1"; FAIL=1; }
mint() { local p="$1"; local k; k=$(VAULT_PASS=$PASS python3 vault.py keygen "$p" | grep '^VAULT_AGENT_KEY=' | cut -d= -f2); eval "KEY_$p=\$k"; printf '%s' "$k" > "/tmp/vk_$p"; }
as_agent() { local prof="$1"; shift; local k; eval "k=\$KEY_$prof"; HERMES_HOME="/Users/guymeaker/.hermes/profiles/$prof" VAULT_AGENT_KEY="$k" VAULT_PASS=$PASS python3 vault.py request "$@" 2>&1; }

# ---------- 1. init ----------
step "init"
REC=$(VAULT_PASS=$PASS python3 vault.py init | grep -A1 'RECOVERY KEY' | tail -1 | tr -d '[:space:]')
export VAULT_REC=$REC
[ -n "$REC" ] && ok "init minted recovery key" || bad "init failed"

# ---------- 2. mint keys for the profiles later tests use ----------
step "mint .env keys"
for p in link oracle x_other x_no x_timeout evil; do mint "$p"; done
ok "keys minted for all tested profiles"

# fake API key in the store so key-scoped lease tests have something to lease
VAULT_PASS=$PASS VAULT_VALUE=dummy_fal_key_ABC123 VAULT_REC=$REC python3 vault.py add fal >/dev/null 2>&1
ok "stored dummy 'fal' key for lease tests"

# ---------- 3. identity: NO key -> denied ----------
step "no key denied"
R3=$(HERMES_HOME=/Users/guymeaker/.hermes/profiles/link VAULT_PASS=$PASS python3 vault.py request GET https://x 0 r 2>&1)
echo "$R3" | grep -qi "denied" && ok "no key -> denied" || bad "no key NOT denied: $R3"

# ---------- 4. identity: flash another profile's key -> ACCESS SNEAK ----------
step "ACCESS SNEAK (flash another profile's key)"
R4=$(HERMES_HOME=/Users/guymeaker/.hermes/profiles/link VAULT_AGENT_KEY="$KEY_evil" VAULT_PASS=$PASS python3 vault.py request GET https://x 5 "sneak" 2>&1)
echo "$R4" | grep -qi "ACCESS SNEAK\|not yours\|not registered" && ok "rogue key while running as link denied" || bad "sneak NOT caught: $R4"

# ---------- 5. valid identity -> flow reaches decision ----------
step "valid identity requests"
R5=$(as_agent oracle GET https://api.fal.ai/render 5 "render pic")
echo "$R5" | grep -qi "request key" && ok "valid identity reaches decision" || bad "valid identity blocked: $R5"

# ---------- 6. lease: live key-scoped lease short-circuits, Batman not asked ----------
step "lease short-circuits"
python3 - <<'PY'
import json,hmac,hashlib,time
tag=b'gsq-vault-lease-v1'; key=hmac.new(tag,b'testpass123',hashlib.sha256).digest()
ls=[{'agent':'link','keys':['fal'],'http':'https://api.vast.ai','expires_at':time.time()+3600,'expires_iso':'2099-01-01T00:00:00Z'}]
canon=json.dumps(ls,sort_keys=True,separators=(',',':')).encode()
json.dump({'data':ls,'sig':hmac.new(key,canon,hashlib.sha256).hexdigest()},open('.vault/leases.json','w'),indent=2)
PY
R6=$(as_agent link GET https://api.vast.ai 5 "grab" --keys fal)
echo "$R6" | grep -qi "ACTIVE LEASE" && ok "live lease covers link for [fal], Batman not asked" || bad "lease not used: $R6"
# NOT-covered key -> must NOT short-circuit (a fal lease never covers docker)
R6b=$(as_agent link GET https://api.vast.ai 5 "grab docker" --keys docker)
echo "$R6b" | grep -qi "unknown key" && ok "lease doesn't cover ungranted key (fail-closed)" || bad "docker NOT blocked: $R6b"

# ---------- 7. stage request for decisions ----------
step "stage request for decisions"
export VAULT_WAIT_MIN=0
K1=$(as_agent oracle GET https://api.fal.ai/render 5 "render pic" | grep -o 'request key [a-f0-9]*' | awk '{print $3}')
[ -n "$K1" ] && ok "request staged ($K1)" || bad "no request key"
PV=$(VAULT_PASS=$PASS python3 vault.py pending)
echo "$PV" | grep -q "$K1" && ok "pending shows staged entry" || bad "pending entry missing"

# ---------- 8. decide + resolve YES -> key-scoped lease or one-off call ----------
step "verdict YES grants lease on requested key"
VAULT_WAIT_MIN=0
K1=$(as_agent oracle GET https://api.fal.ai/render 5 "render pic" --keys fal | grep -o 'request key [a-f0-9]*' | awk '{print $3}')
[ -n "$K1" ] && ok "key-scoped request staged ($K1)" || bad "no request key for key-scoped request"
VAULT_PASS=$PASS python3 vault.py decide "$K1" yes >/dev/null
R8=$(VAULT_PASS=$PASS python3 vault.py resolve "$K1")
echo "$R8" | grep -qi "Lease" && ok "YES resolve grants lease for [fal]" || bad "YES resolve failed: $R8"
LV=$(VAULT_PASS=$PASS python3 vault.py lease)
echo "$LV" | grep -q "fal" && echo "$LV" | grep -q oracle && ok "key-scoped lease created (oracle+fal)" || bad "key-scoped lease not created"

# ---------- 9. decide OTHER -> resolve denies + verbatim message ----------
step "verdict OTHER denies + verbatim"
K2=$(as_agent x_other GET https://api.vast.ai 10 "grab box" | grep -o 'request key [a-f0-9]*' | awk '{print $3}')
MSG="message me on Instagram, tell me what's going on"
VAULT_PASS=$PASS python3 vault.py decide "$K2" other "$MSG" >/dev/null
R9=$(VAULT_PASS=$PASS python3 vault.py resolve "$K2")
echo "$R9" | grep -qi "Denied" && echo "$R9" | grep -qF "$MSG" && ok "OTHER denies + relays message" || bad "OTHER path wrong: $R9"

# ---------- 10. decide NO -> resolve denies ----------
step "verdict NO denies"
K3=$(as_agent x_no GET https://api.r2 5 verify | grep -o 'request key [a-f0-9]*' | awk '{print $3}')
VAULT_PASS=$PASS python3 vault.py decide "$K3" no >/dev/null
R10=$(VAULT_PASS=$PASS python3 vault.py resolve "$K3")
echo "$R10" | grep -qi "Denied" && ok "NO resolve denies" || bad "NO resolve wrong: $R10"

# ---------- 11. resolve pending past window ----------
step "pending timeout (window 0)"
K4=$(as_agent x_timeout GET https://api.x 5 newthing | grep -o 'request key [a-f0-9]*' | awk '{print $3}')
R11=$(VAULT_PASS=$PASS python3 vault.py resolve "$K4")
echo "$R11" | grep -qi "come back later" && ok "pending past window tells agent to come back" || bad "timeout wrong: $R11"

# ---------- 12. no plaintext anywhere ----------
step "no plaintext leak"
LEAK=""
for f in .vault/keys.json .vault/access.json .vault/leases.json .vault/ledger.jsonl; do
  grep -q 'ABC123\|SECRETVALUE\|dummy' "$f" 2>/dev/null && LEAK="$LEAK $f"
done
[ -z "$LEAK" ] && ok "no plaintext in store/access/leases/ledger" || bad "LEAK:$LEAK"

# ---------- 13. crypto: add key + substitute+send vs LOCAL STUB ----------
step "crypto + substitute-send vs stub"
VAULT_PASS=$PASS VAULT_VALUE=dummy_fal_key_ABC123 VAULT_REC=$REC python3 vault.py add fal >/dev/null 2>&1
if grep -q 'ABC123' .vault/keys.json; then bad "key leaked at rest"; else ok "key encrypted at rest"; fi
PORT=18191
cp /Volumes/Secure/private_api_vault/stub_endpoint.py .
(python3 stub_endpoint.py $PORT >/dev/null 2>&1 &)
sleep 1
OUT=$(VAULT_PASS=$PASS python3 vault.py call GET "http://127.0.0.1:$PORT/anything" --header "Authorization: Bearer [fal]" 2>/dev/null)
echo "$OUT" | grep -q 'Bearer dummy_fal_key_ABC123' && ok "secret substituted into header internally" || bad "substitution into header failed"
pkill -f "stub_endpoint.py $PORT" 2>/dev/null
if grep -q 'ABC123' .vault/keys.json; then bad "key leaked after call"; else ok "key still encrypted after call"; fi

# ---------- 14. update password: old dead, new live, recovery intact ----------
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
OLD=$(VAULT_PASS=$PASS python3 vault.py lease 2>&1)
echo "$OLD" | grep -qi "TAMPER\|rejected" && ok "old passphrase rejected after update" || bad "old passphrase still accepted"
NEW=$(VAULT_PASS=passV2 python3 vault.py lease 2>&1)
echo "$NEW" | grep -q oracle && ok "new passphrase works / lease re-signed" || bad "new passphrase failed"
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
elif [ "$BEFORE" = "$AFTER" ]; then ok "recovery key still decrypts after re-key"
else bad "recovery escrow broken by update"; fi
PASS=passV2

# ---------- 15. sensitivity gate: no-use refused, no-lease; flag on lease refused ----------
step "sensitivity gate"
# NO-USE: credential/db endpoint refused even with a live lease present
S1=$(as_agent oracle GET https://api.digitalocean.com/v2/databases/abc/credentials 5 "get db creds")
echo "$S1" | grep -qi "DENIED" && echo "$S1" | grep -qi "no-use" \
  && ok "no-use credential endpoint refused" || bad "no-use NOT caught: $S1"
S1b=$(as_agent oracle GET KUBECONFIG 5 "grab kube" )
echo "$S1b" | grep -qi "DENIED" && ok "no-use kubeconfig refused" || bad "kubeconfig NOT caught: $S1b"
# FLAG: sensitive-but-not-forbidden -> staged with FLAGGED warning
S2=$(as_agent oracle GET https://api.digitalocean.com/v2/billing/history 5 "check billing")
echo "$S2" | grep -qi "FLAGGED" && ok "sensitive request flagged for Batman" || bad "billing NOT flagged: $S2"
# FLAG during an active lease -> refused (can't smuggle via lease)
S3=$(as_agent link GET https://api.digitalocean.com/v2/billing/history 5 "sneak billing via lease")
echo "$S3" | grep -qi "WARNING\|flagged\|refusing" && ok "flagged request refused despite live lease" \
  || bad "flagged-not-refused-via-lease: $S3"

# ---------- 16. bot config: set stores encrypted; info masks token; no plaintext; clear ----------
step "bot config"
BC1=$(VAULT_BOT_TOKEN=dummy_bot_token_ABC987 VAULT_BOT_CHAT=971695123 VAULT_PASS=$PASS VAULT_REC=$REC python3 vault.py bot set)
echo "$BC1" | grep -qi "stored ENCRYPTED" && ok "bot set stores config encrypted" \
  || bad "bot set did not report encrypted store: $BC1"
BC2=$(VAULT_PASS=$PASS python3 vault.py bot info)
echo "$BC2" | grep -qi "configured: YES" && ok "bot info shows configured" || bad "bot info not configured: $BC2"
grep -q "dummy_bot_token_ABC987" .vault/keys.json && bad "bot TOKEN stored in PLAINTEXT!" || ok "no bot token plaintext at rest"
BC3=$(VAULT_PASS=$PASS python3 vault.py bot clear)
echo "$BC3" | grep -qi "cleared" && ok "bot clear removes config" || bad "bot clear failed: $BC3"
BC4=$(VAULT_PASS=$PASS python3 vault.py bot info)
echo "$BC4" | grep -qi "configured: NO" && ok "bot info reflects cleared after clear" || bad "bot info still configured after clear"

# ---------- 17. clean-error guard: bad recovery key rejected, no traceback, nothing stored ----------
step "clean recovery-key error"
CE=$(VAULT_PASS=$PASS VAULT_VALUE=zzz VAULT_REC=not-a-real-hex-key python3 vault.py add __badRec__ 2>&1)
echo "$CE" | grep -qi "INVALID recovery key" && ok "bad recovery key rejected with clean message" || bad "no clean reject: $CE"
! python3 vault.py list | grep -q "__badRec__" && ok "bad rec attempt stored nothing" || bad "bad rec attempt WROTE a key!"

# ---------- 18. KEY-SCOPED LEASE: a lease covers ONLY its granted keys, never *
#   A CLOUDFLARE-pair lease must NOT cover DOCKER_TOKEN.
step "key-scoped lease isolation"
# extra keys for the isolation scenario
VAULT_PASS=$PASS VAULT_VALUE=cf_key VAULT_REC=$REC python3 vault.py add CLOUDFLARE_R2_ACCESS_KEY_ID >/dev/null 2>&1
VAULT_PASS=$PASS VAULT_VALUE=cf_secret VAULT_REC=$REC python3 vault.py add CLOUDFLARE_R2_SECRET_ACCESS_KEY >/dev/null 2>&1
VAULT_PASS=$PASS VAULT_VALUE=docker_secret VAULT_REC=$REC python3 vault.py add DOCKER_TOKEN >/dev/null 2>&1
# ask a CLOUDFLARE-pair lease
K5=$(as_agent link POST https://api.cloudflare.io/v2 10 "push to R2" --keys CLOUDFLARE_R2_ACCESS_KEY_ID,CLOUDFLARE_R2_SECRET_ACCESS_KEY | grep -o 'request key [a-f0-9]*' | awk '{print $3}')
[ -n "$K5" ] && ok "cloudflare-pair request staged" || bad "no cloudflare request key"
VAULT_PASS=$PASS python3 vault.py decide "$K5" yes >/dev/null
R18=$(VAULT_PASS=$PASS python3 vault.py resolve "$K5")
echo "$R18" | grep -qi "Lease" && ok "cloudflare-pair lease granted" || bad "no cloudflare lease: $R18"
# same agent, DIFFERENT key (docker) with that lease live -> must NOT short-circuit
R18b=$(as_agent link POST https://api.docker.io/v2 5 "push image" --keys DOCKER_TOKEN)
echo "$R18b" | grep -qi "request key" && ok "DOCKER not covered by CLOUDFLARE lease (staged anew)" \
  || { echo "$R18b" | grep -qi "ACTIVE LEASE" && bad "LEAK: docker covered by cloudflare lease" \
      || bad "docker-isolation unexpected: $R18b"; }

# ---------- 19. resolve replay: a granted request key cannot be re-resolved ----------
step "resolve replay (no double-grant)"
# reuse a fresh request, decide yes, resolve, then resolve AGAIN -> must refuse
K6=$(as_agent x_other POST https://api.r2/v2 0 "one-off replay" --keys fal | grep -o 'request key [a-f0-9]*' | awk '{print $3}')
[ -n "$K6" ] && ok "replay request staged" || bad "no replay request key"
VAULT_PASS=$PASS python3 vault.py decide "$K6" yes >/dev/null
R19=$(VAULT_PASS=$PASS python3 vault.py resolve "$K6")
R19b=$(VAULT_PASS=$PASS python3 vault.py resolve "$K6")
echo "$R19b" | grep -qi "No pending entry" && ok "second resolve refused (entry purged after grant)" \
  || bad "REPLAY: same key resolved twice: $R19b"

# ---------- 20. recover preserves the access map (not wiped) ----------
step "recover preserves access map"
# grant link an access key first so there's something to preserve
LK=$(VAULT_PASS=$PASS python3 vault.py keygen link 2>/dev/null | grep VAULT_AGENT_KEY | cut -d= -f2)
VAULT_PASS=$PASS python3 vault.py access add link "$LK" >/dev/null 2>&1
ACCT_BEFORE=$(VAULT_PASS=$PASS python3 vault.py access list | grep -c link)
RC=$(VAULT_PASS=$PASS VAULT_NEW_PASS=passV3 VAULT_REC=$REC python3 vault.py recover 2>&1)
echo "$RC" | grep -qi "Recovered" && ok "recover succeeded" || bad "recover failed: $RC"
ACCT_AFTER=$(VAULT_PASS=passV3 python3 vault.py access list 2>&1 | grep -c link)
[ "$ACCT_BEFORE" = "$ACCT_AFTER" ] && [ "$ACCT_BEFORE" -ge 1 ] && ok "recover preserved link's access registration" \
  || bad "recover WIPED the access map (before=$ACCT_BEFORE after=$ACCT_AFTER)"

echo
if [ "$FAIL" -eq 0 ]; then echo "ALL REGRESSION TESTS PASS ($SCRATCH, cleaned)"; else echo "REGRESSION FAILURES DETECTED"; exit 1; fi
