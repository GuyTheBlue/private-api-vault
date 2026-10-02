#!/usr/bin/env bash
# Regression suite for ciphergate.py - runs WITHOUT touching the real store (always
# copies to an isolated scratch dir). Run after ANY change to ciphergate.py.
#   Usage: bash regression.sh [path/to/ciphergate.py]
set -uo pipefail
# CRITICAL: clear every vault env var the suite could inherit from the shell.
# If any VAULT_PASS/VAULT_REC/VAULT_NEW_PASS/VAULT_VALUE leaks in from outside,
# it silently satisfies a prompt and MASKS a bug (the recover-prompt bug was
# hidden exactly this way). The suite owns its env entirely.
unset VAULT_PASS VAULT_REC VAULT_NEW_PASS VAULT_VALUE VAULT_AGENT_KEY VAULT_BOT_TOKEN VAULT_BOT_CHAT VAULT_WAIT_MIN HERMES_HOME 2>/dev/null || true
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
for p in link oracle x_other x_no x_timeout evil x_bare x_clear; do mint "$p"; done
ok "keys minted for all tested profiles"

# fake API key in the store so key-scoped lease tests have something to lease
VAULT_PASS=$PASS VAULT_VALUE=dummy_fal_key_ABC123 VAULT_REC=$REC python3 vault.py add fal >/dev/null 2>&1
ok "stored dummy 'fal' key for lease tests"

# ---------- 2b. show <service> reveals the stored VALUE (Batman-only, passphrase-gated) ----------
step "show reveals a stored key's value"
SH=$(VAULT_PASS=$PASS python3 vault.py show fal 2>&1)
echo "$SH" | grep -q "dummy_fal_key_ABC123" && ok "show displays the real stored value" || bad "show failed to reveal value: $SH"
SD=$(VAULT_PASS=wrongpass python3 vault.py show fal 2>&1)
echo "$SD" | grep -qi "decrypt\|passphrase\|No key" && ok "show with wrong passphrase is refused" || bad "show leaked with wrong pass: $SD"
SN=$(VAULT_PASS=$PASS python3 vault.py show nonexistent_service 2>&1)
echo "$SN" | grep -qi "No key stored" && ok "show refuse unknown service" || bad "show should refuse unknown: $SN"

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

# ---------- 7b. pending clear wipes the waiting list ----------
step "pending clear wipes the wait list"
KC=$(as_agent x_clear GET https://api.x 5 clear-me | grep -o 'request key [a-f0-9]*' | awk '{print $3}')
[ -n "$KC" ] && ok "staged request for clearing ($KC)" || bad "no key to clear"
CLR=$(VAULT_PASS=$PASS python3 vault.py pending clear)
echo "$CLR" | grep -qi "Cleared" && ok "pending clear reports cleared" || bad "pending clear failed: $CLR"
AFTER=$(VAULT_PASS=$PASS python3 vault.py pending)
echo "$AFTER" | grep -q "$KC" && bad "cleared entry still shows" || ok "pending empty after clear"

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

# ---------- 8b. lease-covered REPEAT request short-circuits (does not re-ask Batman) ----------
step "repeat request under live lease short-circuits"
L2=$(as_agent oracle GET https://api.fal.ai/render 5 "second call" --keys fal)
echo "$L2" | grep -qi "ACTIVE LEASE covers" && ok "repeat call short-circuits on live lease (no re-ask)" \
  || bad "repeat call did NOT short-circuit: $L2"
echo "$L2" | grep -qi "request key" && bad "short-circuited call wrongly staged a new ask" \
  || ok "short-circuited call did not stage a new pending"

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
echo "$R11" | grep -qi "retry with key" && ok "pending past window tells agent to wait then retry with the key" || bad "timeout wrong: $R11"

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
# substitution happened (the [fal] placeholder was swapped) AND the real value is redacted
echo "$OUT" | grep -q 'Bearer \[REDACTED\]' && ok "secret substituted into header (and redacted on return)" || { echo "$OUT" | grep -qF 'Bearer dummy_fal_key_ABC123' && bad "RAW secret leaked in response!" || bad "substitution into header failed: $OUT"; }
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

# ---------- 20. recover: NO current passphrase needed (recovery key only) + preserves access map ----------
step "recover: recovery-key only + preserves access map"
# grant link an access key first so there's something to preserve
LK=$(VAULT_PASS=$PASS python3 vault.py keygen link 2>/dev/null | grep VAULT_AGENT_KEY | cut -d= -f2)
VAULT_PASS=$PASS python3 vault.py access add link "$LK" >/dev/null 2>&1
ACCT_BEFORE=$(VAULT_PASS=$PASS python3 vault.py access list | grep -c link)
# CRITICAL: do NOT set VAULT_PASS here. recover must run from the recovery key
# ALONE. If it needed the current passphrase, the gotcha it'd otherwise be
# masked by feeding VAULT_PASS. any error = recover wrongly requires current pass.
RC=$(VAULT_NEW_PASS=passV3 VAULT_REC=$REC python3 vault.py recover 2>&1)
echo "$RC" | grep -qi "Recovered" && ok "recover ran from recovery key alone (no current pass needed)" \
  || bad "recover required current passphrase or failed: $RC"
ACCT_AFTER=$(VAULT_PASS=passV3 python3 vault.py access list 2>&1 | grep -c link)
[ "$ACCT_BEFORE" = "$ACCT_AFTER" ] && [ "$ACCT_BEFORE" -ge 1 ] && ok "recover preserved link's access registration" \
  || bad "recover WIPED the access map (before=$ACCT_BEFORE after=$ACCT_AFTER)"
# old pass must be dead under the new one
OLDDEAD=$(VAULT_PASS=$PASS python3 vault.py lease 2>&1)
echo "$OLDDEAD" | grep -qi "rejected\|TAMPER" && ok "old passphrase dead after recovery" || bad "old pass still accepted"

# ---------- 20b. rotate-recovery-key: old dies, new works, secrets untouched ----------
step "rotate-recovery-key retires the old recovery key"
ROT=$(VAULT_PASS=passV3 python3 vault.py rotate-recovery-key 2>&1 <<EOF
$REC
unused_probe
EOF
)
NEWREC=$(echo "$ROT" | grep -A1 'NEW RECOVERY KEY' | tail -1 | tr -d '[:space:]')
[ -n "$NEWREC" ] && ok "rotate-recovery-key minted a new key" || bad "rotate failed: $ROT"
echo "$ROT" | grep -q "secrets untouched" && ok "rotation left secrets re-wrapped not re-entered" || bad "rotation wording wrong: $ROT"
# the OLD recovery key must now be dead
OLDDEAD2=$(VAULT_NEW_PASS=passV4 VAULT_REC="$REC" python3 vault.py recover 2>&1 | head -1)
echo "$OLDDEAD2" | grep -qi "rejected" && ok "OLD recovery key rejected after rotate" || bad "OLD rec key still worked: $OLDDEAD2"
# the NEW recovery key must still fully recover
NEWOK=$(VAULT_NEW_PASS=passV5 VAULT_REC="$NEWREC" python3 vault.py recover 2>&1 | head -1)
echo "$NEWOK" | grep -qi "Recovered" && ok "NEW recovery key still recovers the store" || bad "NEW rec key failed: $NEWOK"
# restore the vault back to passV3 so the downstream passV3 tests keep working
RESTORE=$(VAULT_NEW_PASS=passV3 VAULT_REC="$NEWREC" python3 vault.py recover 2>&1 | head -1)
echo "$RESTORE" | grep -qi "Recovered" && ok "restored vault to passV3 after rotate test" || bad "restore to passV3 failed: $RESTORE"

# ---------- 21. bare key name guard ----------
step "bare key name is refused + CALL_REJECT logged"
LEDGER="$SCRATCH/.vault/ledger.jsonl"
BKPROF=x_bare; eval "BK__KEY=\$KEY_$BKPROF"
BK=$(HERMES_HOME="/Users/guymeaker/.hermes/profiles/x_bare" VAULT_AGENT_KEY="$BK__KEY" VAULT_PASS=passV3 python3 vault.py request GET https://api.fal.ai/render 0 "bare key test" --keys fal --header "Authorization: Bearer fal" 2>&1)
echo "$BK" | grep -qi "denied before staging" && ok "bare-key request refused before staging" || {
BKKEY=$(echo "$BK" | grep -o 'request key [a-f0-9]*' | awk '{print $3}')
[ -n "$BKKEY" ] && VAULT_PASS=passV3 python3 vault.py decide "$BKKEY" yes >/dev/null 2>&1
GB=$(VAULT_PASS=passV3 python3 vault.py resolve "$BKKEY" 2>&1)
echo "$GB" | grep -qi "REFUSED: bare key name" && ok "bare key name refused by guard" || bad "bare key name NOT refused: $GB"
grep -q '"ev": *"CALL_REJECT"' "$LEDGER" && ok "CALL_REJECT logged to ledger" || bad "no CALL_REJECT ledger event"
}

# ---------- 22. response secret hygiene (echo must not leak the key value) ----------
step "response redacts the secret (no leak on echo)"
LEDGER="$SCRATCH/.vault/ledger.jsonl"
# a stub that echoes the request back incl. the Authorization header
cat >"$SCRATCH/echo_stub.py" <<'PY'
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
class H(BaseHTTPRequestHandler):
    def log_message(self,*a): pass
    def _echo(self):
        body = json.dumps({"you_sent": dict(self.headers)}).encode()
        self.send_response(200); self.send_header("Content-Type","application/json")
        self.send_header("Content-Length", str(len(body))); self.end_headers()
        self.wfile.write(body)
    do_GET=_echo; do_POST=_echo
HTTPServer(("127.0.0.1",18184), H).serve_forever()
PY
python3 "$SCRATCH/echo_stub.py" >/dev/null 2>&1 &
ESTUB=$!
sleep 1
# readiness: confirm the stub answers before staging, else the call times out (not hangs now)
curl -s --max-time 2 http://127.0.0.1:18184/anything >/dev/null 2>&1 || { sleep 1; }
BKL="$BK__KEY"
LEAKKEY=$(HERMES_HOME="/Users/guymeaker/.hermes/profiles/x_bare" VAULT_AGENT_KEY="$BKL" VAULT_PASS=passV3 python3 vault.py request GET http://127.0.0.1:18184/anything 0 "echo leak test" --keys fal --header "Authorization: Bearer [fal]" 2>&1 | grep -o 'request key [a-f0-9]*' | awk '{print $3}')
[ -n "$LEAKKEY" ] && VAULT_PASS=passV3 python3 vault.py decide "$LEAKKEY" yes >/dev/null 2>&1
LEAK_RESULT=$(VAULT_PASS=passV3 python3 vault.py resolve "$LEAKKEY" 2>&1)
echo "$LEAK_RESULT" | grep -q "\[REDACTED\]" && ok "echo body has [REDACTED] (secret masked)" || bad "echo NOT redacted: $LEAK_RESULT"
echo "$LEAK_RESULT" | grep -q "dummy_fal_key_ABC123" && bad "RAW SECRET leaked in response!" || ok "no raw secret value in agent response"
kill "$ESTUB" 2>/dev/null

# ---------- 22b. /request relays a JSON body to the call (data field) ----------
step "server /request relays the data body to the call"
VPSRV=18295
# reuse the echo stub from test 22 (still running on 18184, echoes headers+we need body too)
cat >"$SCRATCH/echo_body.py" <<'PY'
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
class H(BaseHTTPRequestHandler):
    def log_message(self,*a): pass
    def _echo(self):
        ln=int(self.headers.get("Content-Length",0) or 0)
        raw=self.rfile.read(ln).decode()
        body=json.dumps({"path":self.path,"body":raw,"ct":self.headers.get("Content-Type","")}).encode()
        self.send_response(200); self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",str(len(body))); self.end_headers(); self.wfile.write(body)
    do_GET=_echo; do_POST=_echo
HTTPServer(("127.0.0.1",18178), H).serve_forever()
PY
python3 "$SCRATCH/echo_body.py" >/dev/null 2>&1 &
EBODY=$!
(VAULT_PASS=passV3 VAULT_WAIT_MIN=10 python3 vault.py run --port $VPSRV >"$SCRATCH/server.log" 2>&1 &)
sleep 2
cat >"$SCRATCH/dr_req.json" <<EOF
{"agent":"x_bare","key":"$BK__KEY","method":"POST","url":"http://127.0.0.1:18178/anything","expiry":0,"reason":"data relay test","keys":["fal"],"headers":{"Authorization":"Bearer [fal]","Content-Type":"application/json"},"data":{"prompt":"relay_probe_xyz","n":2}}
EOF
# first POST runs in the BACKGROUND (server holds the request open waiting for approval)
curl -s -X POST "http://127.0.0.1:$VPSRV/request" -H 'Content-Type: application/json' \
  -d @"$SCRATCH/dr_req.json" >"$SCRATCH/dr_first.json" &
CP=$!
sleep 1.5
RK2=$(VAULT_PASS=passV3 python3 vault.py pending 2>/dev/null | grep x_bare | awk '{print $1}' | head -1)
[ -n "$RK2" ] && VAULT_PASS=passV3 python3 vault.py decide "$RK2" yes >/dev/null 2>&1
wait $CP
DRRESP=$(cat "$SCRATCH/dr_first.json")
echo "$DRRESP" | grep -q "relay_probe_xyz" && ok "server /request relays the JSON body to the call" || bad "data body NOT relayed: $DRRESP"
kill "$EBODY" 2>/dev/null
pkill -f "vault.py run --port $VPSRV" 2>/dev/null

# ---------- 22c. query-string token substitution + bare-name guard in URL ----------
step "query-string [KEY] substitutes in the URL; bare name refused"
VPSRV2=18294
(cp "$SCRATCH/echo_body.py" "$SCRATCH/echo_qs.py")
cat >"$SCRATCH/echo_qs.py" <<'PY'
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def log_message(self,*a): pass
    def do_GET(self):
        body=("{\"path\":\""+self.path+"\"}").encode()
        self.send_response(200); self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",str(len(body))); self.end_headers(); self.wfile.write(body)
    do_POST=do_GET
HTTPServer(("127.0.0.1",18177), H).serve_forever()
PY
python3 "$SCRATCH/echo_qs.py" >/dev/null 2>&1 &
EQS=$!
(VAULT_PASS=passV3 VAULT_WAIT_MIN=10 python3 vault.py run --port $VPSRV2 >"$SCRATCH/server2.log" 2>&1 &)
sleep 2
# 22c-1: query-string marker must be substituted; the echoed path must not show a literal [fal]
cat >"$SCRATCH/qs_req.json" <<EOF
{"agent":"x_bare","key":"$BK__KEY","method":"GET","url":"http://127.0.0.1:18177/anything?api_key=[fal]", "expiry":0,"reason":"query token test","keys":["fal"]}
EOF
curl -s -X POST "http://127.0.0.1:$VPSRV2/request" -H 'Content-Type: application/json' \
  -d @"$SCRATCH/qs_req.json" >"$SCRATCH/qs_first.json" &
CP2=$!
sleep 1.5
RK3=$(VAULT_PASS=passV3 python3 vault.py pending 2>/dev/null | grep x_bare | awk '{print $1}' | tail -1)
[ -n "$RK3" ] && VAULT_PASS=passV3 python3 vault.py decide "$RK3" yes >/dev/null 2>&1
wait $CP2
QSR=$(cat "$SCRATCH/qs_first.json")
echo "$QSR" | grep -q '"call_status": 200' && ok "query-string [fal] call succeeded (substituted in URL)" || bad "query-string call FAILED: $QSR"
echo "$QSR" | grep -q '\[fal\]' && bad "literal [fal] leaked into URL" || ok "no literal [fal] marker in the URL echo"
# 22c-2: BARE query name (no brackets) must be REFUSED by the URL guard
cat >"$SCRATCH/qs_bare_req.json" <<EOF
{"agent":"x_bare","key":"$BK__KEY","method":"GET","url":"http://127.0.0.1:18177/anything?api_key=fal", "expiry":0,"reason":"bare query test","keys":["fal"]}
EOF
curl -s -X POST "http://127.0.0.1:$VPSRV2/request" -H 'Content-Type: application/json' \
  -d @"$SCRATCH/qs_bare_req.json" >"$SCRATCH/qs_bare.json" &
CP3=$!
sleep 1.5
RK4=$(VAULT_PASS=passV3 python3 vault.py pending 2>/dev/null | grep x_bare | awk '{print $1}' | tail -1)
[ -n "$RK4" ] && VAULT_PASS=passV3 python3 vault.py decide "$RK4" yes >/dev/null 2>&1
wait $CP3
QSB=$(cat "$SCRATCH/qs_bare.json")
echo "$QSB" | grep -qi "REFUSED\|bare key" && ok "bare query name refused by URL guard" || bad "bare query name NOT refused: $QSB"
kill "$EQS" 2>/dev/null
pkill -f "vault.py run --port $VPSRV2" 2>/dev/null

# ---------- 23. tamper writes to the ledger (LAST — breaks pending.json on purpose) ----------
step "tamper is logged (not silent)"
LEDGER="$SCRATCH/.vault/ledger.jsonl"
LEDGER_BEFORE=$(wc -l < "$LEDGER" 2>/dev/null || echo 0)
python3 - "$SCRATCH/.vault/pending.json" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
d["sig"]="0"*64  # break the HMAC
json.dump(d,open(sys.argv[1],"w"))
PY
TAMPER_OUT=$(VAULT_PASS=$PASS python3 vault.py pending 2>&1)
echo "$TAMPER_OUT" | grep -qi "TAMPER DETECTED" && ok "pending tamper is refuse-closed" || bad "tampered pending not refused: $TAMPER_OUT"
LEDGER_AFTER=$(wc -l < "$LEDGER" 2>/dev/null || echo 0)
[ "$LEDGER_AFTER" -gt "$LEDGER_BEFORE" ] && grep -q '"ev": *"TAMPER"' "$LEDGER" && ok "tamper event written to ledger" || bad "no TAMPER ledger event (before=$LEDGER_BEFORE after=$LEDGER_AFTER)"

echo
if [ "$FAIL" -eq 0 ]; then echo "ALL REGRESSION TESTS PASS ($SCRATCH, cleaned)"; else echo "REGRESSION FAILURES DETECTED"; exit 1; fi
