# private-api-vault — QUESTIONS TO ANSWER
# Open this, answer in place, save. Robin reads it when you're done.
# Answer inline after each "- " (just add your answer).

========================================================
## DECISIONS ALREADY LOCKED (do not re-answer, just confirming we agree)
========================================================
- No SQL database. Lease registry = a simple file, entries purged on expiry. Ledger = append-only history.
- Deny list = ONE blanket list. Agent on it = denied, period. No further checks.
- Every grant needs Batman sign-off. NO pass-through / "go as usual".
- Three possible NOs: (1) on deny list, (2) Batman says no, (3) 'other' response = always a NO, but Batman's message is passed to the agent.
- What gets logged: ledger (audit history) + active leases (purged on expiry). Both only readable via the vault's API. Vault alone has write power.
- Agents cannot: edit deny list, set own expiry, approve themselves, read secret values.

========================================================
## QUESTIONS
========================================================

### DENY LIST
- Q1. Who can add/remove agents on the deny list? (assume: Batman only, via vault. Confirm.) Batman only. logged in.
- Q2. Default seed for the deny list — robin? Anyone else? for now.. but not permanent in code? it mut be on list as default.. as in the json file.. but kept in vault to.. ot accessible to agents..
- Q3. When a denied agent asks, does the vault tell them WHY (you're on the list) or just "denied"?
---> we've been through this!!! fuck aman!! is said, yes.. give reason. on list, or batman says no, or 'other' when from telegram bastma responds with 'other' .. did you fucking forget!?>!?!?!

### APPROVAL / BATMAN SIGN-OFF
- Q4. Every non-denied request goes to Batman on Telegram (YES / NO / other)? Or terminal input sometimes?
-->  never terminal.
- Q5. If Batman is silent / unreachable — default to NO? Or wait?
--> if silent, have a timeout and default to NO. not sure how one does this. becaus we have to tell agent after a minute of waiting.. "came back after 5 min" agent can do that.. but now when agent caomes back, how does vault know its the same previous request? i reckon a vault has to put in ledger.. agent equest.. batman not repsondng .. and have unique for this request.. agent has to return with a unique ky to match to pick up last request. so if vault givees agent a key.. vault can look up in ledger.. see that we are wating.. if agent.. was gone for a while.. caomes back and in meantime batman has responded.. vault must see unique key ash baatman repsonded with no, or yes.. or still pnding.. if yes... complete http request as usual.. if no, tell agent. same procecdure of other. and if not responding give kunique to agent again.. agent must decide based on his own rules and skills to do somthing else.... like assue is is no. not sure here. but.. from vault.. it is no response after a minute of waiting.. return to waiting agent say come back in no sooner than 5 minutes. 
- Q6. Confirm: 'other' from Batman = always denied, but Batman's typed message is passed back to the agent verbatim.
--> yes


### LEASES / EXPIRY
- Q7. Lease file: does it record (agent, api key, expiry timestamp) and delete the entry when it expires? Confirm this shape.
---> yes
- Q8. Default lease length for a normal grant? (e.g. 5 min? session length?)
---> no defult, because agent leearns. iw aill have the agents have a skill.. when trying to grab a mchine, for exapmle, on vast.. 5 min.. to grab a machine.. so vault is out of descion loop. agent just knows to request more time.. agent will learn anyway,. and probably request more than 10 min. i, batman can respond wih other.. ans say no. try again, wih 5 min. agent getsthe NO, and message, and tries again.. and message comes through with expiry request. batman then says yes. agent learns from this. over time.
- Q9. Can an agent ever request a longer lease? If so, that request goes to Batman explicitly? Or no, lease only set by Batman at grant time?
---> every time an agent wants to send and to an api or, access some endpoint.. and eeds key.. het goues to vault? fuck man.. this a stupid fucking question. lease are only granted by,
look you seem confused.. maybe.. do this.. agent knows that they need an api key cause they dont have  one.. they have in skills.. use vault ... maybe name vault to something else.. like "secure api proxy" anyway.. the agent comes, ere is my api key, an resason. or amybe the api for "vault" is {http:"", reason: "", expiry:0} expiry is 0 by dfault.. meaning no expiry request. 1 and up.. minutes requested ofr extension of ue.. so batman is not diturbed.. and i can get the machine.
- Q10. Agents cannot set their own expiry. Confirm it's enforced, not just assumed.
--> ? what.. batman is the only one who approves any and all extensions??? wtf are you asking this fall. point of app is to lock fucking keys up... they have to come and send via app.. they dont keys.. cant decide for them selves to hold onkeys or to give them up? if vault has an expiry date in ledger.. they can run through? no need to bother batman...

### THE CALL / SUBSTITUTION
- Q11. The asking agent provides the request string with [key_name] placeholders; vault swaps in held secret(s). Confirm.
- Q12. On YES: vault makes the call itself and returns the HTTP response (no separate agent-run `call` step). Confirm.
- -->
- Q13. If the response is bad / token invalid — agent fixes and retries (vault not involved). Only loops back to Batman if it's a keep-going/money call. Confirm.

--> serously fucking me off. vault is agotstic. holds keys. replaces key mn to string and sends. does not give a fuck about result. if a fuckup call.. the agent deals wih errror respnses and decides like usual? why the fuck are you aasking stupd questions!! yyou know his !! fuuuuuuuck you 
!! wasting my fucking time

### LEDGER / LEASE FILE ACCESS
- Q14. Ledger = permanent append-only history (who, which key, when, outcome). Read-only to everyone. Confirm.
--> yes. add unique kye for look up. his used when agent returns after a no response fom batman.
- Q15. Lease file = active grants only, purged on expiry so it never grows. Confirm.
---> yes
- Q16. Both readable only via the vault program's API. Agents cannot read them directly. Confirm.
---> yes, agents only read via api
- Q17. Who can read them? Batman only? Or also agents (through the vault, to see their own status)? Confirm.
---> agents api read only. batman, via login etc can see it.

### AGENT ACCESS BOUNDARIES (final check)
- Q18. Agents CANNOT: edit deny list, set expiry, approve themselves, read secret values, modify ledger/lease files directly. Confirm this list is complete.
---> yes, agents no nothing, or have access, except ledger and lease via api, read only. secrest are never written in ledger or leases. secrets are nly replaced into htpps strings and sent on aggents behalf.
- Q19. What CAN an agent do? (ask for a key, view own lease status? anything else?)
-> no. the cant ask quesions. just view api list.. what keys are available,  not the secrets. api see ledger and lease. no secrets ever. 
### MIGRATION (later — needs you present)
- Q20. Move real keys from keykeeper/.env into the encrypted store — do this now or later?
---> add when we know it is works.. like i can log in and see the secrets. update etc when im hapy, we delete .env secrets

my own question: do secrets or passwords ever get return from the api?
and can agent who is given access with api.. update account details? so.. like change password, email,etc?


========================================================
## WHEN DONE
- Save this file. Robin will read it and turn your answers into the build plan (TODO.md) off the approved flow diagram.
