# private-api-vault — API key request flow

The vault's ONE job: DECIDE who gets a key and who doesn't — Batman signs
off, unless a rule or expiry auto-approves. Everything else (the request's
shape, the call, fixing a bad response) belongs to the agent. The vault
just holds the secrets, substitutes them into a string it's handed, sends,
and reports back. A key value never leaves the vault's process.

```mermaid
flowchart TD
    AG[Agent arrives: I have an endpoint<br/>and need N keys I don't hold<br/>hands over the request string<br/>with [key_name] placeholders]

    AG --> V[vault: the DECISION]
    V --> C{Holds those keys?}
    C -- No --> D[HELL-NO<br/>log: unknown / not held]
    C -- Yes --> E{Agent allowed?<br/>e.g. robin blocked}
    E -- No --> F[HELL-NO<br/>log: agent blocked]
    E -- Yes --> S{Approve how?}

    S -- has expiry date, still live --> K[AUTO-GRANT<br/>log GRANT by=rule]
    S -- routine for this agent --> K1[AUTO-GRANT<br/>log GRANT by=rule]
    S -- needs-bats --> I[Ask Batman<br/>Telegram YES / NO]
    S -- expired, or none --> I

    I --> N{Batman verdict}
    N -- YES --> L[GRANT + start lease<br/>log GRANT by=batman]
    N -- NO --> P[REJECT<br/>log REJECT]
    N -- other --> Q[log OTHER<br/>reason, no action]

    K --> SUB[Vault: substitute each<br/>placeholder with the held secret]
    K1 --> SUB
    L --> SUB

    SUB --> SEND[Send the request as-is]
    SEND --> RES[Result or error<br/>-> returned to the AGENT]
    RES --> R{Worked?}
    R -- Yes --> DONE[Return result to agent<br/>log CALL]
    R -- No: malformed / bad response --> FIX[Agent fixes the request<br/>and retries]
    FIX --> SUB

    R -- No: agent concludes<br/>it is not working /<br/>token invalid --> PLAN[Agent plans the fix<br/>and asks Batman is it worth<br/>continuing]
    PLAN --> I

    D --> Z[ledger.jsonl]
    F --> Z
    P --> Z
    Q --> Z
    DONE --> Z
```

## The division of labour (read this — it IS the design)

- **The vault decides only one thing: does this agent get this key?**
  Rules + your sign-off + expiry windows. That decision path is all the
  vault's code cares about.
- **The vault does NOT understand templates or endpoints.** It never learns
  "fal needs a Key header" or any provider's auth shape. It is handed a
  finished request string containing `[key_name]` markers, swaps in the
  secrets it holds, sends it, returns whatever comes back.
- **If a call comes back badly formed -> the AGENT fixes and retries.** The
  vault doesn't debug the request; it just tries/refuses the substitution
  and hands the result back.
- **If the agent concludes the thing is genuinely not working (endpoint
  dead, token invalid, money burning) -> the agent plans and asks Batman,
  not the vault.** That's a "is it worth continuing?" decision, so it
  routes to the same approval path — you.
- **One endpoint may need several secrets.** The vault holds however many
  keys a service needs and replaces every marker it finds. "Three or one"
  is automatic — it just swaps every placeholder.

Every decision -> the ledger. Nothing unlogged.
