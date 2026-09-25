# private-api-vault — API key request flow

The vault's ONE job: DECIDE who gets a key and who doesn't — Batman signs
off, unless a rule or expiry auto-approves. Everything else (the request's
shape, the call, fixing a bad response) belongs to the agent. The vault
just holds the secrets, substitutes them into a string it's handed, sends,
and reports back. A key value never leaves the vault's process.

```mermaid
flowchart TD
    AG["Agent arrives: I have an endpoint and need N keys I don't hold. I hand over the request with key placeholders"]

    AG --> V["vault: the DECISION"]
    V --> C{"Holds those keys?"}
    C -- "No" --> D["HELL-NO: unknown key"]
    C -- "Yes" --> E{"Agent allowed? robin is blocked"}
    E -- "No" --> F["HELL-NO: agent blocked"]
    E -- "Yes" --> S{"Approve how?"}

    S -- "expiry date still live" --> K["AUTO-GRANT by rule"]
    S -- "routine for this agent" --> K["AUTO-GRANT by rule"]
    S -- "needs-bats" --> I["Ask Batman (Telegram YES or NO)"]
    S -- "no expiry or expired" --> I

    I --> N{"Batman verdict"}
    N -- "YES" --> L["GRANT + start lease"]
    N -- "NO" --> P["REJECT"]
    N -- "other" --> Q["log OTHER, no action"]

    K --> SUB["Vault swaps every key placeholder for the held secret"]
    L --> SUB

    SUB --> SEND["Send the request as-is"]
    SEND --> RES["Result or error returned to the AGENT"]
    RES --> R{"Worked?"}
    R -- "Yes" --> DONE["Return result to agent"]
    R -- "No: malformed or bad response" --> FIX["Agent fixes and retries"]
    FIX --> SUB
    R -- "No: agent decides it is not working or the token is invalid" --> PLAN["Agent plans and asks Batman if it is worth continuing"]
    PLAN --> I

    D --> Z["ledger.jsonl"]
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
  vault doesn't debug the request; it just tries the send and hands the
  result back.
- **If the agent concludes the thing is genuinely not working (endpoint
  dead, token invalid, money burning) -> the agent plans and asks Batman,
  not the vault.** That's a "is it worth continuing?" decision, so it
  routes to the same approval path — you.
- **One endpoint may need several secrets.** The vault holds however many
  keys a service needs and replaces every mark placeholder it finds. So
  "three secrets or one" is automatic — it swaps every placeholder.

Every decision goes to the ledger. Nothing unlogged.
