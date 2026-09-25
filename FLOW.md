# private-api-vault — API key request flow

How a request for a service key is decided. Every path ends in a ledger
line — WHO asked, for WHAT, WHEN, and the OUTCOME. A keyis never handed
to an agent; the vault decrypts internally and makes the call itself.

```mermaid
flowchart TD
    A[Agent asks for key<br/>service + agent + reason] --> B[vault.py allow]

    B --> C{Key exists?}
    C -- No --> D[HELL-NO<br/>log: no such key]
    C -- Yes --> E{Agent blocked?<br/>e.g. robin}
    E -- Yes --> F[HELL-NO<br/>log: blocked agent]
    E -- No --> H{Already approved?<br/>fresh lease still live<br/>for this service+agent}

    H -- No --> G{What does<br/>rules.json say?}
    H -- Yes, lease live --> R[GRANT lease-reused<br/>log GRANT by=lease]
    R --> RUN[Run the call]

    G -- never --> J[REFUSE<br/>log: never]
    G -- routine --> K[AUTO-GRANT<br/>log GRANT by=rules]
    K --> RUN
    G -- needs-bats --> I[Ask Batman<br/>Telegram YES / NO buttons]

    I --> N{Batman verdict}
    N -- YES --> L[GRANT + start lease<br/>log GRANT by=batman]
    L --> RUN
    N -- NO --> P[REJECT<br/>log REJECT]
    N -- other --> Q[log OTHER<br/>reason, no action]

    RUN --> S[Agent built the request<br/>full URL + headers + body,<br/>secrets left as placeholder markers<br/>e.g. Authorization: [fal_key]<br/>or a body field: [some_key]]
    S --> T{Decrypt and substitute}
    T -- named placeholders from rules --> U[Vault replaces EACH marker<br/>with its decrypted key value]
    U --> XS[key values only in memory<br/>for this one call, never shown]
    XS --> Y[Send request, return result to agent]

    D --> Z[ledger.jsonl]
    F --> Z
    J --> Z
    P --> Z
    Q --> Z
    Y --> Z
```

## How the call stays provider-agnostic

The vault does NOT hardcode header shapes (fal/DO/Bearer). Whoever runs the
call hands the vault a fully-built request — URL, headers, body — with each
secret left as a `[key_name]` placeholder. The rules for that service name
the keys each placeholder maps to (one, or several). The vault:

1. decrypts each named key,
2. string-replaces every placeholder with its value,
3. sends the request, returns the result.

The key values live only in that one call's memory. Adding a new provider
is just a new request template + a rules entry — no vault code change.

## Legend

- **routine**    — low-stakes, same agent always gets it → auto-grant (still logged)
- **needs-bats** — anything costing money or risky → Batman must tap YES
- **never**      — rules release it under no circumstances
- **lease**      — an approval is valid for N minutes; while it's live we do NOT
                  re-ask Batman (reused and logged as lease-reused). Only an
                  expired lease triggers a fresh ask.

Rule of thumb: Batman is only ever asked when a key is genuinely needed,
not already approved, and rules mark it needs-bats. Fast paths (routine,
live lease) never bother him. Every node → the ledger; nothing happens
unlogged.