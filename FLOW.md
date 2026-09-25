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
    H -- Yes --> RUN[Run the call]
    H -- No --> G{What does<br/>rules.json say?}

    G -- never --> J[REFUSE<br/>log: never]
    G -- routine --> K[AUTO-GRANT<br/>log GRANT by=rules]
    K --> RUN
    G -- needs-bats --> I[Ask Batman<br/>Telegram YES / NO buttons]

    I --> N{Batman verdict}
    N -- YES --> L[GRANT + start lease<br/>log GRANT by=batman]
    N -- NO --> P[REJECT<br/>log REJECT]
    N -- other --> Q[log OTHER<br/>reason, no action]

    L --> RUN

    RUN --> T{Call's auth profile}
    T -- fal --> U[Key-header: Authorization: Key ...]
    T -- DigitalOcean --> V[token-header]
    T -- vast / rest --> W[Authorization: Bearer ...]

    U --> XS[key used only inside the call, never shown]
    V --> XS
    W --> XS
    XS --> Y[Return result to agent]

    D --> Z[ledger.jsonl]
    F --> Z
    J --> Z
    K --> Z
    P --> Z
    Q --> Z
    H -- fresh lease reused --> R[log GRANT lease-reused]
    R --> XS
    Y --> Z
```

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