# private-api-vault — API key request flow

How a request for a service key is decided. Every path ends in a ledger
line — WHO asked, for WHAT, WHEN, and the OUTCOME. A keyis never handed
to an agent; the vault decrypts internally and makes the call itself.

```mermaid
flowchart TD
    A[Agent asks for key<br/>service + agent + reason] --> B[vault.py allow]
    B --> C{Key for this<br/>service exists?}
    C -- No --> D[HELL-NO<br/>log DECIDE: no such key]
    C -- Yes --> E{Agent on<br/>blocked list?<br/>e.g. robin}
    E -- Yes --> F[HELL-NO<br/>log DECIDE: blocked agent]
    E -- No --> G{What does<br/>rules.json say?}

    G -- routine for this agent --> H[AUTO-GRANT<br/>log GRANT by=rules]
    G -- needs-bats --> I[Ask Batman]
    G -- never --> J[NEVER<br/>refuse, log]

    I --> K{How is Batman reached?}
    K -- Local terminal --> L[input yes / no]
    K -- Remote session --> M[Telegram buttons<br/>YES / NO]

    L --> N{Batman verdict}
    M --> N{Batman verdict}
    N -- YES --> O[GRANT<br/>with session lease<br/>log GRANT by=batman]
    N -- NO --> P[REJECT<br/>log REJECT]
    N -- other --> Q[log OTHER<br/>reason noted,<br/>no action]

    O --> R{Lease expired?<br/>took longer than<br/>session lease}
    R -- No --> S[Run the call]
    R -- Yes --> I

    S --> T{Call's auth profile}
    T -- fal --> U[Key: <key> header]
    T -- DigitalOcean --> V[token: <key> header]
    T -- vast / rest --> W[Authorization: Bearer <key>]

    U --> X[key used only inside<br/>the call, never shown]
    V --> X
    W --> X
    X --> Y[Return result to agent]
    D --> Z[ledger.jsonl: whole audit trail]
    F --> Z
    H --> Z
    J --> Z
    P --> Z
    Q --> Z
    Y --> Z
```

## Legend

- **routine**   — low-stakes, same agent always gets it (auto-grant, still logged)
- **needs-bats** — anything costing money or risky: Batman must tap YES
- **never**     — rules say no circumstances release it
- **lease**     — approval is only valid for N minutes; a long job re-asks

Every node → the ledger. Nothing happens unlogged.