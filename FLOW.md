# private-api-vault — API key request flow

The agent does not hold API keys (keys live only in the vault's encrypted
store). Every session that needs a key asks the vault. The vault decides
yes or no, and on a yes makes the call itself and returns the HTTP
response. A key value never leaves the vault.

```mermaid
flowchart TD
    A["Agent: a key is needed for this session (held in the skill, not here)"]
    A --> B["Agent asks the vault for key"]

    B --> C["vault decides YES or NO"]
    C --> D{"Approval reached"}
    D -- "no (no key, blocked agent, or not approved)" --> E["vault says NO"]
    D -- "yes (routine, expiry live, or Batman signs off)" --> F["vault makes the API call"]
    F --> G["vault returns the HTTP response to the agent"]
    E --> H["ledger: logged"]
    G --> H["ledger: logged"]
```

## What the vault does

- Decides YES or NO on every key request.
- YES comes from a rule (routine / expiry still live) or from Batman's
  sign-off.
- On YES it doesn't hand a key out — it runs the call itself and returns
  the HTTP response.
- On NO it says so, and the agent is refused.
- Every decision is written to the ledger.

That's the whole map. The agent asks, the vault answers, the ledger records.
