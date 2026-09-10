# SuperWall architecture

```text
Windows child device
  └─ SuperWall Agent (Windows Service)
       ├─ Cached policy (%ProgramData%\\SuperWall)
       ├─ Browser enterprise policies
       ├─ Local filtering proxy :18580
       ├─ Download quarantine / PIN override :18581
       └─ Search-history collector (only uploaded after Admin request)
                    │
                    │ HTTPS + agent token
                    ▼
              SuperWall Dashboard
       ├─ Device inventory
       ├─ Low/High Risk profile assignment
       ├─ URL blocklist policy
       └─ Explicit history request + history viewer
```

## Risk profiles

**Low Risk** is the default and retains up to 30 days locally. **High Risk** retains up to 365 days locally. Changing a device profile changes the retention window in the next cached policy.

History is not pushed continuously. The dashboard creates a `request_history` command and the agent uploads a snapshot only when that command is seen.

## Filtering layers

Blocked domains are matched against the exact domain and all subdomains by the local proxy. Edge and Chrome are forced through that proxy using machine-level enterprise policy, while DNS-over-HTTPS is disabled through policy. Firefox is configured with enterprise policy to use the local proxy and to disable DoH.

Downloads are blocked in Chromium through enterprise `DownloadRestrictions=3`. The agent also watches common per-user Downloads directories and moves newly created files into a service-owned quarantine when downloads are locked. A successful PIN unlock creates a ten-minute local exception.

## Security notes

The agent token authenticates device-to-dashboard traffic. The dashboard admin password is separate. In production, serve the dashboard behind HTTPS and rotate both secrets periodically.

The hard-coded default PIN `2003` is kept because it is part of the current requested product specification; production deployments should make it configurable and store only a derived/hashed value.