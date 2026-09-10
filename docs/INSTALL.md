# Install SuperWall

## 1. Central dashboard

On the server:

```powershell
dotnet run --project src/SuperWall.Dashboard
```

Set these environment variables before starting it:

```powershell
$env:SUPERWALL_ADMIN_PASSWORD = 'change-this'
$env:SUPERWALL_AGENT_TOKEN = 'long-random-agent-token'
$env:SUPERWALL_BIND = 'http://0.0.0.0:5080'
```

Open `http://server:5080`.

## 2. Build the Windows agent

```powershell
dotnet publish src/SuperWall.Agent -c Release -r win-x64 --self-contained false -o publish/agent
```

Run PowerShell as Administrator and install it:

```powershell
.\scripts\Install-Agent.ps1 -DashboardUrl 'https://your-dashboard.example' -AgentToken 'long-random-agent-token'
```

The agent creates its cached state in `%ProgramData%\SuperWall`.

## 3. Download override

The default download policy is block. The local override is deliberately short-lived (10 minutes) and requires the configured PIN, currently `2003`:

```powershell
.\tools\Unlock-Downloads.ps1
```

## Offline-first behavior

The device applies the last successful policy from disk. Losing the dashboard connection therefore does not disable URL blocking, browser policies, retention rules, or download protection. Policy changes propagate on the next agent sync (normally within 60 seconds).

## Important operational note

The first version uses Windows enterprise browser policies and a local filtering proxy. It is intentionally not a kernel/network filter, so administrators should still prevent unmanaged browsers from being installed and keep the Windows account non-administrative for the child profile.