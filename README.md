# SuperWall

SuperWall is an offline-first youth defence and parental control platform for Windows.

## Components

- `src/SuperWall.Agent` — Windows background service. Enforces cached policies even without network access.
- `src/SuperWall.Dashboard` — ASP.NET Core central dashboard/API for devices, profiles and history requests.
- `docs/ARCHITECTURE.md` — design and security notes.

## Default policy

- Profile: **Low Risk**
- Blocked domains: TikTok, YouTube, Roblox and Pornhub
- Search-history retention: 30 days (Low Risk), 365 days (High Risk)
- Search history is never uploaded proactively; an Admin must request it.
- Downloads are blocked by default where supported by browser enterprise policies, with a local PIN override (`2003`) and agent-side quarantine as a fallback.

> SuperWall uses Windows enterprise/browser controls plus a local network proxy. No single Windows API can guarantee filtering of every third-party browser or application, so the agent applies multiple layers and continuously repairs its policy configuration.

## Development

Requires .NET 8 SDK.

```powershell
dotnet build SuperWall.sln
```

See `docs/INSTALL.md` for the Windows service and dashboard setup.