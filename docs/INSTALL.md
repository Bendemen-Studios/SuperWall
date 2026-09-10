# Install SuperWall

## 1. Central dashboard

Production dashboard URL:

`https://superwall.hvmc.nl`

On the server, run the ASP.NET Core dashboard on its internal port:

```bash
dotnet run --project src/SuperWall.Dashboard
```

The default dashboard listener is `http://0.0.0.0:7080`.

The public domain should point to this service through an HTTPS reverse proxy. Keep the dashboard admin password and enrollment secret in server-side environment/secret storage and never commit them to Git.

For the public hostname `superwall.hvmc.nl`, proxy HTTPS traffic to the dashboard's internal `http://127.0.0.1:7080` listener and preserve `X-Forwarded-Proto: https`.

## 2. SuperWall Kids

The Kids installer is `SuperWall-Kids-Setup-0.2.0.exe`. During installation the dashboard URL is prefilled as:

`https://superwall.hvmc.nl`

The installer then asks for the one-time enrollment key used to register that Windows device.

The child PC must use a standard Windows account without local administrator rights. The agent runs as the `LocalSystem` Windows service and keeps enforcing the last successful policy while the dashboard is offline.

## 3. Download override

Downloads are blocked by default. The local override is short-lived (10 minutes) and requires the configured PIN `2003`. Only an administrator can access the local unlock endpoint.

## Offline-first behavior

The device applies the last successful policy from disk. Losing the dashboard connection therefore does not disable URL blocking, browser policies, retention rules, or download protection. Policy changes normally propagate within 60 seconds of the next successful sync.

## Important operational note

SuperWall uses managed browser policies, a local filtering proxy, DNS/hosts hardening and additional download/process controls. The intended deployment boundary is a non-administrative child account. Local administrator access remains outside the application's trust boundary.
