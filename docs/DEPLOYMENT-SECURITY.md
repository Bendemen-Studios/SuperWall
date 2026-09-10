# Production deployment checklist

- Run the Kids agent under `LocalSystem` through the installed Windows service.
- Give the child a standard Windows account; do not make the child a local administrator.
- Publish the central dashboard only behind HTTPS/TLS.
- Keep the dashboard admin secret and enrollment key in a secure secret store; never commit them.
- Generate a unique enrollment key for each installation batch and rotate/revoke it after enrollment where possible.
- Keep Windows Defender, Windows Update, and firewall enabled.
- Restrict software installation to administrators.
- Treat the local administrator account as a security boundary.
- Verify browser policy after installing or updating Chrome, Edge, and Firefox.
- Test the policy while the dashboard is offline; the cached policy must remain enforced.
