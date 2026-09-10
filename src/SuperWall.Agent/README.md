# SuperWall Agent

The agent is a Windows background service intended for a non-administrator child account.

## Security boundary

The agent is not a replacement for Windows account security. A local administrator can stop services, alter firewall and registry policy, replace binaries, or otherwise bypass an application-level parental-control solution.

## Local download unlock

The local unlock endpoint is bound to loopback and requires an authenticated Windows administrator caller. Five failed PIN attempts cause a five-minute lockout. The PIN itself is stored only as a salted PBKDF2 hash.
