# SuperWall security model

## Threat model

SuperWall is designed for a Windows child account that is **not** a local administrator. Administrator access is intentionally treated as a trust boundary: a user with local administrator or SYSTEM access can disable Windows security controls and therefore cannot be reliably constrained by an application-only parental-control agent.

## Enforcement layers

1. Cached local policy continues to apply when the dashboard is unreachable.
2. Chrome and Edge are forced through the local filter proxy, with DoH and QUIC disabled.
3. Firefox receives equivalent proxy and DNS/HTTP3 preferences.
4. Windows hosts entries and outbound DNS firewall rules reduce direct DNS bypasses.
5. Browser extension installation is blocked in managed Chromium browsers.
6. Known portable browser processes launched from common user-writable locations are terminated.
7. Downloads are blocked by browser policy and a local quarantine sweep.
8. Download unlock is administrator-only, rate-limited, and uses the salted PIN hash stored locally rather than plaintext.
9. Agent credentials are per-device, stored with Windows DPAPI and ACL protection.
10. Enrollment bootstrap credentials are stored in an ACL-protected file and consumed after enrollment.
11. The SuperWall state directory is repaired to SYSTEM/Administrators ownership and the service configures automatic restart recovery.

## Remaining platform boundary

No ordinary Windows service can provide a mathematical guarantee against a local administrator. For production deployments, use a standard child account, prevent unapproved administrator accounts, keep Windows Defender and Windows Update enabled, and control which software may be installed.

For stronger enterprise enforcement, the next platform layer is Windows Defender Application Control / WDAC or an equivalent managed application-control policy. That layer should be deployed centrally and tested per Windows edition before enabling enforcement mode.
