# Hardening notes

The current implementation deliberately uses multiple independent controls instead of trusting a single browser setting:

- local cached policy
- managed browser policies
- hosts-based blocking
- outbound DNS restrictions
- local proxy filtering
- QUIC/HTTP3 disabled for managed browsers
- download quarantine
- portable-browser process guard
- per-device agent credentials
- DPAPI-protected local secrets
- ACL-protected state and enrollment data
- Windows service restart recovery

This is application-level parental control. A local administrator remains outside the trust boundary. Stronger tamper resistance requires Windows application-control technology such as WDAC and centrally managed device accounts.
