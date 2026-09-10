# SuperWall Kids installer

`SuperWall Kids` is the Windows-side component for child devices. The installer creates a Windows service running as `LocalSystem` and registers the device with the central SuperWall dashboard.

## Build

The GitHub Actions workflow `.github/workflows/build-kids-installer.yml` publishes a self-contained `win-x64` agent and builds:

`publish/installer/SuperWall-Kids-Setup-0.2.0.exe`

The workflow also publishes `SHA256.txt` and uploads both files as the `SuperWall-Kids-Installer` artifact. A tag named `kids-v*` additionally creates a GitHub release.

## Install

The installer must be run by a Windows administrator. It asks for:

1. The central dashboard HTTPS URL.
2. The enrollment key generated for the SuperWall installation.

After installation the service is started automatically. The agent enrolls once, receives a unique per-device token, stores that token protected with Windows DPAPI, and removes the bootstrap enrollment key from the machine environment.

## Child-side behavior

The service runs without requiring a child to stay logged in. Its local policy cache is used when the dashboard is unavailable. Browser policy, local proxy filtering, hosts-file blocks, DNS egress blocking, and download enforcement are repaired periodically by the service.

Do not give the child a local administrator account. A parental-control product cannot reliably enforce restrictions against a user who can stop services, edit HKLM policy keys, install drivers, or remove the software with administrative privileges.
