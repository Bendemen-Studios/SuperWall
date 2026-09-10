# SuperWall production deployment

Production hostname: `https://superwall.hvmc.nl`

The recommended target is Ubuntu 24.04 with ports **80/443** exposed publicly. The dashboard itself listens only on `127.0.0.1:7080` and should not be exposed directly to the Internet.

## Install

From a fresh Ubuntu 24.04 VPS:

```bash
apt update && apt install -y git
cd /root
git clone https://github.com/Bendemen-Studios/SuperWall.git
cd /root/SuperWall
bash deploy/install-ubuntu.sh
```

If `/root/SuperWall` already exists, update it instead of cloning again:

```bash
cd /root/SuperWall
git fetch origin
git reset --hard origin/main
bash deploy/install-ubuntu.sh
```

The installer creates a dedicated `superwall` service account, installs .NET 8, publishes the dashboard, configures systemd and Nginx, creates server-side secrets when needed, and attempts to issue the TLS certificate for `superwall.hvmc.nl`.

## DNS

Create an `A` record:

```text
superwall.hvmc.nl -> <VPS_PUBLIC_IPV4>
```

If you also use IPv6, create the matching `AAAA` record only when the VPS is actually reachable over IPv6.

## Nginx Proxy Manager

When using Nginx Proxy Manager, create a Proxy Host for `superwall.hvmc.nl` that forwards to `http://127.0.0.1:7080` when NPM runs on the same VPS, or to the dashboard server's private IP on port `7080` when NPM runs on another internal host.

Enable a valid Let's Encrypt certificate and force SSL. Keep the forwarded protocol as HTTPS so the dashboard's HTTPS enforcement recognizes the public connection as secure.

## Firewall

Allow only SSH plus web traffic when the dashboard/NPM boundary is on this server:

```bash
ufw allow OpenSSH
ufw allow 80/tcp
ufw allow 443/tcp
ufw deny 7080/tcp
ufw --force enable
```

Port 7080 is an internal service port and must not be published publicly.

## Credentials

The installer stores the dashboard credentials in:

```text
/etc/superwall/superwall.env
```

Keep this file owned by root with mode `0600`. Never commit its values to Git. Rotate admin credentials if they are exposed.

## Enrollment

Log in to the dashboard, then open:

```text
https://superwall.hvmc.nl/enrollment.html
```

Create an enrollment key for the Windows machine. Keys are stored server-side as hashes, have an expiry time, can be revoked, and can be consumed only once. The plaintext key is shown only when it is created.

Use that key in `SuperWall-Kids-Setup-0.2.0.exe`. After successful enrollment the device receives a unique agent token and the bootstrap key is removed from the child PC.

## Service operations

```bash
systemctl status superwall-dashboard
journalctl -u superwall-dashboard -f
systemctl restart superwall-dashboard
```

The dashboard database is persisted below `/var/lib/superwall`.

## Kids devices

The child Windows account should remain a standard non-administrator account. The Kids agent runs as a LocalSystem service and keeps enforcing the last successful policy while the dashboard is offline.
