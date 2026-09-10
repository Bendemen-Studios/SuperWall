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

The installer creates a dedicated `superwall` service account, installs .NET 8, publishes the dashboard, configures systemd and Nginx, creates server-side secrets when needed, and attempts to issue the TLS certificate for `superwall.hvmc.nl`.

## DNS

Create an `A` record:

```text
superwall.hvmc.nl -> <VPS_PUBLIC_IPV4>
```

If you also use IPv6, create the matching `AAAA` record only when the VPS is actually reachable over IPv6.

## Firewall

Allow only SSH plus web traffic:

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

Keep this file owned by root with mode `0600`. Never commit its values to Git. Rotate the admin password and enrollment key if they are exposed.

## Service operations

```bash
systemctl status superwall-dashboard
journalctl -u superwall-dashboard -f
systemctl restart superwall-dashboard
nginx -t && systemctl reload nginx
```

The dashboard database is persisted below `/var/lib/superwall`.

## Kids devices

Use the `SuperWall-Kids-Setup-0.2.0.exe` installer. It is preconfigured for `https://superwall.hvmc.nl` and asks for the one-time enrollment key. The child Windows account should remain a standard non-administrator account.
