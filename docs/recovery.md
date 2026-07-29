# Recovery

Create a local backup:

```sh
/opt/bindguard/scripts/backup.sh
```

Restore a backup:

```sh
/opt/bindguard/scripts/restore.sh /var/lib/bindguard/backups/bindguard-backup-YYYYmmddTHHMMSSZ.tar.gz
```

The restore script validates BIND, the RPZ zone, dnsdist, and sudoers before
extracting. It then reloads systemd and restarts `named`, `dnsdist`, and
`bindguard`.

When the web interface is unavailable:

```sh
systemctl status bindguard --no-pager
journalctl -u bindguard -n 100 --no-pager
systemctl restart bindguard
```

When DNS is unavailable:

```sh
named-checkconf -p /etc/bind/named.conf
named-checkzone bindguard.rpz /var/lib/bindguard/compiled/bind/bindguard.rpz
dnsdist --check-config -C /etc/dnsdist/dnsdist.conf
systemctl restart named
systemctl restart dnsdist
```
