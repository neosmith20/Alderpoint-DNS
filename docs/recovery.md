# Recovery

Create a local backup:

```sh
/opt/alderpointdns/scripts/backup.sh
```

Restore a backup:

```sh
/opt/alderpointdns/scripts/restore.sh /var/lib/alderpointdns/backups/alderpointdns-backup-YYYYmmddTHHMMSSZ.tar.gz
```

The restore script validates BIND, the RPZ zone, dnsdist, and sudoers before
extracting. It then reloads systemd and restarts `named`, `dnsdist`,
`alderpointdns-analytics`, and `alderpointdns`.

When the web interface is unavailable:

```sh
systemctl status alderpointdns --no-pager
systemctl status alderpointdns-analytics --no-pager
journalctl -u alderpointdns -n 100 --no-pager
systemctl restart alderpointdns
systemctl restart alderpointdns-analytics
```

When DNS is unavailable:

```sh
named-checkconf -p /etc/bind/named.conf
named-checkzone alderpointdns.rpz /var/lib/alderpointdns/compiled/bind/alderpointdns.rpz
dnsdist --check-config -C /etc/dnsdist/dnsdist.conf
systemctl restart named
systemctl restart dnsdist
```

For Local DNS failures, inspect the last deployment on the Local DNS page or in
`local_dns_deployments`. Generated zones are staged first, checked with
`named-checkzone`, installed atomically, and backed up under
`/var/lib/alderpointdns/backups`. Re-run a no-download deploy after correcting bad
records:

```sh
/opt/alderpointdns/app/alderpointdns_compiler.py deploy --no-download
named-checkconf -p /etc/bind/named.conf
```

When analytics is unavailable, DNS service should continue. Check that
`alderpointdns-analytics` is active and that `ss -ltnup` shows the collector only on
`127.0.0.1:5301`.
