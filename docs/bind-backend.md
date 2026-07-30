# BIND backend

The installed backend is BIND 9.20.26 and is enabled as `named.service`.

## Network boundary

BIND listens only on loopback. `127.0.0.1:5353` and `[::1]:5353` provide
plain loopback recursion for health and recovery checks; `127.0.0.1:5354`
requires PROXYv2 from dnsdist so BIND can evaluate the original client address.
It does not listen on port 53 or on the VM interface. Queries and recursion are
restricted to localhost. dnsdist will be its only production client.

## Resolution and validation

Client DNS is forwarded to the configured maintenance-grade upstream set:
`1.1.1.2`, `1.0.0.2`, `4.2.2.1`, and `4.2.2.2`. DNSSEC validation is enabled.
This upstream path is separate from management resolution: management software
uses the host resolver from `/etc/resolv.conf`.

The filtering zone is `alderpointdns.rpz`. Its generated file is
`/var/lib/alderpointdns/compiled/bind/alderpointdns.rpz`.

## Operations

Validate:

```sh
named-checkconf /etc/bind/named.conf
named-checkzone alderpointdns.rpz /var/lib/alderpointdns/compiled/bind/alderpointdns.rpz
```

Test:

```sh
/opt/alderpointdns/tests/test_bind_backend.sh
```

Inspect:

```sh
systemctl status named
rndc status
ss -lntup '( sport = :5353 or sport = :5354 )'
curl http://127.0.0.1:8053/json/v1/status
```

The package-default configurations are preserved under
`/var/lib/alderpointdns/backups`. AppArmor additions are isolated in
`/etc/apparmor.d/local/usr.sbin.named`.
