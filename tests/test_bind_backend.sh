#!/bin/sh
set -eu
named-checkconf /etc/bind/named.conf
named-checkzone bindguard.rpz /var/lib/bindguard/compiled/bind/bindguard.rpz
dig +time=3 +tries=1 @127.0.0.1 -p 5353 debian.org A | grep -Eq 'status: NOERROR'
dig +tcp +time=3 +tries=1 @127.0.0.1 -p 5353 debian.org A | grep -Eq 'status: NOERROR'
dig +dnssec +time=3 +tries=1 @127.0.0.1 -p 5353 cloudflare.com A | grep -Eq 'flags:.* ad[ ;]'
dig +time=3 +tries=1 @127.0.0.1 -p 5353 dnssec-failed.org A | grep -Eq 'status: SERVFAIL'
if ss -H -lntup 'sport = :5353' |
	awk '{ print $5 }' |
	grep -Ev '^(127[.]0[.]0[.]1:5353|[[]::1[]]:5353)$'; then
	echo "BIND is listening on a non-loopback backend address" >&2
	exit 1
fi
echo "BIND backend acceptance tests passed"
