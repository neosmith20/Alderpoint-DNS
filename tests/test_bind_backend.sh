#!/bin/sh
set -eu
named-checkconf /etc/bind/named.conf
named-checkzone alderpointdns.rpz /var/lib/alderpointdns/compiled/bind/alderpointdns.rpz
dig +time=3 +tries=1 @127.0.0.1 -p 5353 debian.org A | grep -Eq 'status: NOERROR'
dig +tcp +time=3 +tries=1 @127.0.0.1 -p 5353 debian.org A | grep -Eq 'status: NOERROR'
if dig +time=1 +tries=1 @127.0.0.1 -p 5354 debian.org A >/tmp/alderpointdns-direct-5354.out 2>&1; then
	echo "BIND PROXYv2 backend accepted direct DNS without a PROXY header" >&2
	exit 1
fi
/opt/alderpointdns/tests/proxyv2_query.py --source-ip 10.9.8.7 --expect-rcode 0 debian.org
/opt/alderpointdns/tests/proxyv2_query.py --source-ip 203.0.113.9 --expect-rcode 5 debian.org
dig +dnssec +time=3 +tries=1 @127.0.0.1 -p 5353 cloudflare.com A | grep -Eq 'flags:.* ad[ ;]'
dig +time=3 +tries=1 @127.0.0.1 -p 5353 dnssec-failed.org A | grep -Eq 'status: SERVFAIL'
if ss -H -lntup '( sport = :5353 or sport = :5354 )' |
	awk '{ print $5 }' |
	grep -Ev '^(127[.]0[.]0[.]1:(5353|5354)|[[]::1[]]:5353)$'; then
	echo "BIND is listening on a non-loopback backend address" >&2
	exit 1
fi
echo "BIND backend acceptance tests passed"
