# dnsdist frontend

BindGuard uses dnsdist as the only client-facing DNS frontend.

Current lab configuration:

- Plain UDP/TCP DNS: `127.0.0.1:53`
- DoH: `https://127.0.0.1/dns-query`
- DoT: `127.0.0.1:853`
- BIND backend: `127.0.0.1:5353`
- ACL: loopback only until allowed client networks are supplied
- dnsdist web/API: `127.0.0.1:8083`, random local credentials
- dnsdist console: `127.0.0.1:5199`, random local key

The Debian 13 dnsdist `1.9.15-0+deb13u1` package reports these enabled
features:

`AF_XDP cdb dns-over-tls(openssl) dns-over-https(nghttp2) dnscrypt ebpf fstrm ipcipher libedit libsodium lmdb protobuf re2 recvmmsg/sendmmsg snmp systemd`

DoQ and DoH3 entry points exist in the binary, but runtime validation reports
that DNS-over-QUIC and DNS-over-HTTP/3 support is not present in this build.
BindGuard must display those transports as unavailable until a compatible
dnsdist build is installed.

Validation commands:

```sh
dnsdist --check-config -C /etc/dnsdist/dnsdist.conf
systemctl status dnsdist --no-pager
/opt/bindguard/tests/test_dnsdist_frontend.sh
```
