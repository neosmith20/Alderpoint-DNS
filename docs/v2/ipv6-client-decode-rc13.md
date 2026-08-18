# IPv6 client-address decode: closed the last "not independently verified" gap from RC6

`docs/v2/package-baseline-rc6.md` flagged this as open scope: the
protobuf decoder's IPv6 branch for PBDNSMessage field 6 ("from") was
implemented per PowerDNS's published schema but never exercised
against a real IPv6 query -- only the IPv4 case (4 raw bytes) had been
confirmed live.

## Method

The packaged default dnsdist config only binds IPv4
(`setLocal("0.0.0.0:53")`) -- there is no admin-facing setting to add
an IPv6 listener yet, so this isn't reachable through normal appliance
use today. To close the verification gap honestly rather than leave it
open indefinitely, temporarily extended the compiled config on a real
installed RC13 container with an additional
`setLocal("[::]:53")`, restarted `alderpointdns-v2-dnsdist`, and issued
a real `dig -6 @::1 example.com A` (both the container's loopback
`::1` and `eth0`'s real link-local address were available).

## Result

Real end-to-end proof through the actual receiver:

- `dig -6` resolved correctly (real upstream answer).
- The real analytics-protobuf-receiver's inbox JSONL event for that
  query: `{"...,"client":"::1",...}` -- the real 16-byte wire encoding
  of `::1` (15 zero bytes + `0x01`) was decoded to the exact correct
  string, through the real production code path, not a synthetic
  buffer.

Config reverted immediately after the test (`setLocal("0.0.0.0:53")`
only, matching every other RC's default), `alderpointdns-v2-dnsdist`
restarted and confirmed still answering real IPv4 queries correctly
afterward.

## Code/test changes

- `app/v2/dnsdist_protobuf.py`'s `_client_ip` docstring updated to
  reflect the now-verified status.
- `tests/v2/test_dnsdist_protobuf.py`: new `TestClientIpDecode` class
  pins the real confirmed `::1` wire encoding as a permanent regression
  fixture, plus the pre-existing IPv4 case and the malformed-length
  error path.

## Conclusion

The IPv6 decode path is now genuinely verified, not just
schema-plausible. Whether to expose an admin-facing IPv6 listen
address as a real feature remains a separate, un-requested roadmap
item (not found in `docs/v2/roadmap-reference/*.md`) and is left as a
future feature decision, not implemented here.
