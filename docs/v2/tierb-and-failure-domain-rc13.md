# Tier B + failure-domain re-verification against RC13

Real installed RC13 package (2 GiB podman container). Bootstrap +
login via real HTTPS API, three real upstream DNS resolutions
(`example.com`/`.org`/`.net`, real internet egress from the
container).

## Tier B popularity tracking

After the analytics worker's drain cycle, `/var/lib/alderpointdns-v2/
tierb/working-set.json` shows real accumulated entries with correct
`hit_count`s matching the real query counts issued
(`example.com.`: 2, `example.org.`/`example.net.`: 1 each) --
confirms the full real pipeline (dnsdist RemoteLogAction/
RemoteLogResponseAction -> analytics-protobuf-receiver -> inbox ->
analytics-worker drain -> Tier B `WorkingSetIndex` -> persisted state
file) is intact end to end on this artifact. `alderpointdns-v2-tierb`
service itself: `active`, `NRestarts=0`, `MemoryCurrent` ~21 MB.

## Failure-domain independence (re-check with the RC13 Argon2id fix in place)

- Stopped `alderpointdns-v2-analytics-protobuf-receiver` -- real DNS
  query for `example.com` still answered correctly.
- `alderpointdns-v2-dnsdist`: `NRestarts=0` throughout.
- Restarted the receiver -- came back `active` immediately.

Matches the RC11 failure-domain finding
(`docs/v2/failure-domain-analytics-receiver.md`); re-confirmed here
against the current artifact rather than assumed still true.

## Conclusion

No regressions found. Tier B and the analytics-receiver failure domain
both continue to behave correctly on RC13, alongside the Argon2id
concurrency fix verified separately in
`docs/v2/argon2id-concurrency-defect-and-rc13-fix.md`.
