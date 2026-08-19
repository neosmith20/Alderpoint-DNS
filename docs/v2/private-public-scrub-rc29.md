# Private/public export-surface scrub, RC29

Roadmap continuation: before treating the private candidate as Gate #3-
ready, scan the actual exportable/package surface (not the private
engineering tree, which is allowed to retain internal docs/commentary
by design) for anything that must never ship: obsolete project names,
personal domains, private/live DNS server names, credentials, secrets,
private infrastructure identifiers, internal agent instructions/
commentary, private UI design critique, private fixtures/logs.

## Method

Extracted the real, exact RC29 artifact
(`alderpointdns-v2_2.0.0~rc29-1_all.deb`, sha256
`0b0a06427ffec93e9949905467c23cc90d8eaca82c4552f9ceae30bc0038472c`) --
both the data payload (`dpkg-deb -x`) and the maintainer control
scripts (`dpkg-deb -e`, i.e. `postinst`/`preinst`/`prerm`/`postrm`) --
and grepped the actual shipped bytes, not source-tree assumptions.
Also grepped the git-tracked repository's `docs/v2/*.md` (this
continuation's own written record) for accidentally-pasted real
secret/credential values, since those must never leak regardless of
public/private tree placement.

## Results

- **Full package file listing**: only `.py`/`.js`/`.css`/`.html`/
  `.service`/`.whl`/`copyright`/`LICENSE` files -- no logs, no docs, no
  test fixtures, no stray database/backup artifacts.
- **Agent names / internal commentary** (`Dex`, `Goose`, `Claude`,
  `Anthropic`, `Alex`): only match found is the legitimate copyright
  attribution (`Copyright 2026 Alex (GitHub: neosmith20)`) in
  `copyright`/`LICENSE` -- the real product owner's real name/handle in
  a real copyright notice, not an internal codename or agent
  reference.
- **Credentials/secrets patterns** (private key headers, hardcoded
  passwords/API keys/secrets): zero hits.
- **Real/personal IP addresses** (excluding RFC1918/loopback/
  documented public-DNS test ranges): zero hits -- the one non-obvious
  match, `192.0.2.1`, is RFC 5737 TEST-NET-1, reserved specifically for
  documentation/examples.
- **Domains**: every real match is a legitimate, intentional reference
  -- public SafeSearch provider domains (`google.com`, `bing.com`,
  `duckduckgo.com`, `youtube.com`) in `safesearch.py`, the product's
  own default DNSCrypt provider name
  (`2.dnscrypt-cert.alderpointdns-v2.local`), and standard
  `hostmaster.localhost` SOA convention. No test/scratch/personal
  domains.
- **Obsolete project name** (`bindguard`, this product's pre-rename
  name, confirmed still present in this session's own home-directory
  scratch files from earlier development): zero hits anywhere in the
  package.
- **Dev-host/scratch paths** (`/root/alderpointdns-work`,
  `/tmp/apdns-*`, `/tmp/dnscrypt-*`, `/tmp/tierb-*`, the podman bridge
  subnet `10.88.0.*` this session's containers used): zero hits.
- **Maintainer scripts** (`postinst`/`preinst`/`prerm`/`postrm`): same
  checks, zero hits.
- **This continuation's own docs** (`docs/v2/*.md`): zero hits for any
  test password used during live verification this session
  (`Testing-Password-9182!`, `correcthorsebattery12`, bootstrap tokens),
  zero hits for pasted private-key material or console keys. Public-key
  fingerprints documented (e.g. the DNSCrypt provider fingerprints in
  `docs/v2/package-baseline-rc25.md`/`rc26.md`) are intentionally not
  secrets -- a DNSCrypt provider fingerprint exists specifically to be
  published for client verification, the same way a TLS certificate
  fingerprint would be.
- **Git-tracked files**: no stray `.db`/`.sqlite`/`.pem`/`.key`/`.p12`/
  backup-archive/`.deb` files committed anywhere in the repository.

## Conclusion

No findings requiring remediation. The RC29 package/export surface is
clean of everything this scrub checks for. Internal engineering docs
(`docs/v2/*.md`) remain in the private tree as designed -- they were
checked only for accidental real-secret leakage, not removed or
redacted, since private-tree internal commentary is explicitly allowed
to remain by the roadmap's own scope.
