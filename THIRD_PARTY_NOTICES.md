# Third-Party Notices

Alderpoint DNS is source-available under the [PolyForm Noncommercial
License 1.0.0](LICENSE) (see `COPYRIGHT`). It integrates with and depends
on the third-party software listed below. **None of it is relicensed by
Alderpoint DNS's license** — each component remains under its own license,
whether it is installed as an operating-system package, installed as a
Python package, or merely invoked as a separate running service.

This audit covers the repository's own source (`app/`, `web/`, `scripts/`,
`packaging/`, `tests/`), its Python and Debian dependency manifests
(`requirements.txt`, `requirements-debian.txt`, `packaging/debian/control`),
and its runtime integration with BIND and dnsdist. No vendored/copied
third-party source code, fonts, icons, or images were found bundled in the
repository as of this audit — `web/static/app.css` and `web/static/app.js`
are original, project-authored files with no vendored library code, and
`tests/fixtures/adguard_home.yaml` / `tests/fixtures/pihole_export.txt` are
synthetic fixtures written to match those tools' export *formats*, not
copies of either project's own source or real user data.

None of the components below are copied into, statically linked into, or
otherwise bundled inside the Alderpoint DNS source tree or the `.deb`
package's own code. Large license texts are not reproduced here; consult
each project's own distribution for its full license text.

## Runtime services (invoked as separate operating-system packages/processes)

Installed via `apt` from `packaging/debian/control`'s `Depends`, and run as
their own independent system services/processes, not linked into
Alderpoint DNS's own Python code.

| Component | Purpose | Upstream project | License |
|---|---|---|---|
| BIND 9 | Recursive/authoritative DNS backend (RPZ filtering, local zones) | <https://www.isc.org/bind/> | MPL-2.0 |
| PowerDNS dnsdist | Client-facing DNS load balancer/frontend (DoH/DoT/DoQ, ACLs, rate limiting) | <https://dnsdist.org/> | GPL-2.0-only |
| bind9-dnsutils | `dig` and related BIND diagnostic tools | <https://www.isc.org/bind/> | MPL-2.0 |
| knot-dnsutils | `kdig` (used for DoQ/DoT verification) | <https://www.knot-dns.cz/> | GPL-3.0-or-later |
| curl | HTTP client used by scripts/diagnostics | <https://curl.se/> | curl license (permissive, MIT/X-derivative) |
| jq | JSON processor used by scripts/diagnostics | <https://jqlang.org/> | MIT |
| OpenSSL | TLS/certificate tooling (`openssl` CLI, used for cert generation) | <https://www.openssl.org/> | Apache-2.0 |
| sudo | Narrow, allowlisted privilege escalation for the web app's deploy path (`packaging/sudoers-alderpointdns`) | <https://www.sudo.ws/> | ISC-style permissive license |

Alderpoint DNS's Python code communicates with BIND and dnsdist over their
own local control-plane protocols (rndc, dnsdist's console/API) and by
generating configuration files for them; it does not statically or
dynamically link against their code.

## Python dependencies (`requirements.txt`)

Installed via `pip`/Debian's `python3-*` packages (see
`requirements-debian.txt`), not vendored into this repository.

| Package | Purpose | License |
|---|---|---|
| FastAPI | Web application framework | MIT |
| Uvicorn | ASGI server | BSD-3-Clause |
| Jinja2 | HTML templating | BSD-3-Clause |
| itsdangerous | Signed session cookies | BSD-3-Clause |
| python-multipart | Multipart form/file upload parsing | Apache-2.0 |
| httpx | HTTP client (AdGuard Home live import, health checks) | BSD-3-Clause |
| dnspython | DNS query/record handling | ISC-style permissive license |
| argon2-cffi | Password hashing | MIT |
| openpyxl | XLSX import/export | MIT |
| PyYAML | AdGuard Home YAML import | MIT |
| aioquic (`python3-aioquic`, Debian runtime only) | DoQ/HTTP3 support used by test/verification tooling | BSD-3-Clause |

## What this means for Alderpoint DNS's own code

Alderpoint DNS's own source is distributed under the PolyForm Noncommercial
License 1.0.0. The permissive licenses above (MIT, BSD-3-Clause, ISC,
Apache-2.0, MPL-2.0, the curl license) do not require this project to
adopt their terms. The copyleft licenses above (BIND9-associated
bind9-dnsutils under MPL-2.0, dnsdist under GPL-2.0-only, knot-dnsutils
under GPL-3.0-or-later) apply to those separate programs; Alderpoint DNS
interacts with them as independent operating-system services/processes
(configuration files, rndc, dnsdist's console/API) rather than by
compiling, statically linking, or otherwise incorporating their source
code — this document states that technical fact and does not itself
constitute legal advice about license compatibility.

## Reporting a concern

If you believe any component listed here (or found elsewhere in the
repository) has been mischaracterized, or that any bundled material has
unclear or incompatible licensing, please open an issue rather than assume
— see `CONTRIBUTING.md`.
