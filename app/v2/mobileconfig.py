"""Apple .mobileconfig DNS-enrollment profiles (beta-rescue priority 3D).

Generates a real `com.apple.dnsSettings.managed` configuration profile
(the same plist-based format V1.1.1 generated, via the stdlib `plistlib`
-- no new dependency) for whichever encrypted-DNS transport V2 actually
has enabled and reachable right now. Deliberately does NOT reuse
app.encryption.apple_mobileconfig's own V1-coupled `cfg` dict/
detect_server_ip() plumbing -- the plist shape it produces is copied
here verbatim (it's the correct, working Apple profile format), but the
inputs come from V2's own real state: app/v2/policy_store.py's
DnsTransportSettings (is this transport actually enabled) and
app/v2/tls_cert.py's CertInfo (the real active certificate's own SAN,
which is also the only hostname a client can actually validate the
connection against -- never a hostname the profile author merely typed
in, and never any key material, since CertInfo itself never carries
one).
"""

from __future__ import annotations

import plistlib
import uuid
from typing import Optional

from app.v2.policy_store import DnsTransportSettings
from app.v2.tls_cert import CertInfo

SUPPORTED_PROTOCOLS = ("doh", "dot")  # Apple's managed DNS profile format has no DoQ/DoH3 protocol value


class MobileconfigError(ValueError):
    pass


def build_mobileconfig(protocol: str, transport: DnsTransportSettings, cert: Optional[CertInfo]) -> bytes:
    if protocol not in SUPPORTED_PROTOCOLS:
        raise MobileconfigError(f"unsupported protocol: {protocol!r} (supported: {SUPPORTED_PROTOCOLS})")
    if protocol == "doh" and not transport.doh_enabled:
        raise MobileconfigError("DNS-over-HTTPS is not enabled on this appliance -- enable it before generating a profile for it")
    if protocol == "dot" and not transport.dot_enabled:
        raise MobileconfigError("DNS-over-TLS is not enabled on this appliance -- enable it before generating a profile for it")
    if cert is None or not cert.san:
        raise MobileconfigError("no active HTTPS certificate with a subject alternative name is configured yet")

    hostname = cert.san[0]
    payload_uuid = str(uuid.uuid4()).upper()
    profile_uuid = str(uuid.uuid4()).upper()

    if protocol == "doh":
        dns_settings = {
            "DNSProtocol": "HTTPS",
            "ServerURL": f"https://{hostname}:{transport.doh_port}{transport.doh_path}",
            "ServerName": hostname,
        }
        label = "DNS-over-HTTPS"
    else:
        dns_settings = {
            "DNSProtocol": "TLS",
            "ServerName": hostname,
        }
        label = "DNS-over-TLS"

    payload = {
        "PayloadType": "com.apple.dnsSettings.managed",
        "PayloadIdentifier": f"appliance.alderpointdns-v2.dns.{protocol}",
        "PayloadUUID": payload_uuid,
        "PayloadVersion": 1,
        "PayloadDisplayName": f"Alderpoint DNS V2 {label}",
        **dns_settings,
    }
    profile = {
        "PayloadContent": [payload],
        "PayloadDisplayName": f"Alderpoint DNS V2 {label} ({hostname})",
        "PayloadIdentifier": f"appliance.alderpointdns-v2.profile.{protocol}",
        "PayloadRemovalDisallowed": False,
        "PayloadType": "Configuration",
        "PayloadUUID": profile_uuid,
        "PayloadVersion": 1,
    }
    return plistlib.dumps(profile, fmt=plistlib.FMT_XML)
