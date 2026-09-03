-- 0027_client_facing_address: owner-configurable client-facing address
-- for the Encryption page's DNS Transports setup instructions --
-- separate from whatever this process happens to listen/bind on
-- (frequently 0.0.0.0, or worse, a container-internal bridge address
-- like 10.88.0.15) and from the TLS certificate's own subject.
--
-- Real defect this fixes: DNS Transports setup guidance auto-detected
-- an address from the WEB CONTAINER's own isolated network namespace
-- (a Podman bridge address, e.g. 10.88.0.15) and displayed it as if a
-- phone, router, or other LAN client could use it to reach the
-- appliance -- none of them can. client_facing_hostname/ip let an
-- owner explicitly record the real answer once; when neither is set
-- and host-side detection (internal/hostagentd.HostLANCandidates) is
-- ambiguous (zero or more than one real LAN interface), the UI must
-- ask the owner to choose rather than guess.
ALTER TABLE dns_transport_settings ADD COLUMN client_facing_hostname TEXT NOT NULL DEFAULT '';
ALTER TABLE dns_transport_settings ADD COLUMN client_facing_ip TEXT NOT NULL DEFAULT '';
-- client_facing_prefer: 'auto' (default -- prefer a real cert hostname,
-- else the saved/detected IP), 'hostname', or 'ip'. Lets an owner with
-- both a working DNS hostname AND a static LAN IP configured pick which
-- one setup instructions should lead with.
ALTER TABLE dns_transport_settings ADD COLUMN client_facing_prefer TEXT NOT NULL DEFAULT 'auto';
