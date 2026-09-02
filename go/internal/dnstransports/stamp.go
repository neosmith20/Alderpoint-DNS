package dnstransports

import "encoding/base64"

// BuildDNSCryptStamp encodes a real sdns:// DNSCrypt stamp, per the
// DNSCrypt stamp spec (https://dnscrypt.info/stamps-specifications):
// protocol byte 0x01 (DNSCrypt), an 8-byte little-endian properties
// bitfield (0 -- this appliance sets no DNSSEC/NoLogs/NoFilter claims),
// then three length-prefixed fields: the "address:port" clients connect
// to, the provider's Ed25519 public key (the same 32 raw bytes already
// stored as DNSCryptProviderPublicKeyB64 -- it IS the pinned trust
// anchor, not a certificate), and the provider name. Every field here is
// short (well under the single-byte length prefix's 255-byte limit), so
// this deliberately doesn't implement the spec's multi-byte continuation
// encoding for longer fields.
func BuildDNSCryptStamp(addr string, providerPublicKey []byte, providerName string) string {
	b := make([]byte, 0, 1+8+1+len(addr)+1+len(providerPublicKey)+1+len(providerName))
	b = append(b, 0x01)
	b = append(b, 0, 0, 0, 0, 0, 0, 0, 0)
	b = appendLengthPrefixed(b, []byte(addr))
	b = appendLengthPrefixed(b, providerPublicKey)
	b = appendLengthPrefixed(b, []byte(providerName))
	return "sdns://" + base64.RawURLEncoding.EncodeToString(b)
}

func appendLengthPrefixed(b, field []byte) []byte {
	if len(field) > 255 {
		field = field[:255] // defensive only -- every real caller's fields are far shorter
	}
	b = append(b, byte(len(field)))
	return append(b, field...)
}
