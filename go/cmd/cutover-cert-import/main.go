// Command cutover-cert-import is a narrow, one-purpose tool for the
// owner-preview cutover documented in CUTOVER.md: validate a
// cert/key pair (real key/cert match, validity window, SAN) and
// atomically promote it to a target path, using the exact same
// internal/tlscert.StageValidatePromote code path the real Encryption
// page's own upload/replace handler uses -- so this tool can never
// behave differently from what an owner uploading the same pair
// through the UI would get.
//
// Never prints key material -- only the same non-sensitive Status
// fields (subject, validity, SAN, self-signed) any successful upload
// already returns over the real API. Not installed anywhere
// permanent; built on demand from this source at cutover-prep time
// (see CUTOVER.md) and not shipped as a standing binary or exposed
// through any API.
package main

import (
	"fmt"
	"os"

	"alderpointdns/go-controlplane/internal/tlscert"
)

func main() {
	if len(os.Args) != 5 {
		fmt.Fprintln(os.Stderr, "usage: cutover-cert-import <src-cert> <src-key> <dest-cert> <dest-key>")
		os.Exit(2)
	}
	certPEM, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Println("read cert:", err)
		os.Exit(1)
	}
	keyPEM, err := os.ReadFile(os.Args[2])
	if err != nil {
		fmt.Println("read key:", err)
		os.Exit(1)
	}
	status, err := tlscert.StageValidatePromote(certPEM, keyPEM, os.Args[3], os.Args[4])
	if err != nil {
		fmt.Println("validate/promote FAILED:", err)
		os.Exit(1)
	}
	fmt.Printf("promoted ok: subject=%q not_before=%s not_after=%s san=%v self_signed=%v\n",
		status.Subject, status.NotBefore.Format("2006-01-02"), status.NotAfter.Format("2006-01-02"), status.SAN, status.IsSelfSigned)
}
