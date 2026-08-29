// Real health-condition checker for the tls_cert_expiring event category
// -- closing one of the five disclosed-but-unwired categories in
// dispatch.go's EventCategories, matching app/notify_check.py's own
// periodic monitoring design (read directly): a scheduled goroutine,
// not an on-demand check, since nothing else in this control plane's
// request path naturally observes "how close is the cert to expiring"
// on its own.
package notifications

import (
	"context"
	"fmt"
	"time"

	"alderpointdns/go-controlplane/internal/tlscert"
)

// DefaultTLSExpiryWarnDays matches the reference implementation's own
// default warning window.
const DefaultTLSExpiryWarnDays = 30

// CheckTLSCertExpiry reads the real, currently-active management TLS
// certificate (the same one internal/tlscert already serves this
// process's own HTTPS listener from, and DoT/DoH/DoQ reuse) and
// dispatches a real tls_cert_expiring event when it's within
// warnWithinDays of NotAfter -- including if it has already expired.
// A missing/unconfigured cert path or a read failure is not itself an
// error worth dispatching over (this control plane may legitimately run
// plain HTTP in a given deployment); it's logged by the caller's own
// scheduler loop instead.
func (s *Service) CheckTLSCertExpiry(ctx context.Context, certPath string, warnWithinDays int) error {
	if certPath == "" {
		return nil
	}
	status, err := (&tlscert.Reader{CertPath: certPath}).Status()
	if err != nil {
		return fmt.Errorf("reading TLS certificate status: %w", err)
	}
	if !status.Active {
		return nil
	}
	daysLeft := int(time.Until(status.NotAfter).Hours() / 24)
	if daysLeft > warnWithinDays {
		return nil
	}
	severity := "warning"
	var summary string
	if daysLeft < 0 {
		severity = "critical"
		summary = fmt.Sprintf("The management TLS certificate (%s) expired %d day(s) ago", status.Subject, -daysLeft)
	} else {
		summary = fmt.Sprintf("The management TLS certificate (%s) expires in %d day(s)", status.Subject, daysLeft)
	}
	_, err = s.Dispatch(ctx, "tls_cert_expiring", severity, "tls_certificate", summary, false)
	return err
}

// RunTLSExpiryScheduler is a single, bounded goroutine that periodically
// calls CheckTLSCertExpiry -- the same "one ticker, not one per check"
// discipline internal/blocklists.Service.RunScheduler already uses.
func (s *Service) RunTLSExpiryScheduler(ctx context.Context, certPath string, warnWithinDays int, tick time.Duration) {
	ticker := time.NewTicker(tick)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.CheckTLSCertExpiry(ctx, certPath, warnWithinDays); err != nil && s.Log != nil {
				s.Log.Error("tls cert expiry check failed", "err", err)
			}
		}
	}
}
