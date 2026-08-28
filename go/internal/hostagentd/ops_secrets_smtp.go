package hostagentd

import (
	"fmt"
	"net/smtp"
	"strings"
)

// sendTestSMTP performs a real SMTP send (STARTTLS opportunistically,
// like Python's smtplib.SMTP + starttls() pattern in app/notifications.py)
// using the decrypted password directly -- never logged, never returned.
// An empty username means an unauthenticated relay is attempted (some
// internal relays allow this), matching Python's own
// `if username and secret: client.login(...)` conditional.
func sendTestSMTP(cfg testNotifySMTP, password, message string) error {
	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	body := fmt.Sprintf("Subject: Alderpoint DNS test notification\r\nFrom: %s\r\nTo: %s\r\n\r\n%s\r\n", cfg.From, cfg.To, message)

	client, err := smtp.Dial(addr)
	if err != nil {
		return fmt.Errorf("connecting to %s: %w", addr, err)
	}
	defer client.Close()

	if ok, _ := client.Extension("STARTTLS"); ok {
		if err := client.StartTLS(nil); err != nil {
			return fmt.Errorf("STARTTLS: %w", err)
		}
	}

	if cfg.Username != "" && password != "" {
		if ok, _ := client.Extension("AUTH"); ok {
			auth := smtp.PlainAuth("", cfg.Username, password, cfg.Host)
			if err := client.Auth(auth); err != nil {
				return fmt.Errorf("authentication: %w", err)
			}
		}
	}

	if err := client.Mail(cfg.From); err != nil {
		return fmt.Errorf("MAIL FROM: %w", err)
	}
	for _, to := range strings.Split(cfg.To, ",") {
		to = strings.TrimSpace(to)
		if to == "" {
			continue
		}
		if err := client.Rcpt(to); err != nil {
			return fmt.Errorf("RCPT TO %s: %w", to, err)
		}
	}
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("DATA: %w", err)
	}
	if _, err := w.Write([]byte(body)); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return client.Quit()
}
