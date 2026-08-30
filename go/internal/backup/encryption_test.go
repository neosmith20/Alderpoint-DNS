package backup

// Real proof that an optional passphrase on the native backup archive
// actually protects it -- added 2026-08-29 to close a real, previously
// disclosed owner-facing gap versus V1.1.1's own optional password-
// protected `.tar.gz.enc` (see service.go's own top-of-file doc
// comment). Every test here uses a disposable, obviously-fake test
// passphrase string local to the test itself -- never logged, never
// asserted against in any failure message that would echo it back.

import (
	"context"
	"errors"
	"os"
	"testing"
)

const testPassphrase = "correct horse battery staple test only"

func TestEncryptDecryptArchiveRoundTrip(t *testing.T) {
	plaintext := []byte("a real tar archive's bytes, or close enough for this unit test")
	envelope, err := encryptArchive(plaintext, testPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	if !isEncryptedArchive(envelope) {
		t.Fatal("expected the envelope to be detected as encrypted by its own magic header")
	}
	if isEncryptedArchive(plaintext) {
		t.Fatal("expected the original plaintext to NOT be detected as encrypted")
	}
	got, err := decryptArchive(envelope, testPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(plaintext) {
		t.Fatalf("round trip did not preserve the plaintext: got %q", got)
	}
}

func TestDecryptArchiveWithWrongPassphraseFails(t *testing.T) {
	envelope, err := encryptArchive([]byte("secret backup contents"), testPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decryptArchive(envelope, "definitely the wrong passphrase"); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("expected ErrWrongPassphrase, got %v", err)
	}
	if _, err := decryptArchive(envelope, ""); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("expected ErrWrongPassphrase for an empty passphrase against an encrypted envelope, got %v", err)
	}
}

func TestDecryptArchiveRejectsTamperedCiphertext(t *testing.T) {
	envelope, err := encryptArchive([]byte("secret backup contents"), testPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte{}, envelope...)
	tampered[len(tampered)-1] ^= 0xFF // flip a bit in the ciphertext/tag
	if _, err := decryptArchive(tampered, testPassphrase); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("expected GCM's own authentication to reject tampered ciphertext (ErrWrongPassphrase), got %v", err)
	}
}

// TestCreateWithPassphraseProducesARealEncryptedFile is the end-to-end
// proof that Create's own passphrase parameter actually reaches the
// on-disk file: the raw bytes on disk are NOT a readable tar (an
// attacker/a nosy household member who copies the file off the
// filesystem gets nothing readable without the passphrase), and List's
// own bulk pass reports it as encrypted without needing one.
func TestCreateWithPassphraseProducesARealEncryptedFile(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	seedOneLocalDNSRecord(t, s.DB, "host1.lan")

	info, err := s.Create(ctx, "manual", testPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Encrypted {
		t.Fatal("expected Create to report Encrypted:true when given a passphrase")
	}

	raw, err := os.ReadFile(s.Dir + "/" + info.Filename)
	if err != nil {
		t.Fatal(err)
	}
	if !isEncryptedArchive(raw) {
		t.Fatal("expected the real on-disk file to carry the encrypted-envelope magic header")
	}
	// The point of encryption: manifest.json/control.db must not be
	// findable as plaintext anywhere in the raw file (a weak "encrypted"
	// implementation that still leaks the tar structure would defeat the
	// whole purpose).
	if containsBytes(raw, []byte("manifest.json")) || containsBytes(raw, []byte("control.db")) {
		t.Fatal("real tar entry names are readable in the supposedly-encrypted file -- encryption is not actually protecting the contents")
	}

	list, err := s.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || !list[0].Encrypted {
		t.Fatalf("expected List to report the backup as encrypted without needing a passphrase, got %+v", list)
	}
	if list[0].TableCounts != nil || list[0].SourceVersion != "" {
		t.Fatalf("expected List's own no-passphrase view to carry no real manifest detail for an encrypted backup, got %+v", list[0])
	}
}

func containsBytes(haystack, needle []byte) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func TestPreviewOfEncryptedBackupRequiresPassphrase(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	seedOneLocalDNSRecord(t, s.DB, "host1.lan")
	info, err := s.Create(ctx, "manual", testPassphrase)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := s.Preview(ctx, info.Filename, ""); !errors.Is(err, ErrPassphraseRequired) {
		t.Fatalf("expected ErrPassphraseRequired with no passphrase, got %v", err)
	}
	if _, err := s.Preview(ctx, info.Filename, "wrong one"); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("expected ErrWrongPassphrase for an incorrect passphrase, got %v", err)
	}
	preview, err := s.Preview(ctx, info.Filename, testPassphrase)
	if err != nil {
		t.Fatalf("expected the correct passphrase to succeed, got %v", err)
	}
	if !preview.Encrypted || preview.TableCounts == nil {
		t.Fatalf("expected a real, full manifest once the correct passphrase is given, got %+v", preview)
	}
	if preview.TableCounts["local_dns_records"] != 1 {
		t.Fatalf("expected the real table count to survive encryption/decryption, got %+v", preview.TableCounts)
	}
}

func TestPreviewOrMinimalAcceptsAnEncryptedUploadWithoutAPassphrase(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	info, err := s.Create(ctx, "manual", testPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.PreviewOrMinimal(ctx, info.Filename)
	if err != nil {
		t.Fatalf("expected PreviewOrMinimal to accept an encrypted file without a passphrase, got %v", err)
	}
	if !got.Encrypted {
		t.Fatalf("expected Encrypted:true, got %+v", got)
	}
}

// TestRestoreOfEncryptedBackupRequiresThePassphrase is the core
// regression proof this task asked for: an encrypted backup cannot be
// restored (i.e. cannot overwrite real live data) without the correct
// passphrase, and the live data is provably untouched by every failed
// attempt.
func TestRestoreOfEncryptedBackupRequiresThePassphrase(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	seedOneLocalDNSRecord(t, s.DB, "original.lan")

	backupOfOriginal, err := s.Create(ctx, "manual", testPassphrase)
	if err != nil {
		t.Fatal(err)
	}

	// Change live data after the backup, so a real restore would be
	// observable.
	if _, err := s.DB.Exec(`UPDATE local_dns_records SET name='changed.lan' WHERE name='original.lan'`); err != nil {
		t.Fatal(err)
	}

	assertLiveName := func(want string) {
		t.Helper()
		var name string
		if err := s.DB.QueryRow(`SELECT name FROM local_dns_records LIMIT 1`).Scan(&name); err != nil {
			t.Fatal(err)
		}
		if name != want {
			t.Fatalf("expected live data to still read %q, got %q", want, name)
		}
	}

	// No passphrase: must fail, live data untouched.
	if _, err := s.Restore(ctx, backupOfOriginal.Filename, "", nil); !errors.Is(err, ErrPassphraseRequired) {
		t.Fatalf("expected ErrPassphraseRequired, got %v", err)
	}
	assertLiveName("changed.lan")

	// Wrong passphrase: must fail, live data untouched.
	if _, err := s.Restore(ctx, backupOfOriginal.Filename, "still wrong", nil); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("expected ErrWrongPassphrase, got %v", err)
	}
	assertLiveName("changed.lan")

	// Correct passphrase: the real restore actually happens.
	if _, err := s.Restore(ctx, backupOfOriginal.Filename, testPassphrase, nil); err != nil {
		t.Fatalf("expected the correct passphrase to actually restore, got %v", err)
	}
	assertLiveName("original.lan")
}

// TestPreRestoreSafetyBackupIsNeverEncrypted proves the deliberate
// design choice documented on Restore's own doc comment: even when
// restoring FROM an encrypted backup, the automatic pre-restore safety
// backup it takes first is always plain -- an unattended safety net a
// human passphrase could otherwise make unusable during an actual
// emergency.
func TestPreRestoreSafetyBackupIsNeverEncrypted(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	seedOneLocalDNSRecord(t, s.DB, "host1.lan")
	backupOfOriginal, err := s.Create(ctx, "manual", testPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	safety, err := s.Restore(ctx, backupOfOriginal.Filename, testPassphrase, nil)
	if err != nil {
		t.Fatal(err)
	}
	if safety.Encrypted {
		t.Fatal("expected the mandatory pre-restore safety backup to never be encrypted, even when restoring from an encrypted backup")
	}
}

// TestScheduledAndAutomatedBackupsAreNeverEncrypted proves the other
// half of the same design choice for every automated Create call site
// this package's own doc comment names -- an unattended process cannot
// usefully produce a passphrase-protected backup of itself.
func TestScheduledAndAutomatedBackupsAreNeverEncrypted(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	if err := s.SetScheduleSettings(ctx, true, 24, 7); err != nil {
		t.Fatal(err)
	}
	result := s.runScheduledTickOnce(ctx)
	if !result.Ran || result.Failed {
		t.Fatalf("expected the scheduled tick to run successfully, got %+v", result)
	}
	list, err := s.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Encrypted {
		t.Fatalf("expected exactly one, unencrypted, scheduled backup, got %+v", list)
	}
}
