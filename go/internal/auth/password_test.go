package auth

import "testing"

func TestHashAndVerifyPasswordRoundTrip(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !VerifyPassword(hash, "correct horse battery staple") {
		t.Error("VerifyPassword should accept the correct password")
	}
	if VerifyPassword(hash, "wrong password") {
		t.Error("VerifyPassword should reject an incorrect password")
	}
}

func TestVerifyPasswordFailsClosedOnMalformedHash(t *testing.T) {
	cases := []string{"", "not-a-hash-at-all", "$bcrypt$abc$def", "$argon2id$v=19$m=x,t=3,p=2$salt$hash"}
	for _, c := range cases {
		if VerifyPassword(c, "anything") {
			t.Errorf("VerifyPassword(%q) should fail closed (false), got true", c)
		}
	}
}

func TestHashPasswordProducesUniqueSalts(t *testing.T) {
	h1, _ := HashPassword("same password")
	h2, _ := HashPassword("same password")
	if h1 == h2 {
		t.Error("two hashes of the same password should differ (random salt)")
	}
}
