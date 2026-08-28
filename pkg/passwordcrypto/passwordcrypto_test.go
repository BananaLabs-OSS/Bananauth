package passwordcrypto

import "testing"

func TestHashAndVerify(t *testing.T) {
	hash, err := Hash("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !Verify(hash, "correct horse battery staple") || Verify(hash, "wrong") {
		t.Fatal("password verification mismatch")
	}
}
