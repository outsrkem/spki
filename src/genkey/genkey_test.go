package genkey

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestCreateKeyAndPEM(t *testing.T) {
	cases := []struct {
		algo string
		size int
	}{
		{"rsa", 2048},
		{"ecdsa", 256},
		{"ecdsa", 384},
		{"ecdsa", 521},
		{"ed25519", 0},
	}

	for _, c := range cases {
		key, err := CreateKey(c.algo, c.size)
		if err != nil {
			t.Fatalf("CreateKey(%s,%d) failed: %v", c.algo, c.size, err)
		}
		pemBytes, err := PrivateKeyToPEM(key)
		if err != nil {
			t.Fatalf("PrivateKeyToPEM(%s) failed: %v", c.algo, err)
		}
		block, _ := pem.Decode(pemBytes)
		if block == nil || block.Type != "PRIVATE KEY" {
			t.Fatalf("unexpected PEM block for %s: %+v", c.algo, block)
		}
		if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
			t.Fatalf("ParsePKCS8PrivateKey(%s) failed: %v", c.algo, err)
		}
	}
}

func TestGenerateRandomPassword(t *testing.T) {
	if _, err := GenerateRandomPassword(0); err == nil {
		t.Fatal("expected error for length 0")
	}
	pw, err := GenerateRandomPassword(32)
	if err != nil {
		t.Fatalf("GenerateRandomPassword failed: %v", err)
	}
	if len(pw) != 32 {
		t.Fatalf("expected length 32, got %d", len(pw))
	}
}
