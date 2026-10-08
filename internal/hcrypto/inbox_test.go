package hcrypto

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"testing"
)

func TestInboxRoundTrip(t *testing.T) {
	private, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// The web app stores the public key in SPKI form, standard base64.
	spki, err := x509.MarshalPKIXPublicKey(private.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	public, err := ParseInboxPublicKey(base64.StdEncoding.EncodeToString(spki))
	if err != nil {
		t.Fatal(err)
	}

	envelope, err := EncryptForInbox(public, []byte(`{"message":"hello"}`))
	if err != nil {
		t.Fatal(err)
	}
	salt, _ := base64.StdEncoding.DecodeString(envelope.HKDFSalt)
	iv, _ := base64.StdEncoding.DecodeString(envelope.IV)
	if len(salt) != 32 || len(iv) != 12 {
		t.Fatalf("salt %d bytes, IV %d bytes", len(salt), len(iv))
	}
	plain, err := DecryptInboxMessage(private, envelope)
	if err != nil || string(plain) != `{"message":"hello"}` {
		t.Fatalf("got %q, %v", plain, err)
	}

	other, _ := ecdh.P256().GenerateKey(rand.Reader)
	if _, err := DecryptInboxMessage(other, envelope); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("another key: got %v", err)
	}
}

func TestParseInboxPublicKeyRejectsOtherKeys(t *testing.T) {
	for _, value := range []string{"", "AAAA", "not base64"} {
		if _, err := ParseInboxPublicKey(value); err == nil {
			t.Fatalf("%q must fail", value)
		}
	}
	x25519, _ := ecdh.X25519().GenerateKey(rand.Reader)
	spki, err := x509.MarshalPKIXPublicKey(x25519.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseInboxPublicKey(base64.StdEncoding.EncodeToString(spki)); err == nil {
		t.Fatal("an X25519 key must fail")
	}
}
