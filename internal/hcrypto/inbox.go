package hcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
)

// The organization inbox uses public-key encryption, as src/lib/inboxCrypto.ts
// in the web app:
//   - The organization has an ECDH P-256 key pair. Its passphrase protects the
//     private key, so only the organization can decrypt.
//   - A sender makes a one-time ECDH P-256 key pair and derives the shared
//     secret with the inbox public key.
//   - HKDF-SHA256 with a random 32-byte salt and the info "hemmelig-inbox-v1"
//     derives a 256-bit AES key from the shared secret.
//   - AES-256-GCM encrypts the message with a random 96-bit IV.

const inboxInfo = "hemmelig-inbox-v1"

// InboxEnvelope is an encrypted inbox message. All values are standard base64.
type InboxEnvelope struct {
	// EphemeralPublicKey is the one-time public key of the sender in SPKI form.
	EphemeralPublicKey string `json:"ephemeralPublicKey"`
	HKDFSalt           string `json:"hkdfSalt"`
	IV                 string `json:"iv"`
	Ciphertext         string `json:"ciphertext"`
}

// ParseInboxPublicKey reads an inbox public key: a P-256 key in SPKI form,
// standard base64.
func ParseInboxPublicKey(value string) (*ecdh.PublicKey, error) {
	der, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("inbox public key: %w", err)
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("inbox public key: %w", err)
	}
	key, ok := parsed.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, errors.New("inbox public key: not a P-256 key")
	}
	return key.ECDH()
}

// inboxKey derives the AES key of one message from an ECDH shared secret.
func inboxKey(private *ecdh.PrivateKey, public *ecdh.PublicKey, salt []byte) (cipher.AEAD, error) {
	shared, err := private.ECDH(public)
	if err != nil {
		return nil, fmt.Errorf("ECDH: %w", err)
	}
	key, err := hkdf.Key(sha256.New, shared, salt, inboxInfo, 32)
	if err != nil {
		return nil, fmt.Errorf("HKDF: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// EncryptForInbox encrypts a message for the inbox with this public key.
func EncryptForInbox(recipient *ecdh.PublicKey, plain []byte) (*InboxEnvelope, error) {
	ephemeral, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	salt := make([]byte, 32)
	iv := make([]byte, ivLength)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	aead, err := inboxKey(ephemeral, recipient, salt)
	if err != nil {
		return nil, err
	}
	spki, err := x509.MarshalPKIXPublicKey(ephemeral.PublicKey())
	if err != nil {
		return nil, err
	}
	encode := base64.StdEncoding.EncodeToString
	return &InboxEnvelope{
		EphemeralPublicKey: encode(spki),
		HKDFSalt:           encode(salt),
		IV:                 encode(iv),
		Ciphertext:         encode(aead.Seal(nil, iv, plain, nil)),
	}, nil
}

// DecryptInboxMessage decrypts an envelope with the inbox private key. The
// CLI does not hold inbox keys. Tests use this function to check
// EncryptForInbox.
func DecryptInboxMessage(private *ecdh.PrivateKey, envelope *InboxEnvelope) ([]byte, error) {
	decode := base64.StdEncoding.DecodeString
	spki, err := decode(envelope.EphemeralPublicKey)
	if err != nil {
		return nil, err
	}
	parsed, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return nil, err
	}
	sender, ok := parsed.(*ecdh.PublicKey)
	if !ok {
		key, isECDSA := parsed.(*ecdsa.PublicKey)
		if !isECDSA {
			return nil, errors.New("sender key: not an EC key")
		}
		if sender, err = key.ECDH(); err != nil {
			return nil, err
		}
	}
	salt, err := decode(envelope.HKDFSalt)
	if err != nil {
		return nil, err
	}
	iv, err := decode(envelope.IV)
	if err != nil {
		return nil, err
	}
	sealed, err := decode(envelope.Ciphertext)
	if err != nil {
		return nil, err
	}
	aead, err := inboxKey(private, sender, salt)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, iv, sealed, nil)
	if err != nil {
		return nil, ErrDecrypt
	}
	return plain, nil
}
