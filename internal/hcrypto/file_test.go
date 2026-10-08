package hcrypto

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"testing"
)

func testCipher(t *testing.T) *Cipher {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	c, err := NewCipherFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestFileV2RoundTrip(t *testing.T) {
	c := testCipher(t)
	for _, size := range []int{0, 1, 15, 16, 17, 32, 33, 100} {
		plain := make([]byte, size)
		_, _ = rand.Read(plain)
		sealed, err := c.encryptFileChunks(plain, 16)
		if err != nil {
			t.Fatal(err)
		}
		if !IsV2(sealed) {
			t.Fatalf("size %d: no v2 header", size)
		}
		opened, err := c.DecryptFile(sealed)
		if err != nil {
			t.Fatalf("size %d: %v", size, err)
		}
		if !bytes.Equal(opened, plain) {
			t.Fatalf("size %d: the plaintext changed", size)
		}
	}
}

func TestFileV2DefaultChunkSize(t *testing.T) {
	c := testCipher(t)
	sealed, err := c.EncryptFile([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint32(sealed[8:12]); got != DefaultChunkSize {
		t.Fatalf("chunk size %d, want %d", got, DefaultChunkSize)
	}
}

func TestFileV2RejectsDamage(t *testing.T) {
	c := testCipher(t)
	sealed, err := c.encryptFileChunks([]byte("0123456789abcdefXYZ"), 16)
	if err != nil {
		t.Fatal(err)
	}

	// A file without the end marker was cut off.
	if _, err := c.DecryptFile(sealed[:len(sealed)-16]); !errors.Is(err, ErrFileFormat) {
		t.Fatalf("cut-off file: got %v", err)
	}
	// A changed byte fails the tag check.
	damaged := append([]byte(nil), sealed...)
	damaged[v2HeaderLength+ivLength+chunkLenBytes] ^= 0xff
	if _, err := c.DecryptFile(damaged); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("damaged file: got %v", err)
	}
	// Data after the end marker is refused.
	if _, err := c.DecryptFile(append(append([]byte(nil), sealed...), 0)); !errors.Is(err, ErrFileFormat) {
		t.Fatalf("trailing data: got %v", err)
	}
	// Another key fails.
	if _, err := testCipher(t).DecryptFile(sealed); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("other key: got %v", err)
	}
}

func TestDecryptFileReadsV1(t *testing.T) {
	c := testCipher(t)
	sealed, err := c.Encrypt([]byte("legacy file"))
	if err != nil {
		t.Fatal(err)
	}
	opened, err := c.DecryptFile(sealed)
	if err != nil || string(opened) != "legacy file" {
		t.Fatalf("got %q, %v", opened, err)
	}
}
