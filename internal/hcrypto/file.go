package hcrypto

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
)

// File formats of attachments. The server stores the format next to the file.
const (
	// FileFormatV1 is one AES-GCM message: the IV, the ciphertext and the tag.
	FileFormatV1 = "v1"
	// FileFormatV2 is the chunked format of the web app. Each chunk has its
	// own IV and tag, and its index and a final flag in the additional data.
	FileFormatV2 = "v2"
)

const (
	// DefaultChunkSize is the plaintext size of one v2 chunk, as in the web app.
	DefaultChunkSize = 4 * 1024 * 1024
	maxChunkSize     = 64 * 1024 * 1024
	chunkLenBytes    = 4
	gcmTagBytes      = 16
)

// v2Magic starts every v2 file: "HMG2", the format version 2 and 3 zero bytes.
var v2Magic = []byte{0x48, 0x4d, 0x47, 0x32, 0x02, 0x00, 0x00, 0x00}

var v2HeaderLength = len(v2Magic) + 4

// ErrFileFormat means that an attachment is not in a known format.
var ErrFileFormat = errors.New("the file is not in a known Hemmelig format")

// IsV2 reports whether data starts with the v2 header.
func IsV2(data []byte) bool {
	return len(data) >= v2HeaderLength && bytes.Equal(data[:len(v2Magic)], v2Magic)
}

// chunkAAD is the additional data of chunk index: the index as a big-endian
// uint64 and 0x01 for the final chunk.
func chunkAAD(index uint64, final bool) []byte {
	aad := make([]byte, 9)
	binary.BigEndian.PutUint64(aad, index)
	if final {
		aad[8] = 0x01
	}
	return aad
}

// EncryptFile encrypts a file in the v2 chunked format of the web app.
func (c *Cipher) EncryptFile(plain []byte) ([]byte, error) {
	return c.encryptFileChunks(plain, DefaultChunkSize)
}

func (c *Cipher) encryptFileChunks(plain []byte, chunkSize int) ([]byte, error) {
	if chunkSize <= 0 || chunkSize > maxChunkSize {
		return nil, fmt.Errorf("invalid chunk size %d", chunkSize)
	}
	chunks := len(plain) / chunkSize
	out := bytes.NewBuffer(make([]byte, 0, v2HeaderLength+len(plain)+(chunks+2)*(ivLength+chunkLenBytes+gcmTagBytes)))
	out.Write(v2Magic)
	_ = binary.Write(out, binary.LittleEndian, uint32(chunkSize))

	writeFrame := func(index uint64, data []byte, final bool) error {
		iv := make([]byte, ivLength)
		if _, err := rand.Read(iv); err != nil {
			return fmt.Errorf("read random IV: %w", err)
		}
		sealed := c.aead.Seal(nil, iv, data, chunkAAD(index, final))
		out.Write(iv)
		_ = binary.Write(out, binary.LittleEndian, uint32(len(sealed)))
		out.Write(sealed)
		return nil
	}

	// Full chunks are not final. The web app always writes a final chunk,
	// also an empty one, so that a reader detects a cut-off file.
	index := uint64(0)
	offset := 0
	for len(plain)-offset > chunkSize {
		if err := writeFrame(index, plain[offset:offset+chunkSize], false); err != nil {
			return nil, err
		}
		offset += chunkSize
		index++
	}
	if len(plain)-offset == chunkSize && len(plain) > 0 {
		if err := writeFrame(index, plain[offset:], false); err != nil {
			return nil, err
		}
		offset = len(plain)
		index++
	}
	if err := writeFrame(index, plain[offset:], true); err != nil {
		return nil, err
	}
	// The end sentinel: a zero IV and a zero length.
	out.Write(make([]byte, ivLength+chunkLenBytes))
	return out.Bytes(), nil
}

// DecryptFile decrypts an attachment in the v1 or the v2 format.
func (c *Cipher) DecryptFile(data []byte) ([]byte, error) {
	if IsV2(data) {
		return c.decryptV2(data)
	}
	return c.Decrypt(data)
}

func (c *Cipher) decryptV2(data []byte) ([]byte, error) {
	chunkSize := int(binary.LittleEndian.Uint32(data[len(v2Magic):v2HeaderLength]))
	if chunkSize <= 0 || chunkSize > maxChunkSize {
		return nil, fmt.Errorf("%w: invalid chunk size", ErrFileFormat)
	}

	var plain bytes.Buffer
	rest := data[v2HeaderLength:]
	index := uint64(0)
	sawFinal := false
	for {
		if len(rest) < ivLength+chunkLenBytes {
			return nil, fmt.Errorf("%w: the file ends before the end marker", ErrFileFormat)
		}
		iv := rest[:ivLength]
		ctLen := int(binary.LittleEndian.Uint32(rest[ivLength : ivLength+chunkLenBytes]))
		rest = rest[ivLength+chunkLenBytes:]
		if ctLen == 0 {
			if !sawFinal {
				return nil, fmt.Errorf("%w: the file has no final chunk", ErrFileFormat)
			}
			if len(rest) > 0 {
				return nil, fmt.Errorf("%w: data after the end marker", ErrFileFormat)
			}
			return plain.Bytes(), nil
		}
		if sawFinal {
			return nil, fmt.Errorf("%w: a chunk after the final chunk", ErrFileFormat)
		}
		if ctLen < gcmTagBytes || ctLen > chunkSize+gcmTagBytes || ctLen > len(rest) {
			return nil, fmt.Errorf("%w: invalid chunk length", ErrFileFormat)
		}
		sealed := rest[:ctLen]
		rest = rest[ctLen:]

		// The reader does not know which chunk is the final one, so it tries
		// the non-final additional data first, like the web app.
		opened, err := c.aead.Open(nil, iv, sealed, chunkAAD(index, false))
		if err != nil {
			opened, err = c.aead.Open(nil, iv, sealed, chunkAAD(index, true))
			if err != nil {
				return nil, ErrDecrypt
			}
			sawFinal = true
		}
		plain.Write(opened)
		index++
	}
}
