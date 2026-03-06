package jwt

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io"
)

// aesGcmEncAlgo implements EncAlgo for AES-GCM content encryption
// (A128GCM, A192GCM, A256GCM).
type aesGcmEncAlgo struct {
	keySize int
}

// String returns the algorithm name (e.g. "A256GCM").
func (a aesGcmEncAlgo) String() string {
	return fmt.Sprintf("A%dGCM", a.keySize*8)
}

// KeySize returns the required key size in bytes.
func (a aesGcmEncAlgo) KeySize() int {
	return a.keySize
}

// Encrypt performs AES-GCM authenticated encryption.
func (a aesGcmEncAlgo) Encrypt(rand io.Reader, key, plaintext, aad []byte) ([]byte, []byte, []byte, error) {
	if len(key) != a.keySize {
		return nil, nil, nil, fmt.Errorf("jwt: key size mismatch: expected %d, got %d", a.keySize, len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, nil, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, nil, err
	}

	iv := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand, iv); err != nil {
		return nil, nil, nil, err
	}

	sealed := aead.Seal(nil, iv, plaintext, aad)

	tagSize := aead.Overhead()
	ciphertext := sealed[:len(sealed)-tagSize]
	tag := sealed[len(sealed)-tagSize:]

	return iv, ciphertext, tag, nil
}

// Decrypt performs AES-GCM authenticated decryption.
func (a aesGcmEncAlgo) Decrypt(key, iv, ciphertext, tag, aad []byte) ([]byte, error) {
	if len(key) != a.keySize {
		return nil, fmt.Errorf("jwt: key size mismatch: expected %d, got %d", a.keySize, len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	sealed := make([]byte, len(ciphertext)+len(tag))
	copy(sealed, ciphertext)
	copy(sealed[len(ciphertext):], tag)

	return aead.Open(nil, iv, sealed, aad)
}

func (a aesGcmEncAlgo) reg() EncAlgo {
	RegisterEncAlgo(a)
	return a
}
