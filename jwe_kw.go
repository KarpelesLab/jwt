package jwt

import (
	"crypto/aes"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"
)

// dirKeyAlgo implements KeyAlgo for direct key agreement where the shared
// secret is used directly as the CEK.
type dirKeyAlgo struct{}

// String returns "dir".
func (d dirKeyAlgo) String() string {
	return "dir"
}

// GenerateCEK returns the provided key as the CEK with no encrypted key.
// The key must be a []byte of the correct size for the content encryption
// algorithm.
func (d dirKeyAlgo) GenerateCEK(rand io.Reader, keySize int, rcptKey any) ([]byte, []byte, error) {
	key, ok := rcptKey.([]byte)
	if !ok {
		return nil, nil, fmt.Errorf("%w: expected []byte key for direct encryption", ErrInvalidSignKey)
	}
	if len(key) != keySize {
		return nil, nil, fmt.Errorf("%w: expected %d byte key, got %d", ErrInvalidSignKey, keySize, len(key))
	}
	return key, nil, nil
}

// UnwrapKey returns the provided key directly. The encrypted key must be empty.
func (d dirKeyAlgo) UnwrapKey(encryptedKey []byte, keySize int, privKey any) ([]byte, error) {
	if len(encryptedKey) != 0 {
		return nil, fmt.Errorf("jwt: encrypted key must be empty for direct encryption")
	}
	key, ok := privKey.([]byte)
	if !ok {
		return nil, fmt.Errorf("%w: expected []byte key for direct encryption", ErrInvalidSignKey)
	}
	if len(key) != keySize {
		return nil, fmt.Errorf("%w: expected %d byte key, got %d", ErrInvalidSignKey, keySize, len(key))
	}
	return key, nil
}

func (d dirKeyAlgo) reg() KeyAlgo {
	RegisterKeyAlgo(d)
	return d
}

// aesKwAlgo implements KeyAlgo for AES Key Wrap (RFC 3394).
type aesKwAlgo struct {
	keySize int
}

// String returns the algorithm name (e.g. "A128KW").
func (a aesKwAlgo) String() string {
	return fmt.Sprintf("A%dKW", a.keySize*8)
}

// GenerateCEK generates a random CEK and wraps it with AES Key Wrap using the
// provided key encryption key.
func (a aesKwAlgo) GenerateCEK(rand io.Reader, keySize int, rcptKey any) ([]byte, []byte, error) {
	kek, ok := rcptKey.([]byte)
	if !ok {
		return nil, nil, fmt.Errorf("%w: expected []byte key for AES-KW", ErrInvalidSignKey)
	}
	if len(kek) != a.keySize {
		return nil, nil, fmt.Errorf("%w: expected %d byte key, got %d", ErrInvalidSignKey, a.keySize, len(kek))
	}

	cek := make([]byte, keySize)
	if _, err := io.ReadFull(rand, cek); err != nil {
		return nil, nil, err
	}

	encryptedKey, err := aesKeyWrap(kek, cek)
	if err != nil {
		return nil, nil, err
	}

	return cek, encryptedKey, nil
}

// UnwrapKey recovers the CEK using AES Key Unwrap.
func (a aesKwAlgo) UnwrapKey(encryptedKey []byte, keySize int, privKey any) ([]byte, error) {
	kek, ok := privKey.([]byte)
	if !ok {
		return nil, fmt.Errorf("%w: expected []byte key for AES-KW", ErrInvalidSignKey)
	}
	if len(kek) != a.keySize {
		return nil, fmt.Errorf("%w: expected %d byte key, got %d", ErrInvalidSignKey, a.keySize, len(kek))
	}

	return aesKeyUnwrap(kek, encryptedKey)
}

func (a aesKwAlgo) reg() KeyAlgo {
	RegisterKeyAlgo(a)
	return a
}

var aesKwDefaultIV = []byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}

// aesKeyWrap implements AES Key Wrap per RFC 3394.
func aesKeyWrap(kek, plaintext []byte) ([]byte, error) {
	if len(plaintext)%8 != 0 {
		return nil, fmt.Errorf("jwt: plaintext must be a multiple of 8 bytes for AES-KW")
	}

	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}

	n := len(plaintext) / 8

	a := make([]byte, 8)
	copy(a, aesKwDefaultIV)
	r := make([][]byte, n)
	for i := range r {
		r[i] = make([]byte, 8)
		copy(r[i], plaintext[i*8:(i+1)*8])
	}

	buf := make([]byte, 16)
	tBytes := make([]byte, 8)
	for j := 0; j <= 5; j++ {
		for i := 1; i <= n; i++ {
			copy(buf[:8], a)
			copy(buf[8:], r[i-1])
			block.Encrypt(buf, buf)
			binary.BigEndian.PutUint64(tBytes, uint64(n*j+i))
			for k := 0; k < 8; k++ {
				buf[k] ^= tBytes[k]
			}
			copy(a, buf[:8])
			copy(r[i-1], buf[8:])
		}
	}

	result := make([]byte, (n+1)*8)
	copy(result[:8], a)
	for i := 0; i < n; i++ {
		copy(result[(i+1)*8:], r[i])
	}

	return result, nil
}

// aesKeyUnwrap implements AES Key Unwrap per RFC 3394.
func aesKeyUnwrap(kek, ciphertext []byte) ([]byte, error) {
	if len(ciphertext)%8 != 0 || len(ciphertext) < 24 {
		return nil, fmt.Errorf("jwt: invalid ciphertext length for AES-KW")
	}

	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}

	n := (len(ciphertext) / 8) - 1

	a := make([]byte, 8)
	copy(a, ciphertext[:8])
	r := make([][]byte, n)
	for i := range r {
		r[i] = make([]byte, 8)
		copy(r[i], ciphertext[(i+1)*8:(i+2)*8])
	}

	buf := make([]byte, 16)
	tBytes := make([]byte, 8)
	for j := 5; j >= 0; j-- {
		for i := n; i >= 1; i-- {
			binary.BigEndian.PutUint64(tBytes, uint64(n*j+i))
			for k := 0; k < 8; k++ {
				a[k] ^= tBytes[k]
			}
			copy(buf[:8], a)
			copy(buf[8:], r[i-1])
			block.Decrypt(buf, buf)
			copy(a, buf[:8])
			copy(r[i-1], buf[8:])
		}
	}

	if subtle.ConstantTimeCompare(a, aesKwDefaultIV) != 1 {
		return nil, ErrDecryptionFailed
	}

	result := make([]byte, n*8)
	for i := 0; i < n; i++ {
		copy(result[i*8:], r[i])
	}

	return result, nil
}
