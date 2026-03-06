package jwt

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"
)

// aesCbcHsEncAlgo implements EncAlgo for AES-CBC with HMAC-SHA2 content
// encryption (A128CBC-HS256, A192CBC-HS384, A256CBC-HS512) as defined in
// RFC 7518 Section 5.2.
type aesCbcHsEncAlgo struct {
	keySize int         // total key size (MAC_KEY + ENC_KEY)
	hash    crypto.Hash // HMAC hash function
}

// String returns the algorithm name (e.g. "A128CBC-HS256").
func (a aesCbcHsEncAlgo) String() string {
	return fmt.Sprintf("A%dCBC-HS%d", (a.keySize/2)*8, a.hash.Size()*8)
}

// KeySize returns the total required key size in bytes (MAC key + encryption key).
func (a aesCbcHsEncAlgo) KeySize() int {
	return a.keySize
}

// Encrypt performs AES-CBC encryption with HMAC authentication.
func (a aesCbcHsEncAlgo) Encrypt(rand io.Reader, key, plaintext, aad []byte) ([]byte, []byte, []byte, error) {
	if len(key) != a.keySize {
		return nil, nil, nil, fmt.Errorf("jwt: key size mismatch: expected %d, got %d", a.keySize, len(key))
	}
	if !a.hash.Available() {
		return nil, nil, nil, fmt.Errorf("%w: %s", ErrHashNotAvailable, a.hash.String())
	}

	macKey := key[:a.keySize/2]
	encKey := key[a.keySize/2:]

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, nil, nil, err
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand, iv); err != nil {
		return nil, nil, nil, err
	}

	padded := pkcs7Pad(plaintext, aes.BlockSize)
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)

	tag := a.computeTag(macKey, aad, iv, ct)

	return iv, ct, tag, nil
}

// Decrypt verifies the HMAC tag and performs AES-CBC decryption.
func (a aesCbcHsEncAlgo) Decrypt(key, iv, ciphertext, tag, aad []byte) ([]byte, error) {
	if len(key) != a.keySize {
		return nil, fmt.Errorf("jwt: key size mismatch: expected %d, got %d", a.keySize, len(key))
	}
	if !a.hash.Available() {
		return nil, fmt.Errorf("%w: %s", ErrHashNotAvailable, a.hash.String())
	}

	macKey := key[:a.keySize/2]
	encKey := key[a.keySize/2:]

	// Verify tag before decrypting (prevents padding oracle attacks)
	expectedTag := a.computeTag(macKey, aad, iv, ciphertext)
	if subtle.ConstantTimeCompare(tag, expectedTag) != 1 {
		return nil, ErrDecryptionFailed
	}

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("jwt: ciphertext is not a multiple of block size")
	}

	plaintext := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, ciphertext)

	return pkcs7Unpad(plaintext, aes.BlockSize)
}

// computeTag computes the HMAC tag per RFC 7518 Section 5.2.2.1:
// MAC(MAC_KEY, AAD || IV || E || AL) truncated to half the hash output.
func (a aesCbcHsEncAlgo) computeTag(macKey, aad, iv, ciphertext []byte) []byte {
	al := make([]byte, 8)
	binary.BigEndian.PutUint64(al, uint64(len(aad)*8))

	mac := hmac.New(a.hash.New, macKey)
	mac.Write(aad)
	mac.Write(iv)
	mac.Write(ciphertext)
	mac.Write(al)

	full := mac.Sum(nil)
	return full[:len(full)/2]
}

func (a aesCbcHsEncAlgo) reg() EncAlgo {
	RegisterEncAlgo(a)
	return a
}

// pkcs7Pad adds PKCS#7 padding to data.
func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padded := make([]byte, len(data)+padding)
	copy(padded, data)
	for i := len(data); i < len(padded); i++ {
		padded[i] = byte(padding)
	}
	return padded
}

// pkcs7Unpad removes and validates PKCS#7 padding.
func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, fmt.Errorf("jwt: invalid padded data")
	}
	padding := int(data[len(data)-1])
	if padding == 0 || padding > blockSize {
		return nil, fmt.Errorf("jwt: invalid PKCS#7 padding")
	}
	for i := len(data) - padding; i < len(data); i++ {
		if data[i] != byte(padding) {
			return nil, fmt.Errorf("jwt: invalid PKCS#7 padding")
		}
	}
	return data[:len(data)-padding], nil
}
