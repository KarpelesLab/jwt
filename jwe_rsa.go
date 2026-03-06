package jwt

import (
	"crypto"
	"crypto/rsa"
	"fmt"
	"io"
)

// rsaOaepKeyAlgo implements KeyAlgo for RSA-OAEP and RSA-OAEP-256 key
// management algorithms.
type rsaOaepKeyAlgo struct {
	hash crypto.Hash
	name string
}

// String returns the algorithm name ("RSA-OAEP" or "RSA-OAEP-256").
func (r rsaOaepKeyAlgo) String() string {
	return r.name
}

// GenerateCEK generates a random CEK and encrypts it with RSA-OAEP using the
// recipient's public key.
func (r rsaOaepKeyAlgo) GenerateCEK(rnd io.Reader, keySize int, rcptKey any) ([]byte, []byte, error) {
	if !r.hash.Available() {
		return nil, nil, fmt.Errorf("%w: %s", ErrHashNotAvailable, r.hash.String())
	}

	// Unwrap key containers (e.g. *JWK)
	if obj, ok := rcptKey.(interface{ Public() crypto.PublicKey }); ok {
		rcptKey = obj.Public()
	}

	pub, ok := rcptKey.(*rsa.PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("%w: expected *rsa.PublicKey, got %T", ErrInvalidPublicKey, rcptKey)
	}

	// Generate random CEK
	cek := make([]byte, keySize)
	if _, err := io.ReadFull(rnd, cek); err != nil {
		return nil, nil, err
	}

	// Encrypt the CEK with RSA-OAEP
	encryptedKey, err := rsa.EncryptOAEP(r.hash.New(), rnd, pub, cek, nil)
	if err != nil {
		return nil, nil, err
	}

	return cek, encryptedKey, nil
}

// UnwrapKey decrypts the encrypted key using RSA-OAEP with the recipient's
// private key. Supports *rsa.PrivateKey and crypto.Decrypter.
func (r rsaOaepKeyAlgo) UnwrapKey(encryptedKey []byte, keySize int, privKey any) ([]byte, error) {
	if !r.hash.Available() {
		return nil, fmt.Errorf("%w: %s", ErrHashNotAvailable, r.hash.String())
	}

	switch k := privKey.(type) {
	case *rsa.PrivateKey:
		return rsa.DecryptOAEP(r.hash.New(), nil, k, encryptedKey, nil)
	case crypto.Decrypter:
		return k.Decrypt(nil, encryptedKey, &rsa.OAEPOptions{Hash: r.hash})
	default:
		return nil, fmt.Errorf("%w: expected *rsa.PrivateKey, got %T", ErrInvalidSignKey, privKey)
	}
}

func (r rsaOaepKeyAlgo) reg() KeyAlgo {
	RegisterKeyAlgo(r)
	return r
}
