package jwt

import (
	"crypto/mlkem"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// mlkemAlgo implements KeyAlgo for ML-KEM (Module-Lattice Key Encapsulation
// Mechanism) as specified in FIPS 203. ML-KEM is a post-quantum key
// encapsulation mechanism used to establish shared secrets for content
// encryption. The shared secret is derived into a CEK using HKDF-SHA256.
type mlkemAlgo struct {
	name  string
	level int // 768 or 1024
}

var (
	MLKEM768  KeyAlgo = mlkemAlgo{name: "ML-KEM-768", level: 768}.reg()
	MLKEM1024 KeyAlgo = mlkemAlgo{name: "ML-KEM-1024", level: 1024}.reg()
)

// String returns the algorithm name (e.g. "ML-KEM-768").
func (a mlkemAlgo) String() string {
	return a.name
}

// GenerateCEK encapsulates a shared secret using the recipient's ML-KEM
// encapsulation key and derives a CEK from it via HKDF-SHA256. The returned
// encrypted key is the KEM ciphertext.
func (a mlkemAlgo) GenerateCEK(rand io.Reader, keySize int, rcptKey any) ([]byte, []byte, error) {
	var sharedKey, ciphertext []byte

	switch a.level {
	case 768:
		ek, err := toEncapsulationKey768(rcptKey)
		if err != nil {
			return nil, nil, err
		}
		sharedKey, ciphertext = ek.Encapsulate()
	case 1024:
		ek, err := toEncapsulationKey1024(rcptKey)
		if err != nil {
			return nil, nil, err
		}
		sharedKey, ciphertext = ek.Encapsulate()
	}

	cek, err := hkdfDerive(sharedKey, keySize, []byte(a.name))
	if err != nil {
		return nil, nil, err
	}

	return cek, ciphertext, nil
}

// UnwrapKey decapsulates the KEM ciphertext using the recipient's ML-KEM
// decapsulation key and derives the CEK via HKDF-SHA256.
func (a mlkemAlgo) UnwrapKey(encryptedKey []byte, keySize int, privKey any) ([]byte, error) {
	var sharedKey []byte
	var err error

	switch a.level {
	case 768:
		dk, ok := privKey.(*mlkem.DecapsulationKey768)
		if !ok {
			return nil, fmt.Errorf("%w: expected *mlkem.DecapsulationKey768, got %T", ErrInvalidSignKey, privKey)
		}
		sharedKey, err = dk.Decapsulate(encryptedKey)
	case 1024:
		dk, ok := privKey.(*mlkem.DecapsulationKey1024)
		if !ok {
			return nil, fmt.Errorf("%w: expected *mlkem.DecapsulationKey1024, got %T", ErrInvalidSignKey, privKey)
		}
		sharedKey, err = dk.Decapsulate(encryptedKey)
	}

	if err != nil {
		return nil, err
	}

	return hkdfDerive(sharedKey, keySize, []byte(a.name))
}

func (a mlkemAlgo) reg() KeyAlgo {
	RegisterKeyAlgo(a)
	return a
}

func toEncapsulationKey768(key any) (*mlkem.EncapsulationKey768, error) {
	switch k := key.(type) {
	case *mlkem.EncapsulationKey768:
		return k, nil
	case *mlkem.DecapsulationKey768:
		return k.EncapsulationKey(), nil
	default:
		return nil, fmt.Errorf("%w: expected *mlkem.EncapsulationKey768, got %T", ErrInvalidPublicKey, key)
	}
}

func toEncapsulationKey1024(key any) (*mlkem.EncapsulationKey1024, error) {
	switch k := key.(type) {
	case *mlkem.EncapsulationKey1024:
		return k, nil
	case *mlkem.DecapsulationKey1024:
		return k.EncapsulationKey(), nil
	default:
		return nil, fmt.Errorf("%w: expected *mlkem.EncapsulationKey1024, got %T", ErrInvalidPublicKey, key)
	}
}

// hkdfDerive derives a key of the given size from the input keying material
// using HKDF-SHA256 with the given info string.
func hkdfDerive(ikm []byte, keySize int, info []byte) ([]byte, error) {
	r := hkdf.New(sha256.New, ikm, nil, info)
	key := make([]byte, keySize)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, err
	}
	return key, nil
}
