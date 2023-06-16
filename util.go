package aesctr

import "crypto/rand"

// GenerateKey generates a random keySize byte key for using in encryption
func GenerateKey(keySize int) ([]byte, error) {
	k := make([]byte, keySize)

	_, err := rand.Read(k)
	if err != nil {
		return nil, err
	}

	return k, nil
}
