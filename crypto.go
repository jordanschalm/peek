package peek

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
)

// Note:
// Encrypt/decrypt functions must use initialization vectors of exactly
// aes.BlockSize bytes and must use keys of either 16, 24, or 32 bytes.

// Encrypts a plaintext using a given key. If the plaintext doesn't fit evenly
// into blocks, pads the last block using pad. An initialization vector is
// randomly generated and prepended to the resulting ciphertext.
func encrypt(plaintext, key []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, errors.New("Cannot encrypt empty message")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	iv := make([]byte, aes.BlockSize)
	_, err = rand.Read(iv)
	if err != nil {
		return nil, err
	}

	padded := pad(plaintext, aes.BlockSize)
	mode := cipher.NewCBCEncrypter(block, iv)
	ciphertext := make([]byte, len(padded))
	mode.CryptBlocks(ciphertext, padded)

	return append(iv, ciphertext...), nil
}

// Decrypts a ciphertext using a given key and initialization vector.
// If the plaintext was originally padded, unpads it using unpad.
func decrypt(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	mode := cipher.NewCBCDecrypter(block, iv)
	// Decrypt in-place
	mode.CryptBlocks(ciphertext, ciphertext)
	unpadded := unpad(ciphertext, aes.BlockSize)
	if unpadded == nil {
		return nil, errors.New("Unpadding message failed")
	}
	return unpadded, nil
}

// Pads a byte array to be a multiple of the blocksize and adds a prefix
// block that describes what padding was added. Block size must be at least
// 2 bytes.
func pad(data []byte, bsize int) []byte {
	if len(data) == 0 {
		return nil
	}

	// Check if the data is already the correct length
	if len(data)%bsize == 0 {
		prefix := make([]byte, bsize)
		return append(prefix, data...)
	}

	// Compute the number of additional bytes required to pad out the data
	padLen := bsize - (len(data) % bsize)
	padded := make([]byte, bsize+len(data)+padLen)
	// Insert the number of padded bytes as the first block
	binary.LittleEndian.PutUint16(padded, uint16(padLen))
	// Copy the data into blocks 2-N. Padding happens here for free since
	// padded will have been zeroed
	copy(padded[bsize:], data)

	return padded
}

// Reverses padding performed by pad. Returns nil rather than panicking.
func unpad(data []byte, bsize int) []byte {
	// Retrieve the number of padded bytes from the first block
	padLen := int(binary.LittleEndian.Uint16(data))
	if padLen >= bsize || len(data) < 2*bsize {
		return nil
	}
	// Chop off the first block and the padding
	return data[bsize : len(data)-padLen]
}
