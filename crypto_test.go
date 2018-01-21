package peek

import (
	"bytes"
	"math/rand"
	"testing"
)

func TestPadMatchBlockSize(t *testing.T) {
	plaintext := []byte{0xef, 0xad, 0x4e, 0x23}
	padded := pad(plaintext, 4)
	unpadded := unpad(padded, 4)
	if bytes.Compare(plaintext, unpadded) != 0 {
		t.Fail()
	}
}

func TestPadOffBlockSize(t *testing.T) {
	plaintext := []byte{0xef, 0xad, 0x4e}
	padded := pad(plaintext, 4)
	unpadded := unpad(padded, 4)
	if bytes.Compare(plaintext, unpadded) != 0 {
		t.Fail()
	}
}

func TestPadZero(t *testing.T) {
	// Should panic with a zero-length input
	defer func() {
		recover()
	}()
	pad([]byte{}, 4)
	t.Fail()
}

func TestEncrypt(t *testing.T) {
	plaintext := []byte("Hello")
	key := make([]byte, 16)
	rand.Read(key)

	ciphertext, err := encrypt(plaintext, key)
	if err != nil {
		t.Error(err)
	}

	decrypted, err := decrypt(ciphertext, key)
	if err != nil {
		t.Error(err)
	}

	if bytes.Compare(plaintext, decrypted) != 0 {
		t.Fail()
	}
}

func TestEncryptLarge(t *testing.T) {
	plaintext := make([]byte, 1000000) // 1MB
	rand.Read(plaintext)
	key := make([]byte, 16)
	rand.Read(key)

	ciphertext, err := encrypt(plaintext, key)
	if err != nil {
		t.Error(err)
	}

	decrypted, err := decrypt(ciphertext, key)
	if err != nil {
		t.Error(err)
	}

	if bytes.Compare(plaintext, decrypted) != 0 {
		t.Fail()
	}
}
