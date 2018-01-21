package peek

import (
	"bytes"
	"fmt"
	"math/rand"
	"testing"
)

func TestHandshake(t *testing.T) {
	secret := make([]byte, secretLen)
	rand.Read(secret)

	// Start a server
	go func() {
		l, err := Listen(":6789", secret)
		if err != nil {
			t.Error(err)
		}

		c, err := l.Accept()
		if err != nil {
			t.Error(err)
		}

		c.Close()
	}()

	c, err := Dial(":6789", secret)
	if err != nil {
		t.Error(err)
	}

	c.Close()
}

func TestHandshakeBadSecret(t *testing.T) {
	secret := make([]byte, secretLen)
	rand.Read(secret)

	badSecret := make([]byte, secretLen)
	rand.Read(badSecret)

	fmt.Printf("%x\n%x\n", secret, badSecret)

	go func() {
		l, err := Listen(":6789", secret)
		if err != nil {
			t.Error(err)
		}

		// Handshake should fail
		_, err = l.Accept()
		if err == nil {
			t.Fail()
		}
	}()

	_, err := Dial(":6789", badSecret)
	// Handshake should fail
	if err == nil {
		t.Fail()
	}
}

func TestReadWrite(t *testing.T) {
	secret := make([]byte, secretLen)
	rand.Read(secret)

	message := []byte("hello")

	// Start a server
	go func() {
		l, err := Listen(":6789", secret)
		if err != nil {
			t.Error(err)
		}

		c, err := l.Accept()
		if err != nil {
			t.Error(err)
		}

		buf := make([]byte, len(message))
		_, err = c.Read(buf)
		if err != nil {
			t.Error(err)
		}

		if !bytes.Equal(buf, message) {
			t.Fail()
		}

		_, err = c.Write(message)
		if err != nil {
			t.Error(err)
		}

		c.Close()
	}()

	c, err := Dial(":6789", secret)
	if err != nil {
		t.Error(err)
	}

	_, err = c.Write(message)
	if err != nil {
		t.Error(err)
	}

	buf := make([]byte, len(message))
	_, err = c.Read(buf)
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(buf, message) {
		t.Fail()
	}

	c.Close()
}
