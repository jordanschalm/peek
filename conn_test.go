package peek

import (
	"bytes"
	"math/rand"
	"testing"
)

// For consistent tests
const seed = 42

func init() {
	rand.Seed(seed)
}

// Starts a server, spins up the passed function as a goroutine and returns
// the address the server is listening on.
func startServer(secret []byte, f func(l *Listener)) (string, error) {
	l, err := Listen("127.0.0.1:0", secret)
	if err != nil {
		return "", err
	}

	go f(l)

	return l.Addr().String(), nil
}

func TestHandshake(t *testing.T) {
	secret := make([]byte, secretLen)
	rand.Read(secret)

	// Start a server
	addr, err := startServer(secret, func(l *Listener) {
		c, err := l.Accept()
		if err != nil {
			t.Error(err)
			t.Fail()
		}

		c.Close()
	})
	if err != nil {
		t.Error(err)
		t.Fail()
	}

	c, err := Dial(addr, secret)
	if err != nil {
		t.Error(err)
		t.Fail()
	}

	c.Close()
}

func TestHandshakeBadSecret(t *testing.T) {
	secret := make([]byte, secretLen)
	rand.Read(secret)

	badSecret := make([]byte, secretLen)
	rand.Read(badSecret)

	addr, err := startServer(secret, func(l *Listener) {
		// Handshake should fail
		_, err := l.Accept()
		if err == nil {
			t.Fail()
		}

		l.Close()
	})

	_, err = Dial(addr, badSecret)
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
	addr, err := startServer(secret, func(l *Listener) {
		c, err := l.Accept()
		if err != nil {
			t.Error(err)
			t.Fail()
		}

		buf := make([]byte, len(message))
		_, err = c.Read(buf)
		if err != nil {
			t.Error(err)
			t.Fail()
		}

		if !bytes.Equal(buf, message) {
			t.Fail()
		}

		_, err = c.Write(message)
		if err != nil {
			t.Error(err)
			t.Fail()
		}

		c.Close()
	})

	c, err := Dial(addr, secret)
	if err != nil {
		t.Error(err)
		t.Fail()
	}

	_, err = c.Write(message)
	if err != nil {
		t.Error(err)
		t.Fail()
	}

	buf := make([]byte, len(message))
	_, err = c.Read(buf)
	if err != nil {
		t.Error(err)
		t.Fail()
	}

	if !bytes.Equal(buf, message) {
		t.Fail()
	}

	c.Close()
}

func TestReadPartial(t *testing.T) {
	secret := make([]byte, secretLen)
	rand.Read(secret)

	message := []byte("12345678")
	done := make(chan bool)

	// Start a server
	addr, err := startServer(secret, func(l *Listener) {
		c, err := l.Accept()
		if err != nil {
			t.Error(err)
			t.Fail()
		}

		// Read in half the message
		buf := make([]byte, len(message))
		_, err = c.Read(buf[:len(message)/2])
		if err != nil {
			t.Error(err)
			t.Fail()
		}

		// Read in the other half
		_, err = c.Read(buf[len(message)/2:])
		if err != nil {
			t.Error(err)
			t.Fail()
		}

		if !bytes.Equal(buf, message) {
			t.Fail()
		}

		c.Close()
		done <- true
	})

	c, err := Dial(addr, secret)
	if err != nil {
		t.Error(err)
		t.Fail()
	}

	_, err = c.Write(message)
	if err != nil {
		t.Error(err)
		t.Fail()
	}

	<-done
	c.Close()
}
