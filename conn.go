package peek

import (
	"crypto/aes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net"
	"time"
)

const (
	nonceLen  = 32
	secretLen = 32
	keyLen    = 32
)

// Conn is a Peek connection. A session key is negotiated when a new connection
// is established and subsequent communication is encrypted.
type Conn struct {
	key []byte
	net.Conn
}

// Dial sets up and returns a new secured connection over TCP by negotiating
// a shared session key with the server.
func Dial(addr string, secret []byte) (*Conn, error) {
	// Set up a connection
	c, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}

	// Generate a nonce to challenge the server
	nonce := make([]byte, nonceLen)
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, err
	}

	enc, err := encrypt(nonce, secret)
	if err != nil {
		return nil, err
	}

	c.SetWriteDeadline(time.Now().Add(time.Second))
	_, err = c.Write(enc)
	if err != nil {
		return nil, err
	}

	c.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 256)
	n, err := c.Read(buf)
	if err != nil {
		return nil, err
	}

	// Chop off extra bytes
	buf = buf[:n]
	plain, err := decrypt(buf, secret)
	if err != nil {
		return nil, err
	}

	// Plaintext must be exactly 2 nonces in length
	if len(plain) != 2*nonceLen {
		return nil, errors.New("Remote reply too short")
	}

	// Check that the remote was able to decrypt the nonce
	if subtle.ConstantTimeCompare(plain[:nonceLen], nonce) != 1 {
		return nil, errors.New("Remote failed nonce challenge")
	}

	// Compute the session key
	key := make([]byte, keyLen)
	for i, b := range sha256.Sum256(plain) {
		key[i] = b
	}

	conn := Conn{
		key:  key,
		Conn: c,
	}

	return &conn, nil
}

// Read reads from a secured connection. Once a secure session has been
// established, decrypts messages from the underlying connection and returns
// the recovered plaintext.
func (c *Conn) Read(b []byte) (int, error) {
	buf := make([]byte, len(b)+3*aes.BlockSize)
	n, err := c.Conn.Read(buf)
	// If error occurs in underlying connection, pretend we haven't read
	// anything, because we can't decrypt partial messages. The message must be
	// resent to recover from this class of error.
	if err != nil {
		return 0, err
	}
	buf = buf[:n]

	dec, err := decrypt(buf, c.key)
	if err != nil {
		return 0, err
	}
	copy(b, dec)

	return len(dec), nil
}

// Write writes to a secured connections. Once a secure session has been
// established, encrypts messages and writes them to underlying connection.
func (c *Conn) Write(b []byte) (int, error) {
	enc, err := encrypt(b, c.key)
	if err != nil {
		return 0, err
	}

	return c.Conn.Write(enc)
}

// Listener is a Peek listener. It negotiates a session secret with connected
// clients and encrypts communications.
type Listener struct {
	secret []byte
	net.Listener
}

// Listen starts listening for new incoming connections on the given interface.
// When new connections are received, it negotiates a shared session key with
// the client.
func Listen(addr string, secret []byte) (*Listener, error) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	return &Listener{
		secret:   secret,
		Listener: l,
	}, nil
}

// Accept accepts the next connection, negotiates a session key, and returns
// the resulting connection.
func (l *Listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	// Pull the nonce from the initial message
	c.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 256)
	n, err := c.Read(buf)
	if err != nil {
		return nil, err
	}

	// Chop off extra bytes and decrypt
	buf = buf[:n]
	plain, err := decrypt(buf, l.secret)
	if err != nil {
		return nil, err
	}

	// Plaintext must be exactly 1 nonce in length
	if len(plain) != nonceLen {
		return nil, errors.New("Remote hello too short")
	}

	// The response plaintext is remoteNonce || localNonce
	res := make([]byte, 2*nonceLen)
	copy(res[:nonceLen], plain)
	_, err = rand.Read(res[nonceLen:])
	if err != nil {
		return nil, err
	}
	enc, err := encrypt(res, l.secret)
	if err != nil {
		return nil, err
	}

	c.SetWriteDeadline(time.Now().Add(time.Second))
	_, err = c.Write(enc)
	if err != nil {
		return nil, err
	}

	// The handshake has completed. Compute the session key from the two nonces
	// and return the secured connection.
	key := make([]byte, keyLen)
	for i, b := range sha256.Sum256(res) {
		key[i] = b
	}

	conn := Conn{
		key:  key,
		Conn: c,
	}

	return &conn, nil
}
