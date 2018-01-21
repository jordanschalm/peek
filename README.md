# Peek

Peek is a simple transport security layer that requires both endpoints to have a shared secret.

:warning: Do not use this to secure anything important. Use a standard protocol :warning:

## Design Goals

### Secure endpoint authentication

An attacker listening to, intercepting, and injecting messages during the authentication handshake should be unable to determine the shared secret or decrypt messages.

### Secure transmission

An attacker listening to messages sent once a secure connection has been established should be unable to decrypt messages.

### Resistance to replay attacks

An attacker should be unable to resend intercepted messages and have them be accepted by either endpoint of the secure connection.
