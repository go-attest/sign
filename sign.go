// Package sign signs pkgx bottles with Ed25519, interoperably with both
// minisign (detached .minisig files, for tarballs served over HTTP from
// dist.pkgx.dev) and cosign (PEM keys + blob signatures, for bottles published
// as OCI artifacts on ghcr.io). A single Ed25519 keypair backs both: minisign
// and cosign each verify a plain Ed25519 signature over the bottle bytes, so
// one signature value serves both transports.
//
// The package is pure standard library for signing and for verifying legacy
// ("Ed") signatures; verifying minisign's prehashed ("ED") form additionally
// pulls in golang.org/x/crypto/blake2b. CGO_ENABLED=0.
package sign

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
)

// KeyID is minisign's 8-byte key identifier, echoed in every signature so a
// verifier can tell which key a signature claims to originate from.
type KeyID [8]byte

// Keypair is an Ed25519 signing keypair plus its minisign-style KeyID.
type Keypair struct {
	ID      KeyID
	Public  ed25519.PublicKey
	Private ed25519.PrivateKey
}

// randRead is the entropy source, swappable in tests to exercise error paths.
var randRead = rand.Read

// Generate creates a fresh Ed25519 keypair with a random KeyID.
func Generate() (*Keypair, error) {
	var id KeyID
	if _, err := randRead(id[:]); err != nil {
		return nil, err
	}
	pub, priv, err := ed25519.GenerateKey(randReader{})
	if err != nil {
		return nil, err
	}
	return &Keypair{ID: id, Public: pub, Private: priv}, nil
}

// randReader adapts randRead to io.Reader so ed25519.GenerateKey shares the
// swappable entropy source.
type randReader struct{}

func (randReader) Read(p []byte) (int, error) { return randRead(p) }

// SecretKeyFile encodes the keypair's private key for storage by go-pkgx tools:
// a comment line plus base64(keyID || Ed25519 private key). This is not
// minisign's scrypt-encrypted format — it is meant for CI signing keys held in
// a secret store, so protection is the store's job, not a passphrase.
func (k *Keypair) SecretKeyFile(comment string) string {
	if comment == "" {
		comment = fmt.Sprintf("go-pkgx secret key %X", k.ID)
	}
	b := make([]byte, 0, 8+ed25519.PrivateKeySize)
	b = append(b, k.ID[:]...)
	b = append(b, k.Private...)
	return "untrusted comment: " + comment + "\n" + base64.StdEncoding.EncodeToString(b) + "\n"
}

// LoadSecretKey parses a SecretKeyFile back into a Keypair.
func LoadSecretKey(s string) (*Keypair, error) {
	raw, err := base64.StdEncoding.DecodeString(lastLine(s))
	if err != nil {
		return nil, fmt.Errorf("sign: bad secret-key base64: %w", err)
	}
	if len(raw) != 8+ed25519.PrivateKeySize {
		return nil, errors.New("sign: malformed secret key")
	}
	kp := &Keypair{Private: ed25519.PrivateKey(append([]byte{}, raw[8:]...))}
	copy(kp.ID[:], raw[:8])
	kp.Public = kp.Private.Public().(ed25519.PublicKey)
	return kp, nil
}
