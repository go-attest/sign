package sign

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/blake2b"
)

// minisign signature algorithms: "Ed" signs the raw message, "ED" signs its
// Blake2b-512 prehash. We emit "Ed" (verifiable with crypto/ed25519 alone) and
// verify both.
const (
	algLegacy = "Ed"
	algHashed = "ED"

	cUntrusted = "untrusted comment: "
	cTrusted   = "trusted comment: "

	pubKeyLen = 2 + 8 + 32 // sig-alg + keyID + Ed25519 public key
)

// PublicKeyString encodes the public key as minisign's one-line base64 form,
// base64("Ed" || keyID || pubkey) — the "RW…"-prefixed string a verifier stores
// as the second line of a .pub file.
func (k *Keypair) PublicKeyString() string {
	b := make([]byte, 0, pubKeyLen)
	b = append(b, algLegacy...)
	b = append(b, k.ID[:]...)
	b = append(b, k.Public...)
	return base64.StdEncoding.EncodeToString(b)
}

// PublicKeyFile returns the two-line minisign public-key file (comment + key).
func (k *Keypair) PublicKeyFile(comment string) string {
	if comment == "" {
		comment = fmt.Sprintf("minisign public key %X", k.ID)
	}
	return cUntrusted + comment + "\n" + k.PublicKeyString() + "\n"
}

// SignMinisign returns a detached minisign signature file (the content of a
// .minisig) over data. It uses legacy Ed25519 (algorithm "Ed", signature over
// the raw message) so `minisign -V` and crypto/ed25519 both verify it without
// Blake2b. The trusted comment is authenticated by the trailing global
// signature; untrusted defaults if empty.
func (k *Keypair) SignMinisign(data []byte, untrusted, trusted string) string {
	sig := ed25519.Sign(k.Private, data)

	line := make([]byte, 0, 2+8+ed25519.SignatureSize)
	line = append(line, algLegacy...)
	line = append(line, k.ID[:]...)
	line = append(line, sig...)

	global := ed25519.Sign(k.Private, globalMsg(sig, trusted))

	if untrusted == "" {
		untrusted = "signed with go-pkgx/sign"
	}
	var b strings.Builder
	b.WriteString(cUntrusted + untrusted + "\n")
	b.WriteString(base64.StdEncoding.EncodeToString(line) + "\n")
	b.WriteString(cTrusted + trusted + "\n")
	b.WriteString(base64.StdEncoding.EncodeToString(global) + "\n")
	return b.String()
}

// globalMsg is the message the minisign global signature covers: the detached
// signature bytes followed by the trusted-comment text.
func globalMsg(sig []byte, trusted string) []byte {
	return append(append([]byte{}, sig...), []byte(trusted)...)
}

// ParsePublicKey decodes a minisign public key from either a one-line key string
// or a full .pub file (whose last non-empty line is the key).
func ParsePublicKey(s string) (KeyID, ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(lastLine(s))
	if err != nil {
		return KeyID{}, nil, fmt.Errorf("sign: bad public-key base64: %w", err)
	}
	if len(raw) != pubKeyLen || string(raw[:2]) != algLegacy {
		return KeyID{}, nil, errors.New("sign: malformed minisign public key")
	}
	var id KeyID
	copy(id[:], raw[2:10])
	return id, ed25519.PublicKey(append([]byte{}, raw[10:]...)), nil
}

// parsedSig holds the fields of a decoded .minisig file.
type parsedSig struct {
	alg     string
	keyID   KeyID
	sig     []byte
	trusted string
	global  []byte
}

// parseMinisig decodes a .minisig file into its fields.
func parseMinisig(s string) (parsedSig, error) {
	lines := nonEmptyLines(s)
	if len(lines) < 4 {
		return parsedSig{}, errors.New("sign: truncated minisig")
	}
	sigRaw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(lines[1]))
	if err != nil {
		return parsedSig{}, fmt.Errorf("sign: bad signature base64: %w", err)
	}
	if len(sigRaw) != 2+8+ed25519.SignatureSize {
		return parsedSig{}, errors.New("sign: malformed signature line")
	}
	global, err := base64.StdEncoding.DecodeString(strings.TrimSpace(lines[3]))
	if err != nil {
		return parsedSig{}, fmt.Errorf("sign: bad global-signature base64: %w", err)
	}
	if len(global) != ed25519.SignatureSize {
		return parsedSig{}, errors.New("sign: malformed global signature")
	}
	var id KeyID
	copy(id[:], sigRaw[2:10])
	return parsedSig{
		alg:     string(sigRaw[:2]),
		keyID:   id,
		sig:     sigRaw[10:],
		trusted: strings.TrimPrefix(lines[2], cTrusted),
		global:  global,
	}, nil
}

// VerifyMinisign checks a detached minisign signature over data against a
// minisign public key. Both legacy ("Ed") and prehashed ("ED", Blake2b-512)
// algorithms are accepted, so signatures made by the minisign CLI verify too.
func VerifyMinisign(data []byte, minisig, pubkey string) error {
	id, pub, err := ParsePublicKey(pubkey)
	if err != nil {
		return err
	}
	p, err := parseMinisig(minisig)
	if err != nil {
		return err
	}
	if p.keyID != id {
		return errors.New("sign: key-id mismatch")
	}
	var msg []byte
	switch p.alg {
	case algLegacy:
		msg = data
	case algHashed:
		h := blake2b.Sum512(data)
		msg = h[:]
	default:
		return errors.New("sign: unknown signature algorithm")
	}
	if !ed25519.Verify(pub, msg, p.sig) {
		return errors.New("sign: signature does not verify")
	}
	if !ed25519.Verify(pub, globalMsg(p.sig, p.trusted), p.global) {
		return errors.New("sign: trusted-comment signature does not verify")
	}
	return nil
}

// lastLine returns the last non-empty, non-comment line of s (the key line of a
// .pub file), or s trimmed if there is none.
func lastLine(s string) string {
	var out string
	for _, ln := range strings.Split(s, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "untrusted comment:") {
			continue
		}
		out = ln
	}
	if out == "" {
		return strings.TrimSpace(s)
	}
	return out
}

// nonEmptyLines splits s and drops blank lines, preserving comment lines (the
// .minisig layout is comment / sig / comment / global-sig).
func nonEmptyLines(s string) []string {
	var out []string
	for _, ln := range strings.Split(s, "\n") {
		if strings.TrimSpace(ln) != "" {
			out = append(out, ln)
		}
	}
	return out
}
