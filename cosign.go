package sign

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
)

// marshalPKIX is x509.MarshalPKIXPublicKey, indirected so tests can exercise
// the (otherwise unreachable for a valid Ed25519 key) marshal-error branch.
var marshalPKIX = x509.MarshalPKIXPublicKey

// PublicKeyPEM encodes the Ed25519 public key as a PKIX PEM block — the form
// `cosign verify-blob --key <file>` and `cosign verify --key <file>` expect.
func (k *Keypair) PublicKeyPEM() ([]byte, error) {
	der, err := marshalPKIX(k.Public)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// ParsePublicKeyPEM decodes a PKIX PEM Ed25519 public key (a cosign.pub).
func ParsePublicKeyPEM(p []byte) (ed25519.PublicKey, error) {
	blk, _ := pem.Decode(p)
	if blk == nil {
		return nil, errors.New("sign: no PEM block in public key")
	}
	key, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("sign: public key is %T, want ed25519", key)
	}
	return pub, nil
}

// SignBlob returns the base64 Ed25519 signature over data, matching what
// `cosign sign-blob --key … <file>` emits and what `cosign verify-blob
// --signature …` checks. It is the same signature value SignMinisign embeds, in
// cosign's encoding.
func (k *Keypair) SignBlob(data []byte) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(k.Private, data))
}

// VerifyBlob checks a base64 Ed25519 blob signature (cosign form) over data.
func VerifyBlob(data []byte, b64sig string, pub ed25519.PublicKey) error {
	sig, err := base64.StdEncoding.DecodeString(b64sig)
	if err != nil {
		return fmt.Errorf("sign: bad signature base64: %w", err)
	}
	if !ed25519.Verify(pub, data, sig) {
		return errors.New("sign: signature does not verify")
	}
	return nil
}

// SimpleSigningPayload builds cosign's "simple signing" JSON payload binding a
// signature to an OCI image by its manifest digest (e.g.
// "sha256:abc…") and reference. This payload — not the raw bytes — is what a
// cosign image signature covers; bottle stores it as the signature artifact's
// layer and SignPayload's output in the cosign signature annotation.
func SimpleSigningPayload(dockerRef, manifestDigest string) ([]byte, error) {
	type identity struct {
		DockerReference string `json:"docker-reference"`
	}
	type image struct {
		DockerManifestDigest string `json:"docker-manifest-digest"`
	}
	type critical struct {
		Identity identity `json:"identity"`
		Image    image    `json:"image"`
		Type     string   `json:"type"`
	}
	payload := struct {
		Critical critical       `json:"critical"`
		Optional map[string]any `json:"optional"`
	}{
		Critical: critical{
			Identity: identity{DockerReference: dockerRef},
			Image:    image{DockerManifestDigest: manifestDigest},
			Type:     "cosign container image signature",
		},
		Optional: nil,
	}
	return json.Marshal(payload)
}

// SignPayload signs an arbitrary payload (e.g. a SimpleSigningPayload) and
// returns the base64 signature to store in cosign's
// `dev.cosignproject.cosign/signature` annotation.
func (k *Keypair) SignPayload(payload []byte) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(k.Private, payload))
}
