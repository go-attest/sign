package sign

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/blake2b"
)

func mustGen(t *testing.T) *Keypair {
	t.Helper()
	kp, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	return kp
}

func TestGenerateEntropyErrors(t *testing.T) {
	orig := randRead
	defer func() { randRead = orig }()

	// fail on the very first read (the KeyID)
	randRead = func([]byte) (int, error) { return 0, errors.New("no entropy") }
	if _, err := Generate(); err == nil {
		t.Error("expected KeyID entropy error")
	}

	// KeyID succeeds, then Ed25519 seed read fails
	n := 0
	randRead = func(p []byte) (int, error) {
		if n++; n == 1 {
			return len(p), nil
		}
		return 0, errors.New("no entropy")
	}
	if _, err := Generate(); err == nil {
		t.Error("expected Ed25519 entropy error")
	}
}

func TestMinisignRoundTrip(t *testing.T) {
	kp := mustGen(t)
	data := []byte("round trip data")
	// default untrusted comment (empty → default), custom trusted
	sig := kp.SignMinisign(data, "", "trust me")
	if !strings.Contains(sig, "signed with go-attest/sign") {
		t.Errorf("default untrusted comment missing:\n%s", sig)
	}
	pub := kp.PublicKeyFile("") // default comment path
	if !strings.Contains(pub, "minisign public key") {
		t.Errorf("default pubkey comment missing:\n%s", pub)
	}
	if err := VerifyMinisign(data, sig, pub); err != nil {
		t.Fatalf("round trip verify: %v", err)
	}
	// tampered data must fail
	if err := VerifyMinisign([]byte("round trip datb"), sig, pub); err == nil {
		t.Error("expected verify failure on tampered data")
	}
}

func TestVerifyMinisignPrehashed(t *testing.T) {
	kp := mustGen(t)
	data := []byte("prehashed payload")
	h := blake2b.Sum512(data)
	sig := ed25519.Sign(kp.Private, h[:])
	trusted := "prehashed"
	line := append(append([]byte(algHashed), kp.ID[:]...), sig...)
	global := ed25519.Sign(kp.Private, globalMsg(sig, trusted))
	minisig := cUntrusted + "x\n" +
		base64.StdEncoding.EncodeToString(line) + "\n" +
		cTrusted + trusted + "\n" +
		base64.StdEncoding.EncodeToString(global) + "\n"
	if err := VerifyMinisign(data, minisig, kp.PublicKeyString()); err != nil {
		t.Fatalf("prehashed verify: %v", err)
	}
}

func TestVerifyMinisignErrors(t *testing.T) {
	kp := mustGen(t)
	data := []byte("d")
	good := kp.SignMinisign(data, "u", "t")
	pub := kp.PublicKeyString()

	// bad public key
	if err := VerifyMinisign(data, good, "!!!"); err == nil {
		t.Error("bad pubkey base64")
	}
	if err := VerifyMinisign(data, good, base64.StdEncoding.EncodeToString([]byte("short"))); err == nil {
		t.Error("short pubkey")
	}
	// bad minisig
	if err := VerifyMinisign(data, "only\none\ntwo", pub); err == nil {
		t.Error("truncated minisig")
	}
	// key-id mismatch: verify with a different key's pubkey
	other := mustGen(t)
	if err := VerifyMinisign(data, good, other.PublicKeyString()); err == nil {
		t.Error("key-id mismatch expected")
	}
	// unknown algorithm
	badAlg := swapAlg(t, good, "ZZ")
	if err := VerifyMinisign(data, badAlg, pub); err == nil {
		t.Error("unknown algorithm expected")
	}
	// broken trusted-comment global sig: flip the trusted comment text
	tampered := strings.Replace(good, cTrusted+"t", cTrusted+"t!", 1)
	if err := VerifyMinisign(data, tampered, pub); err == nil {
		t.Error("trusted-comment tamper expected")
	}
}

// swapAlg rewrites the 2-byte algorithm prefix of a minisig's signature line.
func swapAlg(t *testing.T, minisig, alg string) string {
	t.Helper()
	lines := strings.Split(strings.TrimRight(minisig, "\n"), "\n")
	raw, err := base64.StdEncoding.DecodeString(lines[1])
	if err != nil {
		t.Fatal(err)
	}
	copy(raw[:2], alg)
	lines[1] = base64.StdEncoding.EncodeToString(raw)
	return strings.Join(lines, "\n") + "\n"
}

func TestParseMinisigMalformed(t *testing.T) {
	kp := mustGen(t)
	good := kp.SignMinisign([]byte("x"), "u", "t")
	lines := strings.Split(strings.TrimRight(good, "\n"), "\n")

	// bad signature base64
	if _, err := parseMinisig(lines[0] + "\n@@@\n" + lines[2] + "\n" + lines[3]); err == nil {
		t.Error("bad sig base64")
	}
	// signature line wrong length
	shortSig := base64.StdEncoding.EncodeToString([]byte("tooshort"))
	if _, err := parseMinisig(lines[0] + "\n" + shortSig + "\n" + lines[2] + "\n" + lines[3]); err == nil {
		t.Error("short sig line")
	}
	// bad global base64
	if _, err := parseMinisig(lines[0] + "\n" + lines[1] + "\n" + lines[2] + "\n@@@"); err == nil {
		t.Error("bad global base64")
	}
	// global wrong length
	shortGlobal := base64.StdEncoding.EncodeToString([]byte("nope"))
	if _, err := parseMinisig(lines[0] + "\n" + lines[1] + "\n" + lines[2] + "\n" + shortGlobal); err == nil {
		t.Error("short global")
	}
}

func TestLastLine(t *testing.T) {
	if got := lastLine("untrusted comment: foo\nKEYLINE\n"); got != "KEYLINE" {
		t.Errorf("lastLine = %q", got)
	}
	// only comments / whitespace → falls back to trimmed whole string
	if got := lastLine("untrusted comment: only\n"); got != "untrusted comment: only" {
		t.Errorf("fallback lastLine = %q", got)
	}
}

func TestCosignRoundTrip(t *testing.T) {
	kp := mustGen(t)
	data := []byte("cosign blob")
	pemBytes, err := kp.PublicKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ParsePublicKeyPEM(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyBlob(data, kp.SignBlob(data), pub); err != nil {
		t.Fatalf("blob round trip: %v", err)
	}
	// tampered
	if err := VerifyBlob([]byte("cosign bloc"), kp.SignBlob(data), pub); err == nil {
		t.Error("expected tampered blob failure")
	}
	// bad base64
	if err := VerifyBlob(data, "@@@", pub); err == nil {
		t.Error("expected bad sig base64")
	}
}

func TestPublicKeyPEMError(t *testing.T) {
	orig := marshalPKIX
	defer func() { marshalPKIX = orig }()
	marshalPKIX = func(any) ([]byte, error) { return nil, errors.New("marshal boom") }
	if _, err := mustGen(t).PublicKeyPEM(); err == nil {
		t.Error("expected marshal error")
	}
}

func TestParsePublicKeyPEMErrors(t *testing.T) {
	if _, err := ParsePublicKeyPEM([]byte("not pem")); err == nil {
		t.Error("no PEM block")
	}
	// valid PEM, invalid PKIX DER
	garbage := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte{1, 2, 3}})
	if _, err := ParsePublicKeyPEM(garbage); err == nil {
		t.Error("bad DER")
	}
	// valid PKIX but not Ed25519 (ECDSA P-256)
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&ec.PublicKey)
	ecPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	if _, err := ParsePublicKeyPEM(ecPEM); err == nil {
		t.Error("non-ed25519 key should be rejected")
	}
}

func TestSimpleSigningAndSignPayload(t *testing.T) {
	kp := mustGen(t)
	payload, err := SimpleSigningPayload("ghcr.io/go-pkgx/bottles/openssl.org", "sha256:deadbeef")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(payload), "cosign container image signature") ||
		!strings.Contains(string(payload), "sha256:deadbeef") {
		t.Errorf("payload = %s", payload)
	}
	// the payload signature verifies with the public key
	sig := kp.SignPayload(payload)
	if err := VerifyBlob(payload, sig, kp.Public); err != nil {
		t.Fatalf("payload signature: %v", err)
	}
}

func TestSecretKeyRoundTrip(t *testing.T) {
	kp := mustGen(t)
	// default comment path + explicit comment path
	if !strings.Contains(kp.SecretKeyFile(""), "go-pkgx secret key") {
		t.Error("default secret comment missing")
	}
	file := kp.SecretKeyFile("mine")
	got, err := LoadSecretKey(file)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != kp.ID || string(got.Private) != string(kp.Private) || string(got.Public) != string(kp.Public) {
		t.Error("round-trip key mismatch")
	}
	// a loaded key still signs verifiably
	data := []byte("z")
	if err := VerifyMinisign(data, got.SignMinisign(data, "", "t"), got.PublicKeyString()); err != nil {
		t.Errorf("loaded key sign/verify: %v", err)
	}
	// errors: bad base64, wrong length
	if _, err := LoadSecretKey("untrusted comment: x\n@@@\n"); err == nil {
		t.Error("bad base64")
	}
	if _, err := LoadSecretKey(base64.StdEncoding.EncodeToString([]byte("short"))); err == nil {
		t.Error("short secret")
	}
}

func TestRandReader(t *testing.T) {
	var r randReader
	b := make([]byte, 4)
	if _, err := r.Read(b); err != nil {
		t.Fatal(err)
	}
}
