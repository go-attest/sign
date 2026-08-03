package sign_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/go-attest/sign"
)

// pkgxRun returns a command that runs tool from pkgxPkg via pkgx, or skips the
// test if pkgx (or the tool) is unavailable — so CI without the binaries still
// passes while a developer machine with pkgx proves real interop.
func pkgxRun(t *testing.T, pkgxPkg, tool string, args ...string) *exec.Cmd {
	t.Helper()
	if _, err := exec.LookPath("pkgx"); err != nil {
		t.Skip("pkgx not on PATH; skipping real-binary interop")
	}
	full := append([]string{"+" + pkgxPkg, "--", tool}, args...)
	return exec.Command("pkgx", full...)
}

// TestMinisignForward: our .minisig must verify under the real minisign CLI.
func TestMinisignForward(t *testing.T) {
	kp, err := sign.Generate()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	data := []byte("pkgx bottle: openssl.org/v1.1.1w linux x86-64\n")
	dataF := filepath.Join(dir, "bottle.tar.gz")
	pubF := filepath.Join(dir, "key.pub")
	sigF := filepath.Join(dir, "bottle.tar.gz.minisig")
	mustWrite(t, dataF, data)
	mustWrite(t, pubF, []byte(kp.PublicKeyFile("go-pkgx test key")))
	mustWrite(t, sigF, []byte(kp.SignMinisign(data, "go-pkgx", "bottle openssl.org 1.1.1w")))

	cmd := pkgxRun(t, "jedisct1.github.io/minisign", "minisign", "-V", "-p", pubF, "-m", dataF, "-x", sigF)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("real minisign rejected our signature: %v\n%s", err, out)
	}
}

// TestMinisignReverse: we must verify a signature made by the real minisign CLI.
func TestMinisignReverse(t *testing.T) {
	dir := t.TempDir()
	pubF := filepath.Join(dir, "k.pub")
	secF := filepath.Join(dir, "k.key")
	dataF := filepath.Join(dir, "f.bin")
	data := []byte("reverse interop payload\n")
	mustWrite(t, dataF, data)

	// generate an unencrypted (-W) minisign keypair
	gen := pkgxRun(t, "jedisct1.github.io/minisign", "minisign", "-G", "-W", "-p", pubF, "-s", secF)
	if out, err := gen.CombinedOutput(); err != nil {
		t.Fatalf("minisign -G: %v\n%s", err, out)
	}
	// sign with it
	s := pkgxRun(t, "jedisct1.github.io/minisign", "minisign", "-S", "-s", secF, "-m", dataF)
	if out, err := s.CombinedOutput(); err != nil {
		t.Fatalf("minisign -S: %v\n%s", err, out)
	}
	pub := mustRead(t, pubF)
	sig := mustRead(t, dataF+".minisig")
	if err := sign.VerifyMinisign(data, string(sig), string(pub)); err != nil {
		t.Fatalf("we failed to verify a real minisign signature: %v", err)
	}
}

// TestCosignForward: our blob signature must verify under the real cosign CLI.
func TestCosignForward(t *testing.T) {
	kp, err := sign.Generate()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	data := []byte("cosign blob interop\n")
	dataF := filepath.Join(dir, "blob.bin")
	pubF := filepath.Join(dir, "cosign.pub")
	sigF := filepath.Join(dir, "blob.sig")
	pem, err := kp.PublicKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, dataF, data)
	mustWrite(t, pubF, pem)
	mustWrite(t, sigF, []byte(kp.SignBlob(data)))

	cmd := pkgxRun(t, "sigstore.dev/cosign", "cosign", "verify-blob",
		"--key", pubF, "--signature", sigF, "--insecure-ignore-tlog=true", dataF)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("real cosign rejected our blob signature: %v\n%s", err, out)
	}
}

func mustWrite(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
