package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-pkgx/sign"
)

// run2 runs the CLI capturing stdout/stderr and the exit code.
func run2(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestUsageAndUnknown(t *testing.T) {
	if c, _, _ := run2(); c != 2 {
		t.Errorf("no args code=%d", c)
	}
	if c, _, e := run2("bogus"); c != 2 || !bytes.Contains([]byte(e), []byte("unknown command")) {
		t.Errorf("unknown code=%d err=%q", c, e)
	}
}

func TestKeygenSignVerifyRoundTrip(t *testing.T) {
	dir := t.TempDir()
	pub := filepath.Join(dir, "k.pub")
	sec := filepath.Join(dir, "k.key")
	if c, _, e := run2("keygen", "--pub", pub, "--sec", sec, "--comment", "test"); c != 0 {
		t.Fatalf("keygen code=%d err=%q", c, e)
	}
	for _, f := range []string{pub, pub + ".pem", sec} {
		if _, err := os.Stat(f); err != nil {
			t.Errorf("keygen did not write %s", f)
		}
	}
	// cosign PEM is parseable
	pemBytes, _ := os.ReadFile(pub + ".pem")
	if _, err := sign.ParsePublicKeyPEM(pemBytes); err != nil {
		t.Errorf("cosign pem: %v", err)
	}

	data := filepath.Join(dir, "bottle.tar.gz")
	os.WriteFile(data, []byte("payload"), 0o644)
	if c, _, e := run2("sign", "--sec", sec, data); c != 0 {
		t.Fatalf("sign code=%d err=%q", c, e)
	}
	if _, err := os.Stat(data + ".minisig"); err != nil {
		t.Error("no .minisig")
	}
	if _, err := os.Stat(data + ".cosig"); err != nil {
		t.Error("no .cosig")
	}
	if c, o, e := run2("verify", "--pub", pub, data); c != 0 {
		t.Fatalf("verify code=%d err=%q out=%q", c, e, o)
	}
	// tamper → verify fails
	os.WriteFile(data, []byte("payloae"), 0o644)
	if c, _, _ := run2("verify", "--pub", pub, data); c != 1 {
		t.Errorf("tampered verify code=%d", c)
	}
}

func TestKeygenErrors(t *testing.T) {
	dir := t.TempDir()
	// bad flag
	if c, _, _ := run2("keygen", "-nope"); c != 2 {
		t.Error("bad flag")
	}
	// missing required
	if c, _, _ := run2("keygen", "--pub", filepath.Join(dir, "p")); c != 2 {
		t.Error("missing --sec")
	}
	// Generate error
	og := generate
	generate = func() (*sign.Keypair, error) { return nil, errors.New("boom") }
	if c, _, _ := run2("keygen", "--pub", filepath.Join(dir, "p"), "--sec", filepath.Join(dir, "s")); c != 1 {
		t.Error("generate error")
	}
	generate = og
	// PublicKeyPEM error
	op := pubPEM
	pubPEM = func(*sign.Keypair) ([]byte, error) { return nil, errors.New("pem boom") }
	if c, _, _ := run2("keygen", "--pub", filepath.Join(dir, "p"), "--sec", filepath.Join(dir, "s")); c != 1 {
		t.Error("pem error")
	}
	pubPEM = op
	// writeFiles error
	ow := osWriteFile
	osWriteFile = func(string, []byte, os.FileMode) error { return errors.New("disk full") }
	if c, _, _ := run2("keygen", "--pub", filepath.Join(dir, "p"), "--sec", filepath.Join(dir, "s")); c != 1 {
		t.Error("write error")
	}
	osWriteFile = ow
}

func TestSignErrors(t *testing.T) {
	dir := t.TempDir()
	sec := filepath.Join(dir, "k.key")
	pub := filepath.Join(dir, "k.pub")
	run2("keygen", "--pub", pub, "--sec", sec)
	data := filepath.Join(dir, "f")
	os.WriteFile(data, []byte("x"), 0o644)

	if c, _, _ := run2("sign", "-nope"); c != 2 {
		t.Error("bad flag")
	}
	if c, _, _ := run2("sign", data); c != 2 {
		t.Error("missing --sec")
	}
	// unreadable secret
	if c, _, _ := run2("sign", "--sec", filepath.Join(dir, "nope"), data); c != 1 {
		t.Error("missing secret")
	}
	// bad secret content
	bad := filepath.Join(dir, "bad.key")
	os.WriteFile(bad, []byte("garbage"), 0o644)
	if c, _, _ := run2("sign", "--sec", bad, data); c != 1 {
		t.Error("bad secret")
	}
	// unreadable data file
	if c, _, _ := run2("sign", "--sec", sec, filepath.Join(dir, "missing")); c != 1 {
		t.Error("missing data")
	}
	// write failure
	ow := osWriteFile
	osWriteFile = func(string, []byte, os.FileMode) error { return errors.New("full") }
	if c, _, _ := run2("sign", "--sec", sec, data); c != 1 {
		t.Error("write error")
	}
	osWriteFile = ow
}

func TestVerifyErrors(t *testing.T) {
	dir := t.TempDir()
	pub := filepath.Join(dir, "k.pub")
	sec := filepath.Join(dir, "k.key")
	run2("keygen", "--pub", pub, "--sec", sec)
	data := filepath.Join(dir, "f")
	os.WriteFile(data, []byte("x"), 0o644)
	run2("sign", "--sec", sec, data)

	if c, _, _ := run2("verify", "-nope"); c != 2 {
		t.Error("bad flag")
	}
	if c, _, _ := run2("verify", data); c != 2 {
		t.Error("missing --pub")
	}
	if c, _, _ := run2("verify", "--pub", filepath.Join(dir, "nope"), data); c != 1 {
		t.Error("missing pub")
	}
	if c, _, _ := run2("verify", "--pub", pub, filepath.Join(dir, "missing")); c != 1 {
		t.Error("missing data")
	}
	// missing .minisig
	lone := filepath.Join(dir, "lone")
	os.WriteFile(lone, []byte("y"), 0o644)
	if c, _, _ := run2("verify", "--pub", pub, lone); c != 1 {
		t.Error("missing sig")
	}
}

func TestMainSeam(t *testing.T) {
	oe, oa := osExit, os.Args
	defer func() { osExit, os.Args = oe, oa }()
	got := -1
	osExit = func(c int) { got = c }
	os.Args = []string{"sign"}
	main()
	if got != 2 {
		t.Errorf("main exit=%d", got)
	}
}
