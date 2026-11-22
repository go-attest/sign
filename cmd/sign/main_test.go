package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/go-attest/sign"
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
	oo := osOpenFile
	osOpenFile = func(string, int, os.FileMode) (*os.File, error) { return nil, errors.New("disk full") }
	if c, _, _ := run2("keygen", "--pub", filepath.Join(dir, "p"), "--sec", filepath.Join(dir, "s")); c != 1 {
		t.Error("write error")
	}
	// secret written, then the public file cannot be created
	n := 0
	osOpenFile = func(p string, fl int, m os.FileMode) (*os.File, error) {
		if n++; n > 1 {
			return nil, errors.New("disk full")
		}
		return oo(p, fl, m)
	}
	if c, _, _ := run2("keygen", "--pub", filepath.Join(dir, "p2"), "--sec", filepath.Join(dir, "s2")); c != 1 {
		t.Error("public write error")
	}
	// a write that fails after the open (closed handle)
	osOpenFile = func(p string, fl int, m os.FileMode) (*os.File, error) {
		f, err := oo(p, fl, m)
		if err == nil {
			f.Close()
		}
		return f, err
	}
	if c, _, _ := run2("keygen", "--pub", filepath.Join(dir, "p3"), "--sec", filepath.Join(dir, "s3")); c != 1 {
		t.Error("short write error")
	}
	osOpenFile = oo
}

func keygenIn(t *testing.T, dir string) (int, string, string, string, string) {
	t.Helper()
	pub, sec := filepath.Join(dir, "k.pub"), filepath.Join(dir, "k.key")
	c, _, e := run2("keygen", "--pub", pub, "--sec", sec)
	return c, e, pub, sec, dir
}

func privateDir(t *testing.T) string {
	t.Helper()
	d := filepath.Join(t.TempDir(), "keys")
	if err := os.Mkdir(d, 0o700); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestKeygenRefusesExisting(t *testing.T) {
	dir := privateDir(t)
	c, e, pub, sec, _ := keygenIn(t, dir)
	if c != 0 {
		t.Fatalf("first keygen code=%d err=%q", c, e)
	}
	before, _ := os.ReadFile(sec)
	if c, _, e := run2("keygen", "--pub", pub+"2", "--sec", sec); c != 1 || !strings.Contains(e, "already exists") {
		t.Errorf("existing secret: code=%d err=%q", c, e)
	}
	if _, err := os.Stat(pub + "2"); err == nil {
		t.Error("a refused keygen left a public key behind")
	}
	if after, _ := os.ReadFile(sec); !bytes.Equal(before, after) {
		t.Error("existing secret key was overwritten")
	}
	// an existing public file is refused too, before the secret is created
	sec2 := filepath.Join(dir, "k2.key")
	if c, _, _ := run2("keygen", "--pub", pub, "--sec", sec2); c != 1 {
		t.Errorf("existing public: code=%d", c)
	}
	if _, err := os.Stat(sec2); err == nil {
		t.Error("a refused keygen left a secret key behind")
	}
}

func TestKeygenRefusesSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	dir := privateDir(t)
	target := filepath.Join(dir, "victim")
	for name, tgt := range map[string]string{"dangling": target, "live": filepath.Join(dir, "live")} {
		link := filepath.Join(dir, name+".key")
		if name == "live" {
			os.WriteFile(tgt, []byte("keep"), 0o600)
		}
		if err := os.Symlink(tgt, link); err != nil {
			t.Fatal(err)
		}
		if c, _, _ := run2("keygen", "--pub", filepath.Join(dir, name+".pub"), "--sec", link); c != 1 {
			t.Errorf("%s symlink: code=%d", name, c)
		}
	}
	if _, err := os.Stat(target); err == nil {
		t.Error("keygen wrote through a dangling symlink")
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "live")); string(b) != "keep" {
		t.Error("keygen wrote through a symlink to an existing file")
	}
}

func TestCreateNewRefusesSymlinkRace(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	// Even if the pre-check is bypassed, O_EXCL itself refuses a symlink.
	dir := privateDir(t)
	link := filepath.Join(dir, "l")
	os.Symlink(filepath.Join(dir, "t"), link)
	if err := createNew(link, []byte("x"), 0o600); err == nil {
		t.Error("createNew followed a symlink")
	}
}

func TestKeygenWarnsOnWritableDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes")
	}
	dir := privateDir(t)
	os.Chmod(dir, 0o777)
	c, e, _, _, _ := keygenIn(t, dir)
	if c != 0 || !strings.Contains(e, "writable by group or others") {
		t.Errorf("code=%d err=%q", c, e)
	}
	// private dir: silent; missing dir: no warning, create fails
	if _, e, _, _, _ := keygenIn(t, privateDir(t)); strings.Contains(e, "warning") {
		t.Errorf("unexpected warning %q", e)
	}
	var b bytes.Buffer
	og := goos
	goos = "windows"
	warnUnsafeDir(dir, &b)
	goos = og
	if b.Len() != 0 {
		t.Errorf("warned on windows: %q", b.String())
	}
	warnUnsafeDir(filepath.Join(dir, "no", "such", "k"), &b)
	if b.Len() != 0 {
		t.Errorf("warned about a missing dir: %q", b.String())
	}
}

func TestSignRefusesSimpleSigningPayload(t *testing.T) {
	dir := privateDir(t)
	c, e, _, sec, _ := keygenIn(t, dir)
	if c != 0 {
		t.Fatalf("keygen: %q", e)
	}
	payload, err := sign.SimpleSigningPayload("example.com/img", "sha256:abc")
	if err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(dir, "payload.json")
	os.WriteFile(f, payload, 0o644)
	c, _, e = run2("sign", "--sec", sec, f)
	if c != 1 || !strings.Contains(e, "simple-signing payload") {
		t.Errorf("code=%d err=%q", c, e)
	}
	if _, err := os.Stat(f + ".cosig"); err == nil {
		t.Error("a signature was written for an OCI payload")
	}
	// ordinary JSON is still signed
	g := filepath.Join(dir, "other.json")
	os.WriteFile(g, []byte(`{"critical":{"type":"something else"}}`), 0o644)
	if c, _, e := run2("sign", "--sec", sec, g); c != 0 {
		t.Errorf("ordinary json: code=%d err=%q", c, e)
	}
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
