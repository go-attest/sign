package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-attest/sign"
)

// withStdin runs fn with osStdin replaced by s.
func withStdin(t *testing.T, s string, fn func()) {
	t.Helper()
	old := osStdin
	osStdin = strings.NewReader(s)
	defer func() { osStdin = old }()
	fn()
}

// keygenFiles mints a keypair with the CLI and returns the .pub and secret text.
func keygenFiles(t *testing.T) (pubText, secText, secPath string) {
	t.Helper()
	dir := privateDir(t)
	c, e, pub, sec, _ := keygenIn(t, dir)
	if c != 0 {
		t.Fatalf("keygen code=%d err=%q", c, e)
	}
	p, err := os.ReadFile(pub)
	if err != nil {
		t.Fatal(err)
	}
	s, err := os.ReadFile(sec)
	if err != nil {
		t.Fatal(err)
	}
	return string(p), string(s), sec
}

// The output is the keypair's own .pub file, byte for byte, then the key id.
func TestPubkeyEqualsTheKeygenPubFile(t *testing.T) {
	pubText, secText, secPath := keygenFiles(t)
	kp, err := sign.LoadSecretKey(secText)
	if err != nil {
		t.Fatal(err)
	}
	want := pubText + "key id: " + kpID(kp) + "\n"

	c, out, e := run2("pubkey", "--sec", secPath)
	if c != 0 || e != "" {
		t.Fatalf("file: code=%d err=%q", c, e)
	}
	if out != want {
		t.Errorf("file: got %q want %q", out, want)
	}
	withStdin(t, secText, func() {
		c, out, e := run2("pubkey")
		if c != 0 || e != "" || out != want {
			t.Errorf("stdin: code=%d out=%q err=%q", c, out, e)
		}
	})
	withStdin(t, secText, func() {
		if c, out2, _ := run2("pubkey", "--sec", "-"); c != 0 || out2 != want {
			t.Errorf("stdin dash: code=%d out=%q", c, out2)
		}
	})

	// The public line is a minisign key: base64 of "Ed" + id + 32 bytes.
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 3 || len(lines[1]) != 56 {
		t.Fatalf("shape: %q", out)
	}
	raw, err := base64.StdEncoding.DecodeString(lines[1])
	if err != nil || len(raw) != 42 || string(raw[:2]) != "Ed" {
		t.Errorf("public line is not a minisign key: %v", err)
	}
	if strings.Contains(out, strings.TrimSpace(strings.Split(secText, "\n")[1])) {
		t.Error("the secret line was printed")
	}
}

func kpID(kp *sign.Keypair) string { return fmt.Sprintf("%X", kp.ID) }

func TestPubkeyRefusals(t *testing.T) {
	_, secText, _ := keygenFiles(t)
	secLine := strings.TrimSpace(strings.Split(secText, "\n")[1])

	// An argument could be a secret on argv.
	if c, _, e := run2("pubkey", secLine); c != 2 || strings.Contains(e, secLine) {
		t.Errorf("argv secret: code=%d err=%q", c, e)
	}
	if c, _, _ := run2("pubkey", "--nope"); c != 2 {
		t.Errorf("bad flag code=%d", c)
	}
	if c, out, e := run2("pubkey", "--sec", filepath.Join(t.TempDir(), "absent")); c != 1 || out != "" || e == "" {
		t.Errorf("absent: code=%d out=%q err=%q", c, out, e)
	}

	// Garbage that carries recognisable text is refused without echoing it.
	for name, in := range map[string]string{
		"empty":   "",
		"text":    "untrusted comment: SENTINEL-COMMENT\nnot base64 SENTINEL-BODY\n",
		"short":   "c\n" + base64.StdEncoding.EncodeToString([]byte("SENTINEL-SHORT")) + "\n",
		"pubkey":  "untrusted comment: x\nRWThxRI20GKw0BWqZHXpqJ/Wo2nX8ntSLIrXIFwK/FKm9F/vSE6Bl+mU\n",
		"toolong": strings.Repeat("A", maxSecretKeyFile+1),
	} {
		withStdin(t, in, func() {
			c, out, e := run2("pubkey")
			if c != 1 || out != "" || e == "" {
				t.Errorf("%s: code=%d out=%q err=%q", name, c, out, e)
			}
			if strings.Contains(e, "SENTINEL") || strings.Contains(e, "RWThx") {
				t.Errorf("%s: the input was echoed: %q", name, e)
			}
		})
	}

	// A reader that fails.
	old := osStdin
	osStdin = errReader{}
	defer func() { osStdin = old }()
	if c, _, e := run2("pubkey"); c != 1 || e == "" {
		t.Errorf("read error: code=%d err=%q", c, e)
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, os.ErrInvalid }

// A secret key the parser accepts must never appear in what pubkey prints, and
// nothing the parser rejects may appear in what it says.
func FuzzPubkey(f *testing.F) {
	f.Add("")
	f.Add("untrusted comment: c\n" + base64.StdEncoding.EncodeToString(make([]byte, 72)) + "\n")
	f.Add("untrusted comment: c\nAAAA\n")
	f.Add("\n\n\n")
	f.Add(strings.Repeat("A", 200))
	f.Fuzz(func(t *testing.T, in string) {
		old := osStdin
		osStdin = strings.NewReader(in)
		defer func() { osStdin = old }()
		var out, errb bytes.Buffer
		code := run([]string{"pubkey"}, &out, &errb)
		switch code {
		case 0:
			lines := strings.Split(strings.TrimSpace(out.String()), "\n")
			if len(lines) != 3 || len(lines[1]) != 56 || !strings.HasPrefix(lines[2], "key id: ") {
				t.Fatalf("shape %q", out.String())
			}
			kp, err := sign.LoadSecretKey(in)
			if err != nil {
				t.Fatalf("printed a key for input the parser refuses: %v", err)
			}
			if strings.Contains(out.String(), base64.StdEncoding.EncodeToString(kp.Private)) {
				t.Fatal("the private key was printed")
			}
		case 1:
			if out.Len() != 0 {
				t.Fatalf("stdout on failure: %q", out.String())
			}
			// stderr is one of a fixed set of lines.
			switch strings.TrimSpace(errb.String()) {
			case "pubkey: not a secret key", "pubkey: input is too large to be a secret key":
			default:
				t.Fatalf("stderr is not one of the fixed lines: %q", errb.String())
			}
		default:
			t.Fatalf("code %d", code)
		}
	})
}
