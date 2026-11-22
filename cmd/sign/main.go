// Command sign mints Ed25519 keys and produces detached signatures for pkgx
// bottles that verify under both minisign and cosign.
//
//	sign keygen  --pub k.pub --sec k.key [--comment C]
//	sign sign    --sec k.key [--comment C] <file>   # writes <file>.minisig + <file>.cosig
//	sign verify  --pub k.pub <file>                 # verifies <file>.minisig
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/go-attest/sign"
)

var osExit = os.Exit

func main() { osExit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: sign <keygen|sign|verify> [flags] [file]")
		return 2
	}
	switch args[0] {
	case "keygen":
		return keygen(args[1:], stdout, stderr)
	case "sign":
		return signCmd(args[1:], stdout, stderr)
	case "verify":
		return verifyCmd(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "sign: unknown command %q\n", args[0])
		return 2
	}
}

// fs builds a FlagSet that reports errors to stderr and never calls os.Exit.
func fs(name string, stderr io.Writer) *flag.FlagSet {
	f := flag.NewFlagSet(name, flag.ContinueOnError)
	f.SetOutput(stderr)
	return f
}

func keygen(args []string, stdout, stderr io.Writer) int {
	f := fs("keygen", stderr)
	pub := f.String("pub", "", "public key output path (minisign format)")
	sec := f.String("sec", "", "secret key output path")
	comment := f.String("comment", "", "key comment")
	if err := f.Parse(args); err != nil {
		return 2
	}
	if *pub == "" || *sec == "" {
		fmt.Fprintln(stderr, "keygen: --pub and --sec are required")
		return 2
	}
	kp, err := generate()
	if err != nil {
		fmt.Fprintln(stderr, "keygen:", err)
		return 1
	}
	pemBytes, err := pubPEM(kp)
	if err != nil {
		fmt.Fprintln(stderr, "keygen:", err)
		return 1
	}
	// Check every destination before creating any, so a refusal leaves
	// nothing half-written; the secret key goes first, mode 0600.
	for _, p := range []string{*sec, *pub, *pub + ".pem"} {
		if _, err := osLstat(p); err == nil {
			fmt.Fprintf(stderr, "keygen: %s already exists (or is a symlink); refusing to overwrite or follow it\n", p)
			return 1
		}
	}
	warnUnsafeDir(*sec, stderr)
	if err := createNew(*sec, []byte(kp.SecretKeyFile(*comment)), 0o600); err != nil {
		fmt.Fprintln(stderr, "keygen:", err)
		return 1
	}
	for _, w := range []struct {
		path string
		data []byte
	}{
		{*pub, []byte(kp.PublicKeyFile(*comment))},
		{*pub + ".pem", pemBytes}, // cosign-compatible public key
	} {
		if err := createNew(w.path, w.data, 0o644); err != nil {
			fmt.Fprintln(stderr, "keygen:", err)
			return 1
		}
	}
	fmt.Fprintf(stdout, "wrote %s (minisign), %s.pem (cosign), %s\n", *pub, *pub, *sec)
	return 0
}

func signCmd(args []string, stdout, stderr io.Writer) int {
	f := fs("sign", stderr)
	sec := f.String("sec", "", "secret key path")
	comment := f.String("comment", "", "trusted comment")
	if err := f.Parse(args); err != nil {
		return 2
	}
	if *sec == "" || f.NArg() != 1 {
		fmt.Fprintln(stderr, "sign: --sec and exactly one file are required")
		return 2
	}
	file := f.Arg(0)
	kp, err := loadSecret(*sec)
	if err != nil {
		fmt.Fprintln(stderr, "sign:", err)
		return 1
	}
	data, err := osReadFile(file)
	if err != nil {
		fmt.Fprintln(stderr, "sign:", err)
		return 1
	}
	if sign.IsSimpleSigningPayload(data) {
		fmt.Fprintf(stderr, "sign: %s is a cosign simple-signing payload; refusing to sign it as a raw blob (the key also signs OCI payloads)\n", file)
		return 1
	}
	trusted := *comment
	if trusted == "" {
		trusted = "bottle " + file
	}
	if err := writeFiles(map[string][]byte{
		file + ".minisig": []byte(kp.SignMinisign(data, "", trusted)),
		file + ".cosig":   []byte(kp.SignBlob(data)),
	}); err != nil {
		fmt.Fprintln(stderr, "sign:", err)
		return 1
	}
	fmt.Fprintf(stdout, "wrote %s.minisig and %s.cosig\n", file, file)
	return 0
}

func verifyCmd(args []string, stdout, stderr io.Writer) int {
	f := fs("verify", stderr)
	pub := f.String("pub", "", "public key path (minisign format)")
	if err := f.Parse(args); err != nil {
		return 2
	}
	if *pub == "" || f.NArg() != 1 {
		fmt.Fprintln(stderr, "verify: --pub and exactly one file are required")
		return 2
	}
	file := f.Arg(0)
	pubBytes, err := osReadFile(*pub)
	if err != nil {
		fmt.Fprintln(stderr, "verify:", err)
		return 1
	}
	data, err := osReadFile(file)
	if err != nil {
		fmt.Fprintln(stderr, "verify:", err)
		return 1
	}
	sig, err := osReadFile(file + ".minisig")
	if err != nil {
		fmt.Fprintln(stderr, "verify:", err)
		return 1
	}
	if err := sign.VerifyMinisign(data, string(sig), string(pubBytes)); err != nil {
		fmt.Fprintln(stderr, "verify:", err)
		return 1
	}
	fmt.Fprintf(stdout, "OK: %s\n", file)
	return 0
}

func loadSecret(path string) (*sign.Keypair, error) {
	b, err := osReadFile(path)
	if err != nil {
		return nil, err
	}
	return sign.LoadSecretKey(string(b))
}

// createNew writes content to a file that must not exist yet: O_CREATE|O_EXCL
// with the mode set at creation (no window where it is wider), refusing an
// existing file and any symlink, dangling or not (O_EXCL never follows one).
func createNew(path string, content []byte, mode os.FileMode) error {
	f, err := osOpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	_, err = f.Write(content)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// warnUnsafeDir warns when the directory that will hold path is writable by
// group or others (and not sticky), where another user could swap the file.
func warnUnsafeDir(path string, stderr io.Writer) {
	if goos == "windows" { // Windows reports no meaningful group/other bits
		return
	}
	dir := filepath.Dir(path)
	fi, err := osStat(dir)
	if err != nil || !fi.IsDir() {
		return
	}
	if m := fi.Mode(); m.Perm()&0o022 != 0 && m&os.ModeSticky == 0 {
		fmt.Fprintf(stderr, "keygen: warning: %s is writable by group or others (mode %04o); keep the secret key in a private directory\n", dir, m.Perm())
	}
}

// writeFiles writes every path→content, stopping at the first error.
func writeFiles(files map[string][]byte) error {
	for path, content := range files {
		if err := osWriteFile(path, content, 0o644); err != nil {
			return err
		}
	}
	return nil
}

// seams for tests.
var (
	osReadFile  = os.ReadFile
	osWriteFile = os.WriteFile
	goos        = runtime.GOOS
	osOpenFile  = os.OpenFile
	osLstat     = os.Lstat
	osStat      = os.Stat
	generate    = sign.Generate
	pubPEM      = func(k *sign.Keypair) ([]byte, error) { return k.PublicKeyPEM() }
)
