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
	if err := writeFiles(map[string][]byte{
		*pub:          []byte(kp.PublicKeyFile(*comment)),
		*pub + ".pem": pemBytes, // cosign-compatible public key
		*sec:          []byte(kp.SecretKeyFile(*comment)),
	}); err != nil {
		fmt.Fprintln(stderr, "keygen:", err)
		return 1
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
	generate    = sign.Generate
	pubPEM      = func(k *sign.Keypair) ([]byte, error) { return k.PublicKeyPEM() }
)
