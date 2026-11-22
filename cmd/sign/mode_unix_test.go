//go:build !windows

package main

import (
	"os"
	"syscall"
	"testing"
)

func TestKeygenSecretKeyMode(t *testing.T) {
	// A permissive umask must not widen the secret; the old code wrote 0644.
	old := syscall.Umask(0o022)
	defer syscall.Umask(old)
	c, e, pub, sec, _ := keygenIn(t, privateDir(t))
	if c != 0 {
		t.Fatalf("keygen code=%d err=%q", c, e)
	}
	if fi, _ := os.Stat(sec); fi.Mode().Perm() != 0o600 {
		t.Errorf("secret key mode %04o, want 0600", fi.Mode().Perm())
	}
	for _, f := range []string{pub, pub + ".pem"} {
		if fi, _ := os.Stat(f); fi.Mode().Perm() != 0o644 {
			t.Errorf("%s mode %04o, want 0644", f, fi.Mode().Perm())
		}
	}
}
