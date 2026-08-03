# sign

[![ci](https://github.com/go-attest/sign/actions/workflows/ci.yml/badge.svg)](https://github.com/go-attest/sign/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/go-attest/sign.svg)](https://pkg.go.dev/github.com/go-attest/sign)

Ed25519 signing for build artifacts — **interoperable with both
[minisign](https://jedisct1.github.io/minisign/) and
[cosign](https://github.com/sigstore/cosign)** from a single keypair. Pure Go,
`CGO_ENABLED=0`, zero non-crypto dependencies.

An artifact is often distributed two ways, so it needs two signature encodings
over the *same* bytes:

- as a **tarball over HTTP** → a detached **minisign** `.minisig` served
  alongside it;
- as an **OCI artifact** → a **cosign** blob signature / image signature.

Both are a plain Ed25519 signature over the artifact bytes, so one keypair and
one signature value cover both transports.

## When to use this — and when not

This is a **minimal interop primitive**, not a signing framework. It exists for
pipelines that produce small static, `CGO_ENABLED=0`, multi-arch binaries
(e.g. tools that must run `FROM scratch`) and cannot pull a large dependency
tree, yet still want signatures that the standard verifiers accept.

Reach for the reference tools instead when you need their full feature set:

- **[sigstore/cosign](https://github.com/sigstore/cosign)** /
  **[sigstore-go](https://github.com/sigstore/sigstore-go)** — keyless signing
  with Fulcio certificates and a Rekor transparency log, policy verification,
  the whole Sigstore ecosystem. This package deliberately does *none* of that; it
  only does offline key-based Ed25519 that `cosign verify --key` accepts.
- **[minisign](https://jedisct1.github.io/minisign/)** — the reference CLI. We
  emit and verify its format; use the CLI directly if you don't need it embedded
  in Go.

The one gap this fills that neither covers: a single Ed25519 key producing **both**
a minisign `.minisig` *and* a cosign-verifiable signature, as a tiny library.

## Library

```go
kp, _ := sign.Generate()

// minisign — verifies with `minisign -V`
minisig := kp.SignMinisign(tarball, "", "bottle openssl.org 1.1.1w")
_ = sign.VerifyMinisign(tarball, minisig, kp.PublicKeyString())

// cosign — verifies with `cosign verify-blob --key cosign.pub`
pem, _ := kp.PublicKeyPEM()          // cosign public key
b64 := kp.SignBlob(tarball)          // cosign --signature value
pub, _ := sign.ParsePublicKeyPEM(pem)
_ = sign.VerifyBlob(tarball, b64, pub)
```

Verifying minisign's prehashed (`ED`, Blake2b-512) form is supported too; the
library only emits the legacy (`Ed`) form so verification needs nothing beyond
`crypto/ed25519`.

## CLI

```
sign keygen --pub k.pub --sec k.key [--comment C]   # writes k.pub, k.pub.pem (cosign), k.key
sign sign   --sec k.key [--comment C] <file>        # writes <file>.minisig and <file>.cosig
sign verify --pub k.pub <file>                       # verifies <file>.minisig
```

## Interoperability

Proven in CI-independent tests against the real `minisign` and `cosign`
binaries (skipped automatically where those tools are absent):

- our `.minisig` verifies under `minisign -V`, and we verify minisign's own output;
- our blob signature verifies under `cosign verify-blob --key`.

## License

BSD-3-Clause © the sign authors.
