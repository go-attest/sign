# sign

[![ci](https://github.com/go-attest/sign/actions/workflows/ci.yml/badge.svg)](https://github.com/go-attest/sign/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/go-attest/sign.svg)](https://pkg.go.dev/github.com/go-attest/sign)

Ed25519 signing for pkgx bottles — **interoperable with both
[minisign](https://jedisct1.github.io/minisign/) and
[cosign](https://github.com/sigstore/cosign)** from a single keypair. Pure Go,
`CGO_ENABLED=0`, zero non-crypto dependencies.

A bottle is distributed two ways, so it needs two signature encodings over the
*same* bytes:

- as a **tarball over HTTP** (`dist.pkgx.dev/…/v1.2.3.tar.gz`) → a detached
  **minisign** `.minisig` served alongside it;
- as an **OCI artifact** (`ghcr.io/go-pkgx/bottles/…`) → a **cosign** blob
  signature / image signature.

Both are a plain Ed25519 signature over the bottle bytes, so one keypair and one
signature value cover both transports.

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
