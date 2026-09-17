# sigstore framework
[![Fuzzing Status](https://oss-fuzz-build-logs.storage.googleapis.com/badges/sigstore.svg)](https://bugs.chromium.org/p/oss-fuzz/issues/list?sort=-opened&can=1&q=proj:sigstore) [![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/5716/badge)](https://bestpractices.coreinfrastructure.org/projects/5716)

sigstore/sigstore contains common [Sigstore](https://www.sigstore.dev/) code: that is, code shared by infrastructure (e.g., [Fulcio](https://github.com/sigstore/fulcio) and [Rekor](https://github.com/sigstore/rekor)) and Go language clients (e.g., [Cosign](https://github.com/sigstore/cosign) and [Gitsign](https://github.com/sigstore/gitsign)).

This library currently provides:

* A signing interface (support for ecdsa, ed25519, rsa, ML-DSA, DSSE (in-toto))
* OpenID Connect fulcio client code

ML-DSA support depends on `crypto/mldsa` and is only compiled with Go 1.27 or
later. When built with an older Go, the ML-DSA types and functions in
`pkg/signature` and `pkg/cryptoutils` are absent, the `ML_DSA_*` algorithms are
not present in the algorithm registry (`GetAlgorithmDetails` returns an error
for them), and ML-DSA keys are rejected as unsupported. Downstream code that
references the ML-DSA API directly needs its own `//go:build go1.27` constraint.

The following KMS systems are available:
* AWS Key Management Service
* Azure Key Vault
* HashiCorp Vault
* Google Cloud Platform Key Management Service
* OpenBao
* [OVHcloud KMS](https://github.com/ovh/sigstore-kms-ovhcloud) (as external plugin)

For example code, look at the relevant test code for each main code file.

## Fuzzing
The fuzzing tests are within https://github.com/sigstore/sigstore/tree/main/test/fuzz

## Security

Should you discover any security issues, please refer to sigstores [security
process](https://github.com/sigstore/.github/blob/main/SECURITY.md)

For container signing, you want [cosign](https://github.com/sigstore/cosign)
