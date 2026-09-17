//go:build go1.27

//
// Copyright 2026 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package signature

import (
	"bytes"
	"crypto"
	"crypto/mldsa"
	"errors"
	"fmt"
	"io"

	v1 "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

// ML-DSA support depends on crypto/mldsa, which was introduced in Go 1.27.
// This file is only compiled with Go 1.27 or later; see mldsa_unsupported.go
// for the behavior on older toolchains.

var mldsaSupportedHashFuncs = []crypto.Hash{
	crypto.Hash(0),
}

// MLDSASigner is a signature.Signer that uses the ML-DSA post-quantum signature scheme.
//
// WARNING: This is experimental and may change.
type MLDSASigner struct {
	priv *mldsa.PrivateKey
}

// validateMLDSAPrivateKey checks that the ML-DSA private key is properly initialized.
// Calling priv.PublicKey() does not panic for an uninitialized &mldsa.PrivateKey{} in current
// Go versions (the panic occurs when probing the resulting public key), but this recover is
// retained as defense-in-depth against future runtime changes.
func validateMLDSAPrivateKey(priv *mldsa.PrivateKey) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("key is invalid: %v", r)
		}
	}()
	if _, valErr := cryptoutils.MLDSAPublicKeyParameters(priv.PublicKey()); valErr != nil {
		return valErr
	}
	return nil
}

// LoadMLDSASigner calculates signatures using the specified private key.
func LoadMLDSASigner(priv *mldsa.PrivateKey) (*MLDSASigner, error) {
	if priv == nil {
		return nil, errors.New("invalid ML-DSA private key specified")
	}
	if err := validateMLDSAPrivateKey(priv); err != nil {
		return nil, fmt.Errorf("invalid ML-DSA private key specified: %w", err)
	}

	return &MLDSASigner{
		priv: priv,
	}, nil
}

// SignMessage signs the provided message using Pure ML-DSA with an empty context.
//
// Passing the WithDigest option with a digest is not supported as ML-DSA handles
// its own internal message processing. Other options are ignored.
func (m MLDSASigner) SignMessage(message io.Reader, opts ...SignOption) ([]byte, error) {
	var digest []byte
	for _, opt := range opts {
		opt.ApplyDigest(&digest)
	}
	if len(digest) > 0 {
		return nil, errors.New("WithDigest is not supported for ML-DSA")
	}
	messageBytes, _, err := ComputeDigestForSigning(message, crypto.Hash(0), mldsaSupportedHashFuncs)
	if err != nil {
		return nil, err
	}

	return m.priv.Sign(nil, messageBytes, nil)
}

// Public returns the public key that can be used to verify signatures created by
// this signer.
func (m MLDSASigner) Public() crypto.PublicKey {
	if m.priv == nil {
		return nil
	}

	return m.priv.Public()
}

// PublicKey returns the public key that can be used to verify signatures created by
// this signer. As this value is held in memory, all options provided in arguments
// to this method are ignored.
func (m MLDSASigner) PublicKey(_ ...PublicKeyOption) (crypto.PublicKey, error) {
	return m.Public(), nil
}

// Sign computes the signature for the specified message using Pure ML-DSA with an empty context
// for consistency across software, KMS, and hardware backends. Callers requiring domain separation
// can enforce it at the payload level.
//
// The rand argument is ignored because ML-DSA internally generates randomness.
// If opts is non-nil, only opts with an empty context and HashFunc() == crypto.Hash(0) are supported;
// pre-hashed μ (crypto.MLDSAMu) and non-empty context strings are not permitted.
func (m MLDSASigner) Sign(_ io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	if message == nil {
		return nil, errors.New("message must not be nil")
	}
	if opts != nil {
		if opts.HashFunc() != crypto.Hash(0) {
			return nil, fmt.Errorf("unsupported hash function: %v", opts.HashFunc())
		}
		if mldsaOpts, ok := opts.(*mldsa.Options); ok && mldsaOpts.Context != "" {
			return nil, errors.New("non-empty context is not supported; use empty context for consistency across backends")
		}
	}
	return m.SignMessage(bytes.NewReader(message))
}

// MLDSAVerifier is a signature.Verifier that uses the ML-DSA post-quantum signature system.
//
// WARNING: This is experimental and may change.
type MLDSAVerifier struct {
	publicKey *mldsa.PublicKey
}

// LoadMLDSAVerifier returns a Verifier that verifies signatures using the specified ML-DSA public key.
func LoadMLDSAVerifier(pub *mldsa.PublicKey) (*MLDSAVerifier, error) {
	if pub == nil {
		return nil, errors.New("invalid ML-DSA public key specified")
	}
	if _, err := cryptoutils.MLDSAPublicKeyParameters(pub); err != nil {
		return nil, fmt.Errorf("invalid ML-DSA public key specified: %w", err)
	}

	return &MLDSAVerifier{
		publicKey: pub,
	}, nil
}

// PublicKey returns the public key that is used to verify signatures by
// this verifier. As this value is held in memory, all options provided in arguments
// to this method are ignored.
func (m *MLDSAVerifier) PublicKey(_ ...PublicKeyOption) (crypto.PublicKey, error) {
	return m.publicKey, nil
}

// VerifySignature verifies the signature for the given message using Pure ML-DSA with an empty context.
//
// This function returns nil if the verification succeeded, and an error message otherwise.
//
// Passing the WithDigest option with a digest is explicitly rejected as ML-DSA does not support
// pre-hashed message digests. Other options are ignored.
func (m *MLDSAVerifier) VerifySignature(signature, message io.Reader, opts ...VerifyOption) error {
	if signature == nil {
		return errors.New("nil signature passed to VerifySignature")
	}
	var digest []byte
	for _, opt := range opts {
		opt.ApplyDigest(&digest)
	}
	if len(digest) > 0 {
		return errors.New("WithDigest is not supported for ML-DSA")
	}
	messageBytes, _, err := ComputeDigestForVerifying(message, crypto.Hash(0), mldsaSupportedHashFuncs)
	if err != nil {
		return err
	}

	sigBytes, err := io.ReadAll(signature)
	if err != nil {
		return fmt.Errorf("reading signature: %w", err)
	}

	return mldsa.Verify(m.publicKey, messageBytes, sigBytes, nil)
}

// MLDSASignerVerifier is a signature.SignerVerifier that uses the ML-DSA post-quantum signature system
type MLDSASignerVerifier struct {
	*MLDSASigner
	*MLDSAVerifier
}

// LoadMLDSASignerVerifier creates a combined signer and verifier. This is
// a convenience object that simply wraps an instance of MLDSASigner and MLDSAVerifier.
func LoadMLDSASignerVerifier(priv *mldsa.PrivateKey) (*MLDSASignerVerifier, error) {
	signer, err := LoadMLDSASigner(priv)
	if err != nil {
		return nil, fmt.Errorf("initializing signer: %w", err)
	}
	verifier, err := LoadMLDSAVerifier(priv.PublicKey())
	if err != nil {
		return nil, fmt.Errorf("initializing verifier: %w", err)
	}

	return &MLDSASignerVerifier{
		MLDSASigner:   signer,
		MLDSAVerifier: verifier,
	}, nil
}

// NewDefaultMLDSASignerVerifier creates a combined signer and verifier using ML-DSA.
// This creates a new ML-DSA key using the recommended default MLDSA44 parameter set.
func NewDefaultMLDSASignerVerifier() (*MLDSASignerVerifier, *mldsa.PrivateKey, error) {
	return NewMLDSASignerVerifier(mldsa.MLDSA44())
}

// NewMLDSASignerVerifier creates a combined signer and verifier using ML-DSA.
// This creates a new ML-DSA key using the specified parameter set.
func NewMLDSASignerVerifier(params mldsa.Parameters) (*MLDSASignerVerifier, *mldsa.PrivateKey, error) {
	priv, err := mldsa.GenerateKey(params)
	if err != nil {
		return nil, nil, err
	}

	sv, err := LoadMLDSASignerVerifier(priv)
	if err != nil {
		return nil, nil, err
	}

	return sv, priv, nil
}

// PublicKey returns the public key that is used to verify signatures by
// this verifier. As this value is held in memory, all options provided in arguments
// to this method are ignored.
func (m MLDSASignerVerifier) PublicKey(_ ...PublicKeyOption) (crypto.PublicKey, error) {
	return m.publicKey, nil
}

// mldsaAlgorithms are the ML-DSA entries of the algorithm registry. They are
// only registered when built with Go 1.27 or later, which introduced crypto/mldsa.
var mldsaAlgorithms = []AlgorithmDetails{
	{v1.PublicKeyDetails_ML_DSA_44, MLDSA, crypto.Hash(0), v1.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED, mldsa.MLDSA44(), "mldsa-44"},
	{v1.PublicKeyDetails_ML_DSA_65, MLDSA, crypto.Hash(0), v1.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED, mldsa.MLDSA65(), "mldsa-65"},
	{v1.PublicKeyDetails_ML_DSA_87, MLDSA, crypto.Hash(0), v1.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED, mldsa.MLDSA87(), "mldsa-87"},
}

// GetMLDSAParameters returns the ML-DSA parameters for the algorithm details, if the key type is MLDSA.
func (a AlgorithmDetails) GetMLDSAParameters() (mldsa.Parameters, error) {
	if a.keyType != MLDSA {
		return mldsa.Parameters{}, fmt.Errorf("unable to retrieve ML-DSA parameters for key type: %T", a.keyType)
	}
	params, ok := a.extraKeyParams.(mldsa.Parameters)
	if !ok {
		// This should be unreachable.
		return mldsa.Parameters{}, fmt.Errorf("unable to retrieve parameters for ML-DSA, malformed algorithm details?: %T", a.keyType)
	}
	return params, nil
}

func (a AlgorithmDetails) checkMLDSAKey(pubKey crypto.PublicKey) (bool, error) {
	mldsaKey, ok := pubKey.(*mldsa.PublicKey)
	if !ok {
		return false, nil
	}
	// Validate the ML-DSA key. If the key is a typed nil or uninitialized,
	// return an error so the caller receives a meaningful diagnostic rather
	// than a generic "unsupported algorithm" failure.
	keyParams, err := cryptoutils.MLDSAPublicKeyParameters(mldsaKey)
	if err != nil {
		return false, err
	}
	params, err := a.GetMLDSAParameters()
	if err != nil {
		return false, err
	}
	return keyParams == params, nil
}

// mldsaDefaultPublicKeyDetails returns the default v1.PublicKeyDetails for an ML-DSA public key.
// The boolean result reports whether publicKey is an ML-DSA key at all.
func mldsaDefaultPublicKeyDetails(publicKey crypto.PublicKey) (v1.PublicKeyDetails, bool, error) {
	pk, ok := publicKey.(*mldsa.PublicKey)
	if !ok {
		return v1.PublicKeyDetails_PUBLIC_KEY_DETAILS_UNSPECIFIED, false, nil
	}
	params, err := cryptoutils.MLDSAPublicKeyParameters(pk)
	if err != nil {
		return v1.PublicKeyDetails_PUBLIC_KEY_DETAILS_UNSPECIFIED, true, err
	}
	switch params {
	case mldsa.MLDSA44():
		return v1.PublicKeyDetails_ML_DSA_44, true, nil
	case mldsa.MLDSA65():
		return v1.PublicKeyDetails_ML_DSA_65, true, nil
	case mldsa.MLDSA87():
		return v1.PublicKeyDetails_ML_DSA_87, true, nil
	}
	return v1.PublicKeyDetails_PUBLIC_KEY_DETAILS_UNSPECIFIED, true, errors.New("unsupported public key type")
}

// mldsaSignerFor returns an MLDSASigner if privateKey is an ML-DSA private key.
// The boolean result reports whether privateKey is an ML-DSA key at all.
func mldsaSignerFor(privateKey crypto.PrivateKey) (Signer, bool, error) {
	pk, ok := privateKey.(*mldsa.PrivateKey)
	if !ok {
		return nil, false, nil
	}
	s, err := LoadMLDSASigner(pk)
	return s, true, err
}

// mldsaVerifierFor returns an MLDSAVerifier if publicKey is an ML-DSA public key.
// The boolean result reports whether publicKey is an ML-DSA key at all.
func mldsaVerifierFor(publicKey crypto.PublicKey) (Verifier, bool, error) {
	pk, ok := publicKey.(*mldsa.PublicKey)
	if !ok {
		return nil, false, nil
	}
	v, err := LoadMLDSAVerifier(pk)
	return v, true, err
}

// mldsaSignerVerifierFor returns an MLDSASignerVerifier if privateKey is an ML-DSA private key.
// The boolean result reports whether privateKey is an ML-DSA key at all.
func mldsaSignerVerifierFor(privateKey crypto.PrivateKey) (SignerVerifier, bool, error) {
	pk, ok := privateKey.(*mldsa.PrivateKey)
	if !ok {
		return nil, false, nil
	}
	sv, err := LoadMLDSASignerVerifier(pk)
	return sv, true, err
}
