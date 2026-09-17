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

package cryptoutils

import (
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
)

func TestMLDSAPublicKeyPEMRoundtrip(t *testing.T) {
	t.Parallel()
	for _, param := range []mldsa.Parameters{mldsa.MLDSA44(), mldsa.MLDSA65(), mldsa.MLDSA87()} {
		priv, err := mldsa.GenerateKey(param)
		if err != nil {
			t.Fatalf("mldsa.GenerateKey failed: %v", err)
		}
		verifyPublicKeyPEMRoundtrip(t, priv.PublicKey())
	}
}

func TestSKIDMLDSA(t *testing.T) {
	priv, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatalf("mldsa.GenerateKey failed: %v", err)
	}
	skid, err := SKID(priv.PublicKey())
	if err != nil {
		t.Fatalf("SKID failed for valid ML-DSA key: %v", err)
	}
	if len(skid) != 20 {
		t.Fatalf("expected 20-byte SKID, got %d bytes", len(skid))
	}

	// Nil ML-DSA key
	if _, err := SKID((*mldsa.PublicKey)(nil)); err == nil || !strings.Contains(err.Error(), "ML-DSA public key must not be nil") {
		t.Fatalf("expected error for nil mldsa key, got %v", err)
	}

	// Empty ML-DSA key
	if _, err := SKID(&mldsa.PublicKey{}); err == nil || !strings.Contains(err.Error(), "invalid ML-DSA public key") {
		t.Fatalf("expected error for empty mldsa key, got %v", err)
	}
}

func TestEqualKeysMLDSA(t *testing.T) {
	privRsa, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey failed: %v", err)
	}
	pubEd, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey failed: %v", err)
	}
	// Test ML-DSA (success and failure)
	mldsa44First, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatalf("mldsa.GenerateKey failed: %v", err)
	}
	mldsa44Second, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatalf("mldsa.GenerateKey failed: %v", err)
	}
	mldsa65Key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatalf("mldsa.GenerateKey failed: %v", err)
	}
	// Verify equality with a separately constructed representation of the same key
	mldsa44Same, err := mldsa.NewPublicKey(mldsa.MLDSA44(), mldsa44First.PublicKey().Bytes())
	if err != nil {
		t.Fatalf("mldsa.NewPublicKey failed: %v", err)
	}
	if err := EqualKeys(mldsa44First.PublicKey(), mldsa44Same); err != nil {
		t.Fatalf("unexpected error for mldsa equality with separate representation, got %v", err)
	}
	if err := EqualKeys(mldsa44First.PublicKey(), mldsa44Second.PublicKey()); err == nil || !strings.Contains(err.Error(), "mldsa public keys are not equal") {
		t.Fatalf("expected error for different mldsa keys, got %v", err)
	}
	if err := EqualKeys(mldsa44First.PublicKey(), mldsa65Key.PublicKey()); err == nil || !strings.Contains(err.Error(), "mldsa public keys are not equal") {
		t.Fatalf("expected error for different mldsa parameter keys, got %v", err)
	}
	// Broken first argument
	if err := EqualKeys((*mldsa.PublicKey)(nil), mldsa44First.PublicKey()); err == nil || !strings.Contains(err.Error(), "ML-DSA public key must not be nil") {
		t.Fatalf("expected error for nil first mldsa key, got %v", err)
	}
	if err := EqualKeys(&mldsa.PublicKey{}, mldsa44First.PublicKey()); err == nil || !strings.Contains(err.Error(), "invalid ML-DSA public key") {
		t.Fatalf("expected error for empty first mldsa key, got %v", err)
	}
	// Broken second argument reports inequality without panicking
	if err := EqualKeys(mldsa44First.PublicKey(), (*mldsa.PublicKey)(nil)); err == nil || !strings.Contains(err.Error(), "mldsa public keys are not equal") {
		t.Fatalf("expected inequality error for nil second mldsa key, got %v", err)
	}
	if err := EqualKeys(mldsa44First.PublicKey(), &mldsa.PublicKey{}); err == nil || !strings.Contains(err.Error(), "mldsa public keys are not equal") {
		t.Fatalf("expected inequality error for empty second mldsa key, got %v", err)
	}
	if err := EqualKeys(mldsa44First.PublicKey(), pubEd); err == nil || !strings.Contains(err.Error(), "are not equal") {
		t.Fatalf("expected error for different key types (mldsa vs ed25519), got %v", err)
	}
	// Verify that EqualKeys with a valid non-ML-DSA key and an invalid ML-DSA key exercises
	// the SKID guard in genErrMsg without panicking.
	if err := EqualKeys(privRsa.Public(), &mldsa.PublicKey{}); err == nil || !strings.Contains(err.Error(), "rsa public keys are not equal") {
		t.Fatalf("expected error for rsa vs uninitialized mldsa key, got %v", err)
	}
	if err := EqualKeys(privRsa.Public(), (*mldsa.PublicKey)(nil)); err == nil || !strings.Contains(err.Error(), "rsa public keys are not equal") {
		t.Fatalf("expected error for rsa vs nil mldsa key, got %v", err)
	}
}

func TestValidatePubKeyMLDSA(t *testing.T) {
	mldsaPriv, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatalf("mldsa.GenerateKey failed: %v", err)
	}
	if err := ValidatePubKey(mldsaPriv.PublicKey()); err != nil {
		t.Errorf("unexpected error for valid mldsa key: %v", err)
	}
	if err := ValidatePubKey((*mldsa.PublicKey)(nil)); err == nil {
		t.Errorf("expected error for nil mldsa key")
	}
	if err := ValidatePubKey(&mldsa.PublicKey{}); err == nil {
		t.Errorf("expected error for empty mldsa key")
	}
}

func TestMLDSAPublicKeyParameters(t *testing.T) {
	priv, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatalf("mldsa.GenerateKey failed: %v", err)
	}
	params, err := MLDSAPublicKeyParameters(priv.PublicKey())
	if err != nil {
		t.Errorf("unexpected error for valid ML-DSA public key: %v", err)
	}
	if params != mldsa.MLDSA44() {
		t.Errorf("expected MLDSA44 parameters, got %v", params)
	}

	if _, err := MLDSAPublicKeyParameters(nil); err == nil || !strings.Contains(err.Error(), "ML-DSA public key must not be nil") {
		t.Errorf("expected error containing 'ML-DSA public key must not be nil', got %v", err)
	}

	if _, err := MLDSAPublicKeyParameters(&mldsa.PublicKey{}); err == nil || !strings.Contains(err.Error(), "invalid ML-DSA public key") {
		t.Errorf("expected error containing 'invalid ML-DSA public key', got %v", err)
	}
}
