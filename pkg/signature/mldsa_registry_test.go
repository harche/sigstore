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
	"crypto"
	"crypto/mldsa"
	"strings"
	"testing"

	v1 "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
)

func TestGetAlgorithmDetailsMLDSA(t *testing.T) {
	mldsa44Details, err := GetAlgorithmDetails(v1.PublicKeyDetails_ML_DSA_44)
	if err != nil {
		t.Errorf("unexpected error getting mldsa44 algorithm details: %v", err)
	}
	if mldsa44Details.GetSignatureAlgorithm() != v1.PublicKeyDetails_ML_DSA_44 {
		t.Errorf("unexpected signature algorithm")
	}

	mldsaDetails, err := GetAlgorithmDetails(v1.PublicKeyDetails_ML_DSA_65)
	if err != nil {
		t.Errorf("unexpected error getting mldsa algorithm details: %v", err)
	}
	if mldsaDetails.GetSignatureAlgorithm() != v1.PublicKeyDetails_ML_DSA_65 {
		t.Errorf("unexpected signature algorithm")
	}
	if mldsaDetails.GetKeyType() != MLDSA {
		t.Errorf("unexpected key algorithm")
	}
	if mldsaDetails.GetHashType() != crypto.Hash(0) {
		t.Errorf("unexpected hash algorithm for mldsa")
	}
	if mldsaDetails.GetProtoHashType() != v1.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED {
		t.Errorf("unexpected proto hash algorithm for mldsa")
	}
	params, err := mldsaDetails.GetMLDSAParameters()
	if err != nil {
		t.Errorf("unexpected error getting mldsa parameters")
	}
	if params != mldsa.MLDSA65() {
		t.Errorf("unexpected mldsa parameters")
	}
}

func TestAlgorithmRegistryConfigMLDSA(t *testing.T) {
	config, err := NewAlgorithmRegistryConfig([]v1.PublicKeyDetails{
		v1.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256,
		v1.PublicKeyDetails_ML_DSA_87,
	})
	if err != nil {
		t.Fatalf("unexpected error creating algorithm registry config: %v", err)
	}

	mldsaKey, err := mldsa.GenerateKey(mldsa.MLDSA87())
	if err != nil {
		t.Fatalf("unexpected error creating mldsa key: %v", err)
	}
	isPermitted, err := config.IsAlgorithmPermitted(mldsaKey.PublicKey(), crypto.Hash(0))
	if err != nil {
		t.Errorf("unexpected error checking registry for mldsa-87: %v", err)
	}
	if !isPermitted {
		t.Errorf("unexpected error permitting mldsa-87")
	}

	// A permitted ML-DSA parameter set does not permit a different one.
	mldsa44Key, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatalf("unexpected error creating mldsa key: %v", err)
	}
	isPermitted, err = config.IsAlgorithmPermitted(mldsa44Key.PublicKey(), crypto.Hash(0))
	if err != nil {
		t.Errorf("unexpected error checking registry for mldsa-44: %v", err)
	}
	if isPermitted {
		t.Errorf("unexpected success permitting mldsa-44")
	}
}

func TestSignatureAlgorithmFlagRoundtripMLDSA(t *testing.T) {
	for _, tc := range []struct {
		enum v1.PublicKeyDetails
		flag string
	}{
		{v1.PublicKeyDetails_ML_DSA_44, "mldsa-44"},
		{v1.PublicKeyDetails_ML_DSA_65, "mldsa-65"},
		{v1.PublicKeyDetails_ML_DSA_87, "mldsa-87"},
	} {
		flag, err := FormatSignatureAlgorithmFlag(tc.enum)
		if err != nil {
			t.Errorf("unexpected error formatting signature algorithm flag: %v", err)
		}
		if flag != tc.flag {
			t.Errorf("unexpected flag, expected %s, got %s", tc.flag, flag)
		}
		enum, err := ParseSignatureAlgorithmFlag(tc.flag)
		if err != nil {
			t.Errorf("unexpected error parsing signature algorithm flag: %v", err)
		}
		if enum != tc.enum {
			t.Errorf("unexpected enum, expected %s, got %s", tc.enum, enum)
		}
	}
}

func TestGetDefaultPublicKeyDetailsMLDSA(t *testing.T) {
	for _, tc := range []struct {
		name     string
		params   mldsa.Parameters
		expected v1.PublicKeyDetails
	}{
		{"mldsa-44", mldsa.MLDSA44(), v1.PublicKeyDetails_ML_DSA_44},
		{"mldsa-65", mldsa.MLDSA65(), v1.PublicKeyDetails_ML_DSA_65},
		{"mldsa-87", mldsa.MLDSA87(), v1.PublicKeyDetails_ML_DSA_87},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key, err := mldsa.GenerateKey(tc.params)
			if err != nil {
				t.Fatalf("unexpected error creating mldsa key: %v", err)
			}
			keyDetails, err := GetDefaultPublicKeyDetails(key.PublicKey())
			if err != nil {
				t.Errorf("unexpected error getting default public key details: %v", err)
			}
			if keyDetails != tc.expected {
				t.Errorf("unexpected signature algorithm")
			}

			algorithmDetails, err := GetDefaultAlgorithmDetails(key.PublicKey())
			if err != nil {
				t.Errorf("unexpected error getting default algorithm details: %v", err)
			}
			if algorithmDetails.GetSignatureAlgorithm() != keyDetails {
				t.Errorf("unexpected signature algorithm")
			}
		})
	}
}

func TestGetDefaultPublicKeyDetailsInvalidMLDSA(t *testing.T) {
	keyDetails, err := GetDefaultPublicKeyDetails((*mldsa.PublicKey)(nil))
	if err == nil || !strings.Contains(err.Error(), "ML-DSA public key must not be nil") {
		t.Errorf("expected error containing 'ML-DSA public key must not be nil', got %v", err)
	}
	if keyDetails != v1.PublicKeyDetails_PUBLIC_KEY_DETAILS_UNSPECIFIED {
		t.Errorf("expected UNSPECIFIED public key details for nil key, got %v", keyDetails)
	}

	keyDetails, err = GetDefaultPublicKeyDetails(&mldsa.PublicKey{})
	if err == nil || !strings.Contains(err.Error(), "invalid ML-DSA public key") {
		t.Errorf("expected error containing 'invalid ML-DSA public key', got %v", err)
	}
	if keyDetails != v1.PublicKeyDetails_PUBLIC_KEY_DETAILS_UNSPECIFIED {
		t.Errorf("expected UNSPECIFIED public key details for empty key, got %v", keyDetails)
	}
}

func TestCheckKeyInvalidMLDSA(t *testing.T) {
	details, err := GetAlgorithmDetails(v1.PublicKeyDetails_ML_DSA_65)
	if err != nil {
		t.Fatalf("unexpected error getting algorithm details: %v", err)
	}
	// Untyped nil is not an ML-DSA key and returns (false, nil)
	ok, err := details.checkKey(nil)
	if err != nil || ok {
		t.Errorf("expected (false, nil) for untyped nil key, got (%v, %v)", ok, err)
	}

	// Typed nil and uninitialized ML-DSA keys should return meaningful errors
	ok, err = details.checkKey((*mldsa.PublicKey)(nil))
	if err == nil || !strings.Contains(err.Error(), "ML-DSA public key must not be nil") || ok {
		t.Errorf("expected error containing 'ML-DSA public key must not be nil', got (%v, %v)", ok, err)
	}

	ok, err = details.checkKey(&mldsa.PublicKey{})
	if err == nil || !strings.Contains(err.Error(), "invalid ML-DSA public key") || ok {
		t.Errorf("expected error containing 'invalid ML-DSA public key', got (%v, %v)", ok, err)
	}
}
