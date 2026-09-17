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
	"crypto/mldsa"
	"testing"
)

func TestLoadDefaultMLDSA(t *testing.T) {
	priv, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatalf("unexpected error creating mldsa key: %v", err)
	}

	s, err := LoadDefaultSigner(priv)
	if err != nil {
		t.Fatalf("unexpected error creating signer: %v", err)
	}
	if _, ok := s.(*MLDSASigner); !ok {
		t.Fatalf("expected signer to be an mldsa signer, got %T", s)
	}

	v, err := LoadDefaultVerifier(priv.PublicKey())
	if err != nil {
		t.Fatalf("unexpected error creating verifier: %v", err)
	}
	if _, ok := v.(*MLDSAVerifier); !ok {
		t.Fatalf("expected verifier to be an mldsa verifier, got %T", v)
	}

	v, err = LoadUnsafeVerifier(priv.PublicKey())
	if err != nil {
		t.Fatalf("unexpected error creating unsafe verifier: %v", err)
	}
	if _, ok := v.(*MLDSAVerifier); !ok {
		t.Fatalf("expected unsafe verifier to be an mldsa verifier, got %T", v)
	}

	sv, err := LoadDefaultSignerVerifier(priv)
	if err != nil {
		t.Fatalf("unexpected error creating signer/verifier: %v", err)
	}
	if _, ok := sv.(*MLDSASignerVerifier); !ok {
		t.Fatalf("expected signer/verifier to be an mldsa signer/verifier, got %T", sv)
	}
}
