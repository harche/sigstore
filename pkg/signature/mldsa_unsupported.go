//go:build !go1.27

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

	v1 "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
)

// ML-DSA support requires crypto/mldsa, which was introduced in Go 1.27.
// When built with an older Go, no ML-DSA algorithms are registered and any
// ML-DSA key is reported as an unsupported key type.

// mldsaAlgorithms is empty when built with Go < 1.27.
var mldsaAlgorithms []AlgorithmDetails

// checkMLDSAKey is unreachable on Go < 1.27: AlgorithmDetails with an MLDSA
// key type only come from mldsaAlgorithms, which is empty here.
func (a AlgorithmDetails) checkMLDSAKey(crypto.PublicKey) (bool, error) {
	return false, nil
}

func mldsaDefaultPublicKeyDetails(crypto.PublicKey) (v1.PublicKeyDetails, bool, error) {
	return v1.PublicKeyDetails_PUBLIC_KEY_DETAILS_UNSPECIFIED, false, nil
}

func mldsaSignerFor(crypto.PrivateKey) (Signer, bool, error) {
	return nil, false, nil
}

func mldsaVerifierFor(crypto.PublicKey) (Verifier, bool, error) {
	return nil, false, nil
}

func mldsaSignerVerifierFor(crypto.PrivateKey) (SignerVerifier, bool, error) {
	return nil, false, nil
}
