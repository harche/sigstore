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
	"crypto"
	"crypto/mldsa"
	"errors"
	"fmt"
)

// ML-DSA support depends on crypto/mldsa, which was introduced in Go 1.27.
// This file is only compiled with Go 1.27 or later; see mldsa_unsupported.go
// for the behavior on older toolchains.

// MLDSAPublicKeyParameters returns the parameters of the ML-DSA public key,
// after checking that it is non-nil and properly initialized.
// In the Go standard library, calling methods such as Parameters() on an uninitialized
// &mldsa.PublicKey{} panics because its internal parameters are uninitialized. This function
// performs a deliberate probe to catch such panics safely and return a descriptive error.
func MLDSAPublicKeyParameters(pub *mldsa.PublicKey) (params mldsa.Parameters, err error) {
	if pub == nil {
		return mldsa.Parameters{}, errors.New("ML-DSA public key must not be nil")
	}
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("invalid ML-DSA public key: %v", r)
		}
	}()
	// Deliberate panic probe: calling Parameters() panics if pub is &mldsa.PublicKey{}
	return pub.Parameters(), nil
}

// isMLDSAPublicKey reports whether pub is an ML-DSA public key.
func isMLDSAPublicKey(pub crypto.PublicKey) bool {
	_, ok := pub.(*mldsa.PublicKey)
	return ok
}

// validateMLDSAPublicKey checks that pub is a properly initialized ML-DSA
// public key.
func validateMLDSAPublicKey(pub crypto.PublicKey) error {
	mldsaKey, ok := pub.(*mldsa.PublicKey)
	if !ok {
		return errors.New("not an ML-DSA public key")
	}
	_, err := MLDSAPublicKeyParameters(mldsaKey)
	return err
}

// equalMLDSAKeys reports whether first equals second. It expects first to be
// an ML-DSA public key; callers should gate on isMLDSAPublicKey first.
func equalMLDSAKeys(first, second crypto.PublicKey) error {
	pub, ok := first.(*mldsa.PublicKey)
	if !ok {
		return errors.New("not an ML-DSA public key")
	}
	if _, err := MLDSAPublicKeyParameters(pub); err != nil {
		return err
	}
	if !pub.Equal(second) {
		return errors.New(genErrMsg(first, second, "mldsa"))
	}
	return nil
}
