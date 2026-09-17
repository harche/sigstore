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
	"testing"

	v1 "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
)

// When built with Go < 1.27, ML-DSA algorithms must not be registered.
func TestMLDSAUnsupported(t *testing.T) {
	for _, alg := range []v1.PublicKeyDetails{
		v1.PublicKeyDetails_ML_DSA_44,
		v1.PublicKeyDetails_ML_DSA_65,
		v1.PublicKeyDetails_ML_DSA_87,
	} {
		if _, err := GetAlgorithmDetails(alg); err == nil {
			t.Errorf("expected error getting algorithm details for %s", alg)
		}
		if _, err := FormatSignatureAlgorithmFlag(alg); err == nil {
			t.Errorf("expected error formatting flag for %s", alg)
		}
	}
	for _, flag := range []string{"mldsa-44", "mldsa-65", "mldsa-87"} {
		if _, err := ParseSignatureAlgorithmFlag(flag); err == nil {
			t.Errorf("expected error parsing flag %s", flag)
		}
	}
	if _, err := NewAlgorithmRegistryConfig([]v1.PublicKeyDetails{v1.PublicKeyDetails_ML_DSA_65}); err == nil {
		t.Errorf("expected error creating registry config with ML-DSA")
	}
}
