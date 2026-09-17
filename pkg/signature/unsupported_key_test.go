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
	"strings"
	"testing"
)

type unsupportedTestKey struct{}

// Keys of an unknown type must be rejected by every loader, regardless of
// which optional algorithms are compiled in.
func TestLoadUnsupportedKeyType(t *testing.T) {
	key := unsupportedTestKey{}

	if _, err := LoadSigner(key, crypto.SHA256); err == nil || !strings.Contains(err.Error(), "unsupported private key type") {
		t.Errorf("LoadSigner: expected unsupported private key type error, got %v", err)
	}
	if _, err := LoadSignerVerifier(key, crypto.SHA256); err == nil || !strings.Contains(err.Error(), "unsupported public key type") {
		t.Errorf("LoadSignerVerifier: expected unsupported public key type error, got %v", err)
	}
	if _, err := LoadVerifier(key, crypto.SHA256); err == nil || !strings.Contains(err.Error(), "unsupported public key type") {
		t.Errorf("LoadVerifier: expected unsupported public key type error, got %v", err)
	}
	if _, err := LoadUnsafeVerifier(key); err == nil || !strings.Contains(err.Error(), "unsupported public key type") {
		t.Errorf("LoadUnsafeVerifier: expected unsupported public key type error, got %v", err)
	}
	if _, err := GetDefaultPublicKeyDetails(key); err == nil || !strings.Contains(err.Error(), "unsupported public key type") {
		t.Errorf("GetDefaultPublicKeyDetails: expected unsupported public key type error, got %v", err)
	}
	if _, err := GetDefaultAlgorithmDetails(key); err == nil {
		t.Errorf("GetDefaultAlgorithmDetails: expected error for unsupported key type")
	}
}
