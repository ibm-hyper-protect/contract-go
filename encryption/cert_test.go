// Copyright (c) 2026 IBM Corp.
// All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package encryption

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Testcase to check that CCCO keeps exactly three mod release certs (n, n-1, n-2)
func TestCccoModReleaseWindow(t *testing.T) {
	assert.Len(t, CccoReleases, 3)
	for _, r := range CccoReleases {
		assert.NotEmpty(t, CertificateMap[OsTypeCcco][r.Mod], "missing cert for mod %s", r.Mod)
	}
}

// Testcase to check that fixpack versions share the parent mod cert
func TestCccoFixpackSharesParentCert(t *testing.T) {
	parent := CertificateMap[OsTypeCcco]["1.2.2"]
	assert.NotEmpty(t, parent)
	assert.Equal(t, parent, CertificateMap[OsTypeCcco]["1.2.2.1"])
	assert.Equal(t, parent, CertificateMap[OsTypeCcco]["1.2.2.2"])
}

// Testcase to check that undeclared and legacy date-based versions are rejected
func TestCccoUndeclaredVersionsRejected(t *testing.T) {
	for _, v := range []string{"1.2.2.3", "1.2.3", "26.7.1", "26.4.0", "25.12.0"} {
		_, ok := CertificateMap[OsTypeCcco][v]
		assert.False(t, ok, "version %s should not be accepted", v)
	}
}

// Testcase to check that the latest CCCO cert is the newest mod release cert
func TestCccoLatestCertIsNewestMod(t *testing.T) {
	assert.Equal(t, CertificateMap[OsTypeCcco]["1.2.2"], LatestEncryptionCertificateCcco)
}

// Testcase to check that release-map entries are well formed: fixpacks (x.x.x.x) belong to their parent mod (x.x.x)
func TestCccoReleaseMapWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range CccoReleases {
		assert.Len(t, strings.Split(r.Mod, "."), 3, "mod %s must be x.x.x", r.Mod)
		assert.False(t, seen[r.Mod], "duplicate version %s", r.Mod)
		seen[r.Mod] = true
		for _, fp := range r.Fixpacks {
			assert.Len(t, strings.Split(fp, "."), 4, "fixpack %s must be x.x.x.x", fp)
			assert.True(t, strings.HasPrefix(fp, r.Mod+"."), "fixpack %s must belong to mod %s", fp, r.Mod)
			assert.False(t, seen[fp], "duplicate version %s", fp)
			seen[fp] = true
		}
	}
}

// Testcase to check that mod releases carry distinct certificates
func TestCccoModCertsAreDistinct(t *testing.T) {
	assert.NotEqual(t, CertificateMap[OsTypeCcco]["1.2.1"], CertificateMap[OsTypeCcco]["1.2.2"])
}
