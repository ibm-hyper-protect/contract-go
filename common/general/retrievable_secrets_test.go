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

package general

import (
	"encoding/base64"
	"encoding/binary"
	"os"
	"strings"
	"testing"
)

func testAddSecretRequest(version uint32) []byte {
	size := 1416
	if version == 0x200 {
		size = 2968
	}
	data := make([]byte, size)
	copy(data, "asrcbM")
	binary.BigEndian.PutUint32(data[8:12], version)
	binary.BigEndian.PutUint32(data[12:16], uint32(size))
	data[39] = 1
	binary.BigEndian.PutUint32(data[44:48], 32)
	return data
}

func TestAddSecretRequestStructure(t *testing.T) {
	for _, version := range []uint32{0x100, 0x200} {
		data := testAddSecretRequest(version)
		if err := validateAddSecretRequest(data); err != nil {
			t.Fatal(err)
		}
		for size := 0; size < len(data); size++ {
			if err := validateAddSecretRequest(data[:size]); err == nil {
				t.Fatalf("truncated request accepted at size %d", size)
			}
		}
	}
	for _, tc := range []struct {
		name string
		edit func([]byte) []byte
	}{
		{"magic", func(b []byte) []byte { b[0] = 0; return b }},
		{"version", func(b []byte) []byte { binary.BigEndian.PutUint32(b[8:12], 0x300); return b }},
		{"user data kind", func(b []byte) []byte { binary.BigEndian.PutUint16(b[6:8], 5); return b }},
		{"no key slots", func(b []byte) []byte { b[39] = 0; return b }},
		{"missing key slot data", func(b []byte) []byte { b[39] = 255; return b }},
		{"short confidential data", func(b []byte) []byte { binary.BigEndian.PutUint32(b[44:48], 31); return b }},
		{"confidential data overflow", func(b []byte) []byte { binary.BigEndian.PutUint32(b[44:48], 0xffffffff); return b }},
		{"length overflow", func(b []byte) []byte { binary.BigEndian.PutUint32(b[12:16], 0xffffffff); return b }},
		{"trailing bytes", func(b []byte) []byte { return append(b, 0) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateAddSecretRequest(tc.edit(testAddSecretRequest(0x100))); err == nil {
				t.Fatal("malformed request accepted")
			}
		})
	}
	// The documented 8190-byte limit is for the plaintext secret, not its request.
	large := append(testAddSecretRequest(0x100), make([]byte, 8192)...)
	binary.BigEndian.PutUint32(large[12:16], uint32(len(large)))
	if err := validateAddSecretRequest(large); err != nil {
		t.Fatalf("request larger than plaintext limit: %v", err)
	}
}

func FuzzAddSecretRequest(f *testing.F) {
	f.Add(testAddSecretRequest(0x100))
	f.Add(testAddSecretRequest(0x200))
	f.Add([]byte("asrcbM"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) { _ = validateAddSecretRequest(data) })
}

func FuzzRetrievableContractValidation(f *testing.F) {
	certificate, err := os.ReadFile(sampleEncryptionCertificate)
	if err != nil {
		f.Fatal(err)
	}
	encodedCert := base64.StdEncoding.EncodeToString(certificate)
	f.Add("type: env\nlogging:\n  logRouter:\n    hostname: logs.example.com\n    iamApiKey: test-only\nuv-secrets:\n  index-1:\n    type: pvsecret\n    pvsecret: " + base64.StdEncoding.EncodeToString(testAddSecretRequest(0x100)) + "\nhost-attestation:\n  HKD-9175-0271A28:\n    description: Test host\n    host-key-doc: " + encodedCert + "\nvolumes:\n  data:\n    uv-secret-id: index-1\n")
	f.Add("type: env\nuv-secrets: wrong\n")
	f.Add("type: env\nlogging: 42\n")
	f.Add("type: env\nlogging:\n  logRouter:\n    hostname: logs.example.com\n    iamApiKey: test\nenv:\n  FIRST: &variable_name SECOND\n  SECOND: 42\n  *variable_name: test\n")
	f.Add("type: env\nlogging:\n  logRouter:\n    hostname: logs.example.com\n    iamApiKey: test\nenv:\n  <<: &defaults\n    FIRST: original\n  FIRST: replacement\n")
	f.Add("type: env\nenv: &cycle\n  VALUE: *cycle\n")
	f.Add("type: env\nvolumes:\n  data:\n    uv-secret-id: index-1\n")
	f.Add("type: env\nuv-secrets:\n  index-1:\n    type: pvsecret\n    pvsecret: AAAA\n")
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 16384 || strings.Count(input, "\n") > 256 {
			t.Skip()
		}
		_ = VerifyContractWithSchema(input, ConfidentialComputingOsCcrv, "env")
	})
}

func FuzzRetrievableCertificateEncoding(f *testing.F) {
	certificate, err := os.ReadFile(sampleEncryptionCertificate)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(certificate)
	f.Add(append(append([]byte{}, certificate...), certificate...))
	f.Add([]byte("-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----\n"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 65536 {
			t.Skip()
		}
		encoded := base64.StdEncoding.EncodeToString(data)
		for _, maximum := range []int{1, 2} {
			_ = validateContractCertificates(encoded, "certificate", maximum)
		}
	})
}
