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

package decrypt

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestDecryptWorkloadRejectsUnsupportedOpenSSLBeforeUse(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test executable uses a POSIX shell")
	}
	fixtures := map[int]string{
		8:  "U2FsdGVkX18BAgMEBQYHCJThSnnJ3H5P6QPGNkfE2/BRZflMgTs9ZFEJbZ76PNMK",
		16: "U2FsdGVkX18BAgMEBQYHCAkKCwwNDg8QJIIz/tqXgTZx7dzAXswGzqoRNyDMsJ1PZgNYUim1UQw=",
	}
	for _, tc := range []struct {
		name, help, expected string
		salt                 int
	}{
		{"PBKDF2 unavailable", "Usage: enc\n -saltlen bytes\n", "-pbkdf2", 8},
		{"long salts unavailable", "Usage: enc\n -pbkdf2 derive key\n", "16-byte salts require OpenSSL 3.2+", 16},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			executable, marker := filepath.Join(dir, "openssl"), filepath.Join(dir, "decryption-attempted")
			script := "#!/bin/sh\n" +
				"if [ \"$1\" = version ]; then printf 'OpenSSL test executable\\n'; exit 0; fi\n" +
				"if [ \"$1\" = enc ] && [ \"$2\" = -help ]; then printf '%s\\n' \"$CONTRACT_TEST_OPENSSL_HELP\" >&2; exit 0; fi\n" +
				"printf called > \"$CONTRACT_TEST_OPENSSL_MARKER\"\nexit 99\n"
			if err := os.WriteFile(executable, []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("OPENSSL_BIN", executable)
			t.Setenv("CONTRACT_TEST_OPENSSL_HELP", tc.help)
			t.Setenv("CONTRACT_TEST_OPENSSL_MARKER", marker)
			clear, err := DecryptWorkload("test-password", fixtures[tc.salt])
			if clear != "" || err == nil || !strings.Contains(err.Error(), "OPENSSL_UNSUPPORTED_FEATURE") || !strings.Contains(err.Error(), tc.expected) {
				t.Fatalf("expected actionable capability error, got %q, %v", clear, err)
			}
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatal("unsupported decryption was attempted")
			}
			if strings.Contains(err.Error(), "test-password") || strings.Contains(err.Error(), fixtures[tc.salt]) {
				t.Fatal("capability error exposed confidential input")
			}
		})
	}
}
