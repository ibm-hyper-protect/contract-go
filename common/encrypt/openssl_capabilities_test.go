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

package encrypt

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func capabilityTestOpenSSL(t *testing.T, help, helpExit string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("test executable uses a POSIX shell")
	}
	dir := t.TempDir()
	executable := filepath.Join(dir, "openssl")
	marker := filepath.Join(dir, "cipher-command-ran")
	script := "#!/bin/sh\n" +
		"if [ \"$1\" = version ]; then printf 'OpenSSL test executable\\n'; exit 0; fi\n" +
		"if [ \"$1\" = enc ] && [ \"$2\" = -help ]; then printf '%s\\n' \"$CONTRACT_TEST_OPENSSL_HELP\" >&2; exit \"$CONTRACT_TEST_OPENSSL_HELP_EXIT\"; fi\n" +
		"printf called > \"$CONTRACT_TEST_OPENSSL_MARKER\"\nexit 99\n"
	if err := os.WriteFile(executable, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OPENSSL_BIN", executable)
	t.Setenv("CONTRACT_TEST_OPENSSL_HELP", help)
	t.Setenv("CONTRACT_TEST_OPENSSL_HELP_EXIT", helpExit)
	t.Setenv("CONTRACT_TEST_OPENSSL_MARKER", marker)
	return marker
}

func TestOpenSSLEncCapabilityChecks(t *testing.T) {
	for _, tc := range []struct {
		name, help, exit, expected string
	}{
		{"supported", "Usage: enc\n -pbkdf2 use PBKDF2\n -saltlen bytes\n", "0", ""},
		{"compatible help status one", "usage: enc [options]\n -pbkdf2 use PBKDF2\n -saltlen bytes\n", "1", ""},
		{"missing PBKDF2", "Usage: enc\n -saltlen bytes\n", "0", "OPENSSL_UNSUPPORTED_FEATURE: enc requires -pbkdf2"},
		{"missing salt length", "Usage: enc\n -pbkdf2 use PBKDF2\n", "0", "16-byte salts require OpenSSL 3.2+"},
		{"compatible build without salt length", "usage: enc [options]\n -pbkdf2 use PBKDF2\n", "1", "16-byte salts require OpenSSL 3.2+"},
		{"partial option names", " -pbkdf2-disabled\n -saltlen-disabled\n", "0", "OPENSSL_UNSUPPORTED_FEATURE"},
		{"help fails despite output", " -pbkdf2\n -saltlen\n", "1", "OPENSSL_CAPABILITY_CHECK_FAILED"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			marker := capabilityTestOpenSSL(t, tc.help, tc.exit)
			err := RequireOpenSSLEncOptions("-pbkdf2", "-saltlen")
			if tc.expected == "" && err != nil || tc.expected != "" && (err == nil || !strings.Contains(err.Error(), tc.expected)) {
				t.Fatalf("expected %q, got %v", tc.expected, err)
			}
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatal("capability inspection attempted a cipher operation")
			}
		})
	}
}

func TestEncryptStringRejectsUnsupportedPBKDF2BeforeUse(t *testing.T) {
	marker := capabilityTestOpenSSL(t, "Usage: enc\n -saltlen bytes\n", "0")
	result, err := EncryptString("test-password", "  private payload  \n")
	if result != "" || err == nil || !strings.Contains(err.Error(), "OPENSSL_UNSUPPORTED_FEATURE") || !strings.Contains(err.Error(), "-pbkdf2") {
		t.Fatalf("unsupported encryption did not fail clearly: %q, %v", result, err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("unsupported encryption was attempted")
	}
	if strings.Contains(err.Error(), "test-password") || strings.Contains(err.Error(), "private payload") {
		t.Fatal("capability error exposed confidential input")
	}
}
