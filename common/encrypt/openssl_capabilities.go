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
	"errors"
	"fmt"
	"os/exec"
	"strings"

	gen "github.com/ibm-hyper-protect/contract-go/v3/common/general"
)

// RequireOpenSSLEncOptions checks the configured executable's actual enc options.
// It does not rely on a version string or retry with weaker encryption options.
//
// Parameters:
//   - options: Required enc option names, such as -pbkdf2 or -saltlen.
//
// Returns:
//   - nil if every required option is advertised by recognized help output.
//   - An actionable unsupported-feature or capability-check error otherwise.
func RequireOpenSSLEncOptions(options ...string) error {
	if len(options) == 0 {
		return nil
	}
	help, err := exec.Command(gen.GetOpenSSLPath(), "enc", "-help").CombinedOutput()
	if err != nil {
		// Compatible tools such as macOS LibreSSL return status 1 for help.
		// Accept that documented usage shape, not arbitrary failed output.
		var exitError *exec.ExitError
		if !errors.As(err, &exitError) || exitError.ExitCode() != 1 || !strings.Contains(strings.ToLower(string(help)), "usage: enc ") {
			return fmt.Errorf("OPENSSL_CAPABILITY_CHECK_FAILED: cannot inspect enc options; configure a working executable with OPENSSL_BIN - %v", err)
		}
	}
	supported := make(map[string]bool)
	for _, token := range strings.Fields(string(help)) {
		supported[token] = true
	}
	for _, option := range options {
		if !supported[option] {
			hint := "use a compatible OpenSSL build or set OPENSSL_BIN"
			if option == "-saltlen" {
				hint = "16-byte salts require OpenSSL 3.2+ with -saltlen; upgrade or set OPENSSL_BIN"
			}
			return fmt.Errorf("OPENSSL_UNSUPPORTED_FEATURE: enc requires %s; %s", option, hint)
		}
	}
	return nil
}
