// Copyright 2023 IBM Corp.
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
// limitations under the License.package datasource

package either

import (
	"testing"

	E "github.com/IBM/fp-go/either"
	F "github.com/IBM/fp-go/function"
	C "github.com/ibm-hyper-protect/contract-go/certificates"
	"github.com/stretchr/testify/assert"
)

func TestCertificateFromSpec(t *testing.T) {
	certs := map[string]string{
		"1.0.10": "cert 1.0.10",
		"1.0.11": "cert 1.0.11",
		"1.0.9":  "cert 1.0.9",
	}
	result := F.Pipe4(
		ParseConstraint("^1.0.0"),
		E.Map[error](CertificateFromSpec),
		E.Flap[error, E.Either[error, C.VersionCert]](certs),
		E.Flatten[error, C.VersionCert],
		E.Map[error](F.Flow2(
			C.GetVersion,
			C.Version.String,
		)),
	)

	assert.Equal(t, E.Of[error]("1.0.11"), result)
}

func TestResolver(t *testing.T) {
	resolver := ParseResolver(DefaultTemplate)
	version := ParseVersion("1.0.11")

	res := F.Pipe1(
		version,
		E.Chain(resolver),
	)

	assert.Equal(t, E.Of[error]("https://cloud.ibm.com/media/docs/downloads/hyper-protect-container-runtime/ibm-hyper-protect-container-runtime-1-0-s390x-11-encrypt.crt"), res)
}
