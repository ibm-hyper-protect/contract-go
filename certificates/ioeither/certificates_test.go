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

package ioeither

import (
	"net/http"
	"testing"

	A "github.com/IBM/fp-go/array"
	E "github.com/IBM/fp-go/either"
	F "github.com/IBM/fp-go/function"
	IOE "github.com/IBM/fp-go/ioeither"
	IOEH "github.com/IBM/fp-go/ioeither/http"
	C "github.com/ibm-hyper-protect/contract-go/certificates"
	CE "github.com/ibm-hyper-protect/contract-go/certificates/either"
	"github.com/stretchr/testify/assert"
)

func TestDownloadCertificates(t *testing.T) {
	client := IOEH.MakeClient(http.DefaultClient)
	resolver := CE.ParseResolver(CE.DefaultTemplate)

	versions := A.From("1.0.11", "1.0.10")

	download := DownloadCertificates(client)(resolver)

	downloaded := F.Pipe3(
		versions,
		E.TraverseArray(CE.ParseVersion),
		E.Fold(IOE.Left[[]C.VersionCert, error], download),
		IOE.Map[error](A.Map(F.Flow2(
			C.GetVersion,
			C.Version.String,
		))),
	)

	result := downloaded()

	assert.Equal(t, E.Of[error](versions), result)
}
