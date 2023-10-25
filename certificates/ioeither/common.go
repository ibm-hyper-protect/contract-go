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

	F "github.com/IBM/fp-go/function"
	IOE "github.com/IBM/fp-go/ioeither"
)

var (
	// MakeRequest is an eitherized version of [http.NewRequest]
	makeRequest = F.Bind13of3(IOE.Eitherize3(http.NewRequest))

	// specialize
	makeGetRequest = makeRequest("GET", nil)
)
