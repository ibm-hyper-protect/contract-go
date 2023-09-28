// Copyright 2023 IBM Corp.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package common

import (
	F "github.com/IBM/fp-go/function"
	IO "github.com/IBM/fp-go/io"
	IOO "github.com/IBM/fp-go/iooption"
	S "github.com/IBM/fp-go/string"
	T "github.com/IBM/fp-go/tuple"
	CIOO "github.com/ibm-hyper-protect/contract-go/common/iooption"
)

type (
	// OpenSSLVersion represents the openSSL version, including the path to the binary
	OpenSSLVersion = T.Tuple2[string, string]
)

var (
	// name of the environment variable carrying the openSSL binary
	KeyEnvOpenSSL = "OPENSSL_BIN"

	// default name of the openSSL binary
	DefaultOpenSSL = "openssl"

	GetPath    = T.First[string, string]
	GetVersion = T.Second[string, string]

	// tests if a string contains "OpenSSL"
	IncludesOpenSSL = S.Includes("OpenSSL")

	// name of the open SSL binary either from the environment or a fallback
	OpenSSLBinary = F.Pipe2(
		KeyEnvOpenSSL,
		CIOO.LookupEnv,
		IOO.Fold(F.Constant(IO.Of(DefaultOpenSSL)), IO.Of[string]),
	)
)
