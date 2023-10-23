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

package ioeither

import (
	"fmt"

	E "github.com/IBM/fp-go/either"
	F "github.com/IBM/fp-go/function"
	IOE "github.com/IBM/fp-go/ioeither"
	T "github.com/IBM/fp-go/tuple"
	Common "github.com/ibm-hyper-protect/contract-go/common"
	EC "github.com/ibm-hyper-protect/contract-go/encrypt/common"
)

const (
	saltlen    = 8
	keylen     = 32 // 32 is being used because we use aes-256-cbc for the symmetric encryption and 256/8 = 32
	iterations = 10000
)

// EncryptBasic implements the basic encryption operations
func EncryptBasic(
	genPwd IOE.IOEither[error, []byte],
	asymmEncrypt func([]byte) IOE.IOEither[error, string],
	symmEncrypt EncryptBasicFunc,
) func([]byte) IOE.IOEither[error, string] {

	return func(data []byte) IOE.IOEither[error, string] {
		// encrypt data
		encrypter := symmEncrypt(data)
		// generate the password
		return F.Pipe1(
			genPwd,
			IOE.Chain(func(pwd []byte) IOE.IOEither[error, string] {
				// encode the password
				encPwd := F.Pipe1(
					pwd,
					asymmEncrypt,
				)
				// encode the data
				encData := F.Pipe1(
					pwd,
					encrypter,
				)
				// combine
				return F.Pipe1(
					IOE.SequenceT2(encPwd, encData),
					IOE.Map[error](T.Tupled2(func(pwd string, token string) string {
						return fmt.Sprintf("%s.%s.%s", Common.PrefixBasicEncoding, pwd, token)
					})),
				)
			}),
		)
	}
}

// DecryptBasic implements the basic decryption operations
func DecryptBasic(
	asymmDecrypt func(string) IOE.IOEither[error, []byte],
	symmDecrypt func(string) func([]byte) IOE.IOEither[error, []byte],
) func(string) IOE.IOEither[error, []byte] {

	return func(data string) IOE.IOEither[error, []byte] {
		// split the string
		splitE := F.Pipe1(
			data,
			EC.SplitHyperProtectToken,
		)
		// get password
		pwdIOE := F.Pipe3(
			splitE,
			E.Map[error](EC.GetPwd),
			IOE.FromEither[error, string],
			IOE.Chain(asymmDecrypt),
		)

		// get the token
		return F.Pipe5(
			splitE,
			E.Map[error](EC.GetToken),
			E.Map[error](symmDecrypt),
			IOE.FromEither[error, func([]byte) IOE.IOEither[error, []byte]],
			IOE.Ap[IOE.IOEither[error, []byte]](pwdIOE),
			IOE.Flatten[error, []byte],
		)
	}
}
