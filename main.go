package main

import (
	"fmt"

	F "github.com/IBM/fp-go/function"
	IOE "github.com/IBM/fp-go/ioeither"
	Arch "github.com/ibm-hyper-protect/contract-go/archive"
	Archive "github.com/ibm-hyper-protect/contract-go/archive/ioeither"

	"github.com/IBM/fp-go/ioeither/file"
)

func main() {
	// get the actual encryption functions to use (openssl or crypto)
	//	enc := Encrypt.DefaultEncryption()
	// build the encrypter for the contract
	// 	ctrEnc := Contract.DefaultEncryptAndSignContract(enc)
	// load the public key
	pubKey := file.ReadFile("Data/ibm-hyper-protect-container-runtime-1-0-s390x-2-encrypt.crt")
	// build the contract, start by creating a tgz of the compose file
	// instead of doing this manually we could also have a contract ready in yaml format and just encrypt it
	archive := F.Pipe2(
		Archive.CreateBase64Writer,
		Archive.TarFolder[*Arch.Base64Writer]("./samples/hello-world"),
		IOE.ChainEitherK((*Arch.Base64Writer).Close),
	)

	fmt.Printf("%v, %v", pubKey(), archive())
}
