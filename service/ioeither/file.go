/*
 * =============================================================================================
 * IBM Confidential
 * © Copyright IBM Corp. 2023
 * The source code for this program is not published or otherwise divested of its trade secrets,
 * irrespective of what has been deposited with the U.S. Copyright Office.
 * =============================================================================================
 */

package ioeither

import (
	F "github.com/IBM/fp-go/function"
	IOE "github.com/IBM/fp-go/ioeither"
	"github.com/IBM/fp-go/ioeither/file"
	SE "github.com/ibm-hyper-protect/contract-go/service/either"
)

var (
	// ReadContract reads a contract document from a YAML file, parses and validates it
	// and returns it as a strongly typed data structure
	ReadContract = F.Flow2(
		file.ReadFile,
		IOE.ChainEitherK(SE.ParseAndValidateContract),
	)
)
