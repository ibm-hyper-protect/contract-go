package ioeither

import (
	"testing"

	E "github.com/IBM/fp-go/either"
	F "github.com/IBM/fp-go/function"
	IOE "github.com/IBM/fp-go/ioeither"
	RR "github.com/IBM/fp-go/record"
	"github.com/stretchr/testify/assert"
)

func TestFomFolder(t *testing.T) {
	res := F.Pipe2(
		"../../samples/tar/sample1",
		FromFolder,
		IOE.Map[error](F.Flow2(
			RR.Keys[string, []byte],
			func(values []string) bool {
				return assert.Contains(t, values, "var/hyperprotect/cidata.decrypted.yml")
			},
		)),
	)
	assert.Equal(t, E.Of[error](true), res())
}
