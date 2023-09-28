package common

import (
	"fmt"
	"regexp"

	E "github.com/IBM/fp-go/either"
	T "github.com/IBM/fp-go/tuple"
)

var (
	// regular expression used to split the token
	tokenRe = regexp.MustCompile(`^hyper-protect-basic\.((?:[A-Za-z\d+/]{4})*(?:[A-Za-z\d+/]{3}=|[A-Za-z\d+/]{2}==)?)\.((?:[A-Za-z\d+/]{4})*(?:[A-Za-z\d+/]{3}=|[A-Za-z\d+/]{2}==)?)$`)

	errNoMatch = E.Left[SplitToken](fmt.Errorf("token does not match the specification"))

	GetPwd   = T.First[string, string]
	GetToken = T.Second[string, string]

	// IsHyperProtectBasic tests if a string is a hyper protect token
	IsHyperProtectBasic = tokenRe.MatchString
)

type SplitToken = T.Tuple2[string, string]

func SplitHyperProtectToken(token string) E.Either[error, SplitToken] {
	all := tokenRe.FindAllStringSubmatch(token, -1)
	if all == nil {
		return errNoMatch
	}
	match := all[0]
	return E.Of[error](T.MakeTuple2(match[1], match[2]))
}
