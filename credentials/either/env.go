package either

import (
	"fmt"
	"net/url"
	"strings"

	RA "github.com/IBM/fp-go/array"
	E "github.com/IBM/fp-go/either"
	"github.com/IBM/fp-go/errors"
	F "github.com/IBM/fp-go/function"
	O "github.com/IBM/fp-go/option"
	RR "github.com/IBM/fp-go/record"
	S "github.com/IBM/fp-go/string"
	T "github.com/IBM/fp-go/tuple"
	C "github.com/ibm-hyper-protect/contract-go/credentials"

	"github.com/iancoleman/strcase"
)

var (
	intercalateS = RA.Intercalate(S.Monoid)
	parseUrl     = E.Eitherize1(url.Parse)
)

const (
	suffixUsername = "USERNAME"
	suffixPassword = "PASSWORD"
)

func resolveSimple(env map[string]string) func(segments []string) O.Option[C.Credential] {

	lookupSuffix := func(suffix string) func(string) O.Option[string] {
		return func(key string) O.Option[string] {
			return RR.Lookup[string](fmt.Sprintf("%s_%s", key, suffix))(env)
		}
	}

	lookupUsername := lookupSuffix(suffixUsername)
	lookupPassword := lookupSuffix(suffixPassword)

	lookup := func(key string) O.Option[T.Tuple2[string, string]] {
		return O.SequenceT2(lookupUsername(key), lookupPassword(key))
	}

	var resolve func([]string) O.Option[C.Credential]

	resolve = func(segments []string) O.Option[C.Credential] {
		return F.Pipe4(
			segments,
			O.FromPredicate(RA.IsNonEmpty[string]),
			O.Map(intercalateS(" ")),
			O.Map(strcase.ToScreamingSnake),
			O.Chain(F.Flow3(
				lookup,
				O.Map(C.FromTuple),
				O.Alt(func() O.Option[C.Credential] {
					return resolve(segments[:len(segments)-1])
				}),
			)),
		)
	}

	return resolve
}

func segmentsFromUrl(u *url.URL) []string {
	// split the path
	return RA.ArrayConcatAll(RA.Of(u.Hostname()), strings.Split(u.Path, "/"))
}

// ResolveCredential resolves the credentials for accessing a URL based on an environment map
//
// The key into the service needs to be a URL. The implementation will convert the URL into [constant case](https://www.npmjs.com/package/constant-case) and then tries to find environment
// variables with the suffix `_USERNAME` and `_PASSWORD`. It will fallback for the complete path up to the hostname. So to provide credentials
// in the environment for the URL `https://eu.artifactory.swg-devops.com/artifactory/api/npm/sys-zaas-team-dev-npm-virtual/` you can specify
//
//	```text
//	EU_ARTIFACTORY_SWG_DEVOPS_COM_USERNAME=XXX
//	EU_ARTIFACTORY_SWG_DEVOPS_COM_PASSWORD=YYY
//	```
//
//	as environment variables. The complete fallback path for the example is:
//
//	```text
//	EU_ARTIFACTORY_SWG_DEVOPS_COM_ARTIFACTORY_API_NPM_SYS_ZAAS_TEAM_DEV_NPM_VIRTUAL_USERNAME
//	EU_ARTIFACTORY_SWG_DEVOPS_COM_ARTIFACTORY_API_NPM_USERNAME
//	EU_ARTIFACTORY_SWG_DEVOPS_COM_ARTIFACTORY_API_USERNAME
//	EU_ARTIFACTORY_SWG_DEVOPS_COM_ARTIFACTORY_USERNAME
//	EU_ARTIFACTORY_SWG_DEVOPS_COM_USERNAME
func ResolveCredential(env map[string]string) func(string) E.Either[error, C.Credential] {

	simple := resolveSimple(env)

	return func(url string) E.Either[error, C.Credential] {
		// parse the URL
		return F.Pipe3(
			url,
			parseUrl,
			E.Map[error](F.Flow2(
				segmentsFromUrl,
				RA.Filter(S.IsNonEmpty),
			)),
			E.ChainOptionK[[]string, C.Credential](errors.OnNone("unable to resolve credentials for [%s]", url))(simple),
		)
	}

}
