package credentials

import (
	T "github.com/IBM/fp-go/tuple"
)

type (
	Credential struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
)

// CreateCredential creates a credential data structure
func CreateCredential(username, password string) Credential {
	return Credential{Username: username, Password: password}
}

// FromTuple creates a credential from a tuple
var FromTuple = T.Tupled2(CreateCredential)
