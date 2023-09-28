# Contract Go

Utility functions to encrypt and decrypt an [Hyper Protect Container Runtime](https://cloud.ibm.com/docs/vpc?topic=vpc-about-contract_se) contract.

## Usage

Refer to `main.go` for an example

## Design

The API design is based on functional and monadic interfaces exposed by the [fp-go](https://pkg.go.dev/github.com/IBM/fp-go/) library.

### Error Handling

Functions that can produce an error return an [Either](https://pkg.go.dev/github.com/IBM/fp-go/either#Either) instead of the idiomatic golang tuple, because an [Either](https://pkg.go.dev/github.com/IBM/fp-go/either#Either) can be used in functiona composition but the tuple cannot.

### Side Effects

Functions with side effects are represented as [IOEither](https://pkg.go.dev/github.com/IBM/fp-go/ioeither#IOEither), i.e. the actual execution of the side effect is deferred until the function gets executed

### Idiomatic golang style

- [Either](https://pkg.go.dev/github.com/IBM/fp-go/either#Either): to convert a function returning [Either](https://pkg.go.dev/github.com/IBM/fp-go/either#Either) to a function in golang style, call `Either.UneitherizeXXX`

## References

- [contract-schema](https://github.com/ibm-hyper-protect/contract-schema) - JSON schema for the contract
- [fp-go](https://github.com/IBM/fp-go) - implementation of the functional programming layer
