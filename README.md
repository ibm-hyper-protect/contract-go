Utility functions to encrypt and decrypt an HPCR contract.

## Usage

Refer to `main.go` for an example

## Design

The API design is based on functional and monadic interfaces exposed by the [fp-go](https://github.ibm.com/ZaaS/hpse-fp-go) library.

### Error Handling

Functions that can produce an error return an [Either](https://github.ibm.com/ZaaS/hpse-fp-go/tree/master/Either) instead of the idiomatic golang tuple, because an [Either](https://github.ibm.com/ZaaS/hpse-fp-go/tree/master/Either) can be used in functiona composition but the tuple cannot.

### Side Effects

Functions with side effects are represented as [IOEither](https://github.ibm.com/ZaaS/hpse-fp-go/tree/master/IOEither), i.e. the actual execution of the side effect is deferred until the function gets executed


### Idiomatic golang style:

- [Either](https://github.ibm.com/ZaaS/hpse-fp-go/tree/master/Either): to convert a function returning [Either](https://github.ibm.com/ZaaS/hpse-fp-go/tree/master/Either) to a function in golang style, call `Either.UneitherizeXXX`


## Build Setup

[![Build Status](https://sys-zaas-hp-jenkins.swg-devops.com/buildStatus/icon?job=hpse%2Fhpse_cd%2Fhpse-contract-go%2Fmaster)](https://sys-zaas-hp-jenkins.swg-devops.com/job/hpse/job/hpse_cd/job/hpse-contract-go/job/master/)

## References

- [hpcr-contract](https://github.ibm.com/ZaaS/hpha-se-contract-schema) - documentation of the contract
- [hpse-fp-go](https://github.ibm.com/ZaaS/hpse-fp-go) - implementation of the functional programming layer

## Local Development

Please refer to [hpse-use-private-module-go](https://github.ibm.com/ZaaS/hpse-use-private-module-go) as an example of how to setup you local development environment to use this module.
