# Contract Go

[![Go Reference](https://pkg.go.dev/badge/github.com/ibm-hyper-protect/contract-go.svg)](https://pkg.go.dev/github.com/ibm-hyper-protect/contract-go)
[![contract-go CI](https://github.com/ibm-hyper-protect/contract-go/actions/workflows/build.yml/badge.svg)](https://github.com/ibm-hyper-protect/contract-go/actions/workflows/build.yml)


## Introduction

The library has been developed to automate the process of provisioning HPVS on both IBM Cloud and On Prem.

For more details on Hyper Protect Virtual Servers for VPC and Hyper Protect Container Runtime, refer [Confidential computing with LinuxONE](https://cloud.ibm.com/docs/vpc?topic=vpc-about-se) and [IBM Hyper Protect Virtual Servers](https://www.ibm.com/docs/en/hpvs/2.2.x).

## Features

1. Decrypt encrypted attestation records.
2. Download encryption certificates from IBM Cloud docs.
3. Generate Base64 of a string.
4. Generate IBM Hyper Protect encrypted string.
5. Generate IBM Hyper Protect signed and encrypted contract (With and without contract expiry).
6. Generate Base64 tar of `docker-compose.yaml` or `pods.yaml`.

## Usage

Refer [Docs](docs/index.md) for more details on how to leverage this library for your usecases.


## References

- [contract-cli](https://github.com/ibm-hyper-protect/contract-cli) - CLI tool for generating Hyper Protect contracts
- [terraform-provider-hpcr](https://github.com/ibm-hyper-protect/terraform-provider-hpcr) - Terraform Provider for generating Hyper Protect contracts
- [k8s-operator-hpcr](https://github.com/ibm-hyper-protect/k8s-operator-hpcr) - Kubernetes operator for generating Hyper Protect contracts
