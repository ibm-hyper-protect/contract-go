# Contract Go

[![contract-go CI](https://github.com/ibm-hyper-protect/contract-go/actions/workflows/build.yml/badge.svg)](https://github.com/ibm-hyper-protect/contract-go/actions/workflows/build.yml)
[![Latest Release](https://img.shields.io/github/v/release/ibm-hyper-protect/contract-go?include_prereleases)](https://github.com/ibm-hyper-protect/contract-go/releases/latest)
[![Go Report Card](https://goreportcard.com/badge/github.com/ibm-hyper-protect/contract-go)](https://goreportcard.com/report/ibm-hyper-protect/contract-go)
[![Go Reference](https://pkg.go.dev/badge/github.com/ibm-hyper-protect/contract-go.svg)](https://pkg.go.dev/github.com/ibm-hyper-protect/contract-go)


## Introduction

The library is developed to automate the process of provisioning Hyper Protect Virtual Servers (HPVS) on both IBM Cloud and on prem.

For more information on HPVS for VPC and Hyper Protect Container Runtime (HPCR), see [Confidential computing with LinuxONE](https://cloud.ibm.com/docs/vpc?topic=vpc-about-se) and [IBM Hyper Protect Virtual Servers](https://www.ibm.com/docs/en/hpvs/2.2.x).


## Features

1. Decrypt the encrypted attestation records.
2. Download the encryption certificates from IBM Cloud docs.
<!-- Should we link to the Cloud docs - specific topic? -->
3. Get a specific encryption certificate from the encryption certificates JSON that is downloaded.
<!-- encryption certificates JSON - is this the name o the JSON file? Should we write it as is in the name of the file? -->
4. Generate `Base64` of a string.
5. Validate the schema of an unencrypted contract.
6. Generate IBM Hyper Protect encrypted string.
7. Generate IBM Hyper Protect signed and encrypted contract (With and without contract expiry).
8. Generate `Base64` tar of `docker-compose.yaml` or `pods.yaml`.
9. Get the latest HPCR Image from IBM Cloud Image JSON data.
<!-- IBM Cloud Image JSON - should we mention the exact file name here? -->

## Usage

See the [docs](docs/README.md) for more information on how to use this library for your use cases.


## References

- [contract-cli](https://github.com/ibm-hyper-protect/contract-cli) - CLI tool for generating Hyper Protect contracts (uses contract-go)
- [terraform-provider-hpcr](https://github.com/ibm-hyper-protect/terraform-provider-hpcr) - Terraform Provider for generating Hyper Protect contracts
- [k8s-operator-hpcr](https://github.com/ibm-hyper-protect/k8s-operator-hpcr) - Kubernetes operator for generating Hyper Protect contracts
- [linuxone-vsi-automation-samples - hpvs](https://github.com/ibm-hyper-protect/linuxone-vsi-automation-samples/tree/master/terraform-hpvs) - Terraform examples to provision HPVS
- [linuxone-vsi-automation-samples - hpcr-rhvs](https://github.com/ibm-hyper-protect/linuxone-vsi-automation-samples/tree/master/terraform-hpcr-rhvs) - Terraform examples to provision HPCR RHVS
- [hyper-protect-virtual-server-samples](https://github.com/ibm-hyper-protect/hyper-protect-virtual-server-samples) - HPVS scripts for different features


## Contributors

![Contributors](https://contrib.rocks/image?repo=ibm-hyper-protect/contract-go)
