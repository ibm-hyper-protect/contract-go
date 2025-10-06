# Contract Go

[![contract-go CI](https://github.com/ibm-hyper-protect/contract-go/actions/workflows/build.yml/badge.svg)](https://github.com/ibm-hyper-protect/contract-go/actions/workflows/build.yml)
[![Latest Release](https://img.shields.io/github/v/release/ibm-hyper-protect/contract-go?include_prereleases)](https://github.com/ibm-hyper-protect/contract-go/releases/latest)
[![Go Report Card](https://goreportcard.com/badge/github.com/ibm-hyper-protect/contract-go)](https://goreportcard.com/report/ibm-hyper-protect/contract-go)
[![Go Reference](https://pkg.go.dev/badge/github.com/ibm-hyper-protect/contract-go.svg)](https://pkg.go.dev/github.com/ibm-hyper-protect/contract-go)


## Introduction

The library has been developed to automate the process of provisioning Hyper Protect Virtual Servers (HPVS) and Hyper Protect Container Runtime for RedHat Virtualization solutions (HPCR RHVS).

For more details on Hyper Protect Virtual Servers for VPC and Hyper Protect Container Runtime, refer [Confidential computing with LinuxONE](https://cloud.ibm.com/docs/vpc?topic=vpc-about-se) and [IBM Hyper Protect Virtual Servers](https://www.ibm.com/docs/en/hpvs/2.2.x).


## Features

1. Decrypt encrypted attestation records.
2. Download encryption certificates from IBM Cloud docs.
3. Get specific encryption certificate from encryption certificates JSON downloaded.
4. Generate Base64 of a string.
5. Validate schema of unencrypted contract.
6. Generate IBM Hyper Protect encrypted string.
7. Generate IBM Hyper Protect signed and encrypted contract (With and without contract expiry).
8. Generate Base64 tar of `docker-compose.yaml` or `pods.yaml`.
9. Get latest HPCR Image from IBM Cloud Image JSON data.
10. Validate schema of network-config (for on-prem environment) for HPVS and HPCR RHVS.

## Usage

Refer [Contract-Go docs](https://ibm-hyper-protect.github.io/contract-go) for more details on how to leverage this library for your usecases.


## References

- [contract-cli](https://github.com/ibm-hyper-protect/contract-cli) - CLI tool for generating Hyper Protect contracts (leverages contract-go)
- [terraform-provider-hpcr](https://github.com/ibm-hyper-protect/terraform-provider-hpcr) - Terraform Provider for generating Hyper Protect contracts
- [k8s-operator-hpcr](https://github.com/ibm-hyper-protect/k8s-operator-hpcr) - Kubernetes operator for generating Hyper Protect contracts
- [linuxone-vsi-automation-samples - hpvs](https://github.com/ibm-hyper-protect/linuxone-vsi-automation-samples/tree/master/terraform-hpvs) - Terraform examples to provision HPVS
- [linuxone-vsi-automation-samples - hpcr-rhvs](https://github.com/ibm-hyper-protect/linuxone-vsi-automation-samples/tree/master/terraform-hpcr-rhvs) - Terraform examples to provision HPCR RHVS
- [hyper-protect-virtual-server-samples](https://github.com/ibm-hyper-protect/hyper-protect-virtual-server-samples) - HPVS scripts for different features


## Contributors

![Contributors](https://contrib.rocks/image?repo=ibm-hyper-protect/contract-go)
