// Copyright (c) 2025 IBM Corp.
// All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package image

import (
	"testing"

	"github.com/Masterminds/semver/v3"
	"github.com/stretchr/testify/assert"

	gen "github.com/ibm-hyper-protect/contract-go/common/general"
)

const (
	ibmCloudImageListPathTerraform = "../samples/image/terraform_image.json"
	ibmCloudImageListPathCli       = "../samples/image/cli_image.json"
	ibmCloudImageListPathApi       = "../samples/image/api_image.json"
	sampleVersion                  = "1.0.21"

	// For API, Non Version
	sampleLatestVersion = "1.0.22"
	sampleArchitecture  = "s390x"
	sampleId            = "r006-2b8ba093-c8a3-4ed9-9b73-f6f0bb18d6f9"
	sampleName          = "ibm-hyper-protect-container-runtime-1-0-s390x-22"
	sampleOs            = "hyper-protect-1-0-s390x-hpcr"
	sampleStatus        = "available"
	sampleVisibility    = "public"
	sampleChecksum      = "489a0c4b84a7bd1aa3f06cd1280717bd1eb91fccbf85e77b0b7c6a8374bab2c7"

	// For Terraform and CLI
	sampleIdWithVer       = "r006-ad389a05-d7b0-4c92-ba6c-0934c4457d91"
	sampleNameWithVer     = "ibm-hyper-protect-container-runtime-1-0-s390x-21"
	sampleChecksumWithVer = "6d2eb0bea66d4ae8a4ccf6afdfe4f1336e98cda004963e60a8b0ae7fb7a4d396"
)

// Testcase to check SelectImage() is able to fetch the latest hyper protect image
func TestSelectImageTerraform(t *testing.T) {
	imageJsonList, err := gen.ReadDataFromFile(ibmCloudImageListPathTerraform)
	if err != nil {
		t.Errorf("failed to read data from file - %v", err)
	}

	imageId, imageName, imageChecksum, ImageVersion, err := HpcrSelectImage(imageJsonList, sampleVersion)
	if err != nil {
		t.Errorf("failed to select HPCR image - %v", err)
	}

	assert.Equal(t, imageId, sampleIdWithVer)
	assert.Equal(t, imageName, sampleNameWithVer)
	assert.Equal(t, imageChecksum, sampleChecksumWithVer)
	assert.Equal(t, ImageVersion, sampleVersion)
}

func TestSelectImageTerraformNoVersion(t *testing.T) {
	imageJsonList, err := gen.ReadDataFromFile(ibmCloudImageListPathTerraform)
	if err != nil {
		t.Errorf("failed to read data from file - %v", err)
	}

	imageId, imageName, imageChecksum, ImageVersion, err := HpcrSelectImage(imageJsonList, "")
	if err != nil {
		t.Errorf("failed to select HPCR image - %v", err)
	}

	assert.Equal(t, imageId, sampleId)
	assert.Equal(t, imageName, sampleName)
	assert.Equal(t, imageChecksum, sampleChecksum)
	assert.Equal(t, ImageVersion, sampleLatestVersion)
}

func TestSelectImageCli(t *testing.T) {
	imageJsonList, err := gen.ReadDataFromFile(ibmCloudImageListPathCli)
	if err != nil {
		t.Errorf("failed to read data from file - %v", err)
	}

	imageId, imageName, imageChecksum, ImageVersion, err := HpcrSelectImage(imageJsonList, sampleVersion)
	if err != nil {
		t.Errorf("failed to select HPCR image - %v", err)
	}

	assert.Equal(t, imageId, sampleIdWithVer)
	assert.Equal(t, imageName, sampleNameWithVer)
	assert.Equal(t, imageChecksum, sampleChecksumWithVer)
	assert.Equal(t, ImageVersion, sampleVersion)
}

func TestSelectImageApi(t *testing.T) {
	imageJsonList, err := gen.ReadDataFromFile(ibmCloudImageListPathApi)
	if err != nil {
		t.Errorf("failed to read data from file - %v", err)
	}

	imageId, imageName, imageChecksum, ImageVersion, err := HpcrSelectImage(imageJsonList, sampleLatestVersion)
	if err != nil {
		t.Errorf("failed to select HPCR image - %v", err)
	}

	assert.Equal(t, imageId, sampleId)
	assert.Equal(t, imageName, sampleName)
	assert.Equal(t, imageChecksum, sampleChecksum)
	assert.Equal(t, ImageVersion, sampleLatestVersion)
}

// Testcase to check if TestIsCandidateImage() can correctly identify if given data is hyper protect image data
func TestIsCandidateImage(t *testing.T) {
	sampleImageData := Image{
		Architecture: sampleArchitecture,
		ID:           sampleId,
		Name:         sampleName,
		Os:           sampleOs,
		Status:       sampleStatus,
		Visibility:   sampleVisibility,
		Checksum:     sampleChecksum,
	}

	result := IsCandidateImage(sampleImageData)

	assert.Equal(t, result, true)
}

// Testcase to check if PickLatestImage() is able to pick the latest image
func TestPickLatestImageWithVersion(t *testing.T) {
	version, err := semver.NewVersion(sampleVersion)
	if err != nil {
		t.Errorf("failed to generate semantic version - %v", err)
	}

	var image []ImageVersion

	image = append(image, ImageVersion{ID: sampleId, Name: sampleName, Checksum: sampleChecksum, Version: version})

	imageId, imageName, imageChecksum, imageVersion, err := PickLatestImage(image, sampleVersion)
	if err != nil {
		t.Errorf("failed to pick latest image - %v", err)
	}

	assert.Equal(t, imageId, sampleId)
	assert.Equal(t, imageName, sampleName)
	assert.Equal(t, imageChecksum, sampleChecksum)
	assert.Equal(t, imageVersion, sampleVersion)
}

func TestPickLatestImageWithoutVersion(t *testing.T) {
	version, err := semver.NewVersion(sampleVersion)
	if err != nil {
		t.Errorf("failed to generate semantic version - %v", err)
	}

	var image []ImageVersion

	image = append(image, ImageVersion{ID: sampleId, Name: sampleName, Checksum: sampleChecksum, Version: version})

	imageId, imageName, imageChecksum, imageVersion, err := PickLatestImage(image, sampleVersion)
	if err != nil {
		t.Errorf("failed to pick latest image - %v", err)
	}

	assert.Equal(t, imageId, sampleId)
	assert.Equal(t, imageName, sampleName)
	assert.Equal(t, imageChecksum, sampleChecksum)
	assert.Equal(t, imageVersion, sampleVersion)
}
