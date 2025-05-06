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
	sampleVersion                  = "1.0.22"

	sampleArchitecture = "s390x"
	sampleId           = "r006-2b8ba093-c8a3-4ed9-9b73-f6f0bb18d6f9"
	sampleName         = "ibm-hyper-protect-container-runtime-1-0-s390x-22"
	sampleOs           = "hyper-protect-1-0-s390x-hpcr"
	sampleStatus       = "available"
	sampleVisibility   = "public"
	sampleChecksum     = "489a0c4b84a7bd1aa3f06cd1280717bd1eb91fccbf85e77b0b7c6a8374bab2c7"
)

// Testcase to check SelectImage() is able to fetch the latest hyper protect image
func TestSelectImage(t *testing.T) {
	imageJsonList, err := gen.ReadDataFromFile(ibmCloudImageListPathTerraform)
	if err != nil {
		t.Errorf("failed to read data from file - %v", err)
	}

	imageId, imageName, imageChecksum, ImageVersion, err := HpcrSelectImage(imageJsonList, sampleVersion)
	if err != nil {
		t.Errorf("failed to select HPCR image - %v", err)
	}

	assert.Equal(t, imageId, sampleId)
	assert.Equal(t, imageName, sampleName)
	assert.Equal(t, imageChecksum, sampleChecksum)
	assert.Equal(t, ImageVersion, sampleVersion)
}

// Testcase to check if TestIsCandidateImage() can correctly identify if given data is hyper protect image data
func TestIsCandidateImage(t *testing.T) {
	sampleImageData := Image{
		Architecture: sampleArchitecture,
		ID:           sampleId,
		Name:         sampleName,
		OS:           sampleOs,
		Status:       sampleStatus,
		Visibility:   sampleVisibility,
		Checksum:     sampleChecksum,
	}

	result := IsCandidateImage(sampleImageData)

	assert.Equal(t, result, true)
}

// Testcase to check if PickLatestImage() is able to pick the latest image
func TestPickLatestImage(t *testing.T) {
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
