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
	"encoding/json"
	"fmt"
	"regexp"
	"sort"

	"github.com/Masterminds/semver/v3"

	gen "github.com/ibm-hyper-protect/contract-go/v2/common/general"
)

type (
	Image struct {
		ID           string      `json:"id"`
		Name         string      `json:"name"`
		Status       string      `json:"status"`
		Visibility   string      `json:"visibility"`
		Architecture string      `json:"architecture"`
		Os           string      `json:"os"`
		File         *File       `json:"file,omitempty"`
		Checksum     string      `json:"checksum"`
		OSRaw        interface{} `json:"operating_system"`
	}

	File struct {
		Checksums Checksums `json:"checksums"`
	}

	Checksums struct {
		Sha256 string `json:"sha256"`
	}

	OperatingSystem struct {
		Name         string `json:"name"`
		Architecture string `json:"architecture"`
	}

	ImageVersion struct {
		ID       string
		Checksum string
		Name     string
		Version  *semver.Version
	}
)

var (
	// reHyperProtectOS tests if this is a hyper protect image
	reHyperProtectOS = regexp.MustCompile(`^hyper-protect-[\w-]+-s390x-hpcr$`)

	// reHyperProtectVersion tests if the name references a valid hyper protect version
	reHyperProtectName = regexp.MustCompile(`^ibm-hyper-protect-container-runtime-(\d+)-(\d+)-s390x-(\d+)$`)
)

const (
	emptyParameterErrStatement = "required parameter is empty"
)

// HpcrSelectImage selects the latest HPCR image from IBM Cloud images based on version constraints.
// It parses the image JSON data, filters for valid Hyper Protect images, and returns the latest
// image matching the version specification using semantic versioning rules.
//
// Parameters:
//   - imageJsonData: JSON array of IBM Cloud images from Terraform, IBM Cloud API, or IBM Cloud CLI
//   - versionSpec: Semantic version constraint (e.g., ">=1.1.0", "~1.1.14") - selects latest if empty
//
// Returns:
//   - Image ID from IBM Cloud
//   - Full image name
//   - SHA256 checksum of the image
//   - Semantic version string (e.g., "1.1.15")
//   - Error if no matching image found or JSON is invalid
func HpcrSelectImage(imageJsonData, versionSpec string) (string, string, string, string, error) {
	if gen.CheckIfEmpty(imageJsonData) {
		return "", "", "", "", fmt.Errorf(emptyParameterErrStatement)
	}

	var images []Image
	var hyperProtectImages []ImageVersion

	err := json.Unmarshal([]byte(imageJsonData), &images)
	if err != nil {
		return "", "", "", "", fmt.Errorf("failed to unmarshal JSON - %v", err)
	}

	for _, image := range images {
		switch data := image.OSRaw.(type) {
		case map[string]interface{}:
			osJson, _ := json.Marshal(data)
			var os OperatingSystem
			_ = json.Unmarshal(osJson, &os)

			if image.Architecture == "" {
				image.Architecture = os.Architecture
			}
			if image.Os == "" {
				image.Os = os.Name
			}
		case []interface{}:
			if len(data) > 0 {
				osJson, _ := json.Marshal(data[0])
				var os OperatingSystem
				_ = json.Unmarshal(osJson, &os)
				if image.Architecture == "" {
					image.Architecture = os.Architecture
				}
				if image.Os == "" {
					image.Os = os.Name
				}
			}
		}

		if image.Checksum == "" && image.File != nil {
			image.Checksum = image.File.Checksums.Sha256
		}

		if IsCandidateImage(image) {
			versionRegex := reHyperProtectName.FindStringSubmatch(image.Name)
			hyperProtectImages = append(hyperProtectImages, ImageVersion{
				ID:       image.ID,
				Name:     image.Name,
				Checksum: image.Checksum,
				Version:  semver.MustParse(fmt.Sprintf("%s.%s.%s", versionRegex[1], versionRegex[2], versionRegex[3])),
			})
		}
	}

	return PickLatestImage(hyperProtectImages, versionSpec)
}

// IsCandidateImage checks if an image is a valid Hyper Protect image.
// It validates that the image meets all requirements: s390x architecture, available status,
// public visibility, and matches the Hyper Protect OS and naming patterns.
//
// Parameters:
//   - img: Image structure parsed from IBM Cloud image JSON
//
// Returns:
//   - true if the image is a valid Hyper Protect image, false otherwise
func IsCandidateImage(img Image) bool {
	return img.Architecture == "s390x" && img.Status == "available" && img.Visibility == "public" &&
		reHyperProtectOS.MatchString(img.Os) && reHyperProtectName.MatchString(img.Name)
}

// PickLatestImage selects the latest image from a list of Hyper Protect images based on version constraints.
// It applies semantic version filtering if a version constraint is provided, then sorts the matching
// images by version and returns the latest one.
//
// Parameters:
//   - hyperProtectImages: List of ImageVersion structures containing parsed Hyper Protect images
//   - version: Semantic version constraint (e.g., ">=1.1.0", "~1.1.14") - empty returns absolute latest
//
// Returns:
//   - Image ID from IBM Cloud
//   - Full image name
//   - SHA256 checksum of the image
//   - Semantic version string (e.g., "1.1.15")
//   - Error if no matching images found or version constraint is invalid
func PickLatestImage(hyperProtectImages []ImageVersion, version string) (string, string, string, string, error) {
	if gen.CheckIfEmpty(hyperProtectImages) {
		return "", "", "", "", fmt.Errorf(emptyParameterErrStatement)
	}

	var matchingVersions []*semver.Version
	imageMap := make(map[string]ImageVersion)

	for _, image := range hyperProtectImages {
		if image.Version == nil {
			continue
		}
		matchingVersions = append(matchingVersions, image.Version)
		imageMap[image.Version.String()] = image
	}

	if version != "" {
		constraint, err := semver.NewConstraint(version)
		if err != nil {
			return "", "", "", "", fmt.Errorf("error parsing target version constraint - %v", err)
		}

		filtered := []*semver.Version{}
		for _, v := range matchingVersions {
			if constraint.Check(v) {
				filtered = append(filtered, v)
			}
		}
		matchingVersions = filtered
	}

	if len(matchingVersions) == 0 {
		return "", "", "", "", fmt.Errorf("no Hyper Protect image matching version found")
	}

	sort.Sort(sort.Reverse(semver.Collection(matchingVersions)))
	latest := matchingVersions[0]
	selected := imageMap[latest.String()]
	return selected.ID, selected.Name, selected.Checksum, selected.Version.String(), nil
}
