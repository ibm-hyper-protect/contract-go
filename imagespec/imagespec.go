// Copyright (c) 2026 IBM Corp.
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

// Package imagespec fetches OCI image metadata from a container registry
// and generates a Kubernetes pod YAML template that contains the correct
// env, entrypoint/command, user, and exposed-port overrides required when
// the image is used with a registryMapping replacement in a
// confidential-containers workload contract.
package imagespec

import (
	"fmt"
	"path"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	gen "github.com/ibm-hyper-protect/contract-go/v2/common/general"
	"gopkg.in/yaml.v3"
)

// GenerateImageSpec fetches the OCI image config and generates a Kubernetes
// pod YAML snippet in one call. Returns the YAML, the SHA256 of imageRef
// (input), and the SHA256 of the generated YAML (output).
// containerName defaults to the image name when empty.
func GenerateImageSpec(imageRef, containerName string, auth *AuthConfig) (string, string, string, error) {
	cfg, err := fetchImageConfig(imageRef, auth)
	if err != nil {
		return "", "", "", err
	}

	if containerName == "" {
		containerName = deriveContainerName(imageRef)
	}

	return generatePodYAMLTemplate(imageRef, cfg, containerName)
}

// fetchImageConfig fetches the OCI image config from the registry.
// Pass nil auth for public images; supply AuthConfig for private registries.
func fetchImageConfig(imageRef string, auth *AuthConfig) (*v1.Config, error) {
	if strings.TrimSpace(imageRef) == "" {
		return nil, fmt.Errorf("imageRef must not be empty")
	}

	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return nil, fmt.Errorf("failed to parse image reference %q: %w", imageRef, err)
	}

	var remoteOpts []remote.Option
	if auth != nil && auth.Username != "" && auth.Password != "" {
		remoteOpts = append(remoteOpts, remote.WithAuth(&authn.Basic{
			Username: auth.Username,
			Password: auth.Password,
		}))
	} else {
		// Anonymous auth avoids credential-helper errors on machines where
		// the Docker keychain helper is configured but not in PATH.
		remoteOpts = append(remoteOpts, remote.WithAuth(authn.Anonymous))
	}

	img, err := remote.Image(ref, remoteOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch image %q: %w", imageRef, err)
	}

	cfgFile, err := img.ConfigFile()
	if err != nil {
		return nil, fmt.Errorf("failed to read config from image %q: %w", imageRef, err)
	}

	return &cfgFile.Config, nil
}

// generatePodYAMLTemplate builds the Kubernetes pod YAML snippet from the OCI
// image config. Returns the YAML, SHA256 of imageRef, and SHA256 of the YAML.
func generatePodYAMLTemplate(imageRef string, cfg *v1.Config, containerName string) (string, string, string, error) {
	cs := containerSpec{
		Name:       containerName,
		Image:      imageRef,
		WorkingDir: cfg.WorkingDir,
	}

	// Env: split "KEY=VALUE" into name/value pairs.
	for _, e := range cfg.Env {
		parts := strings.SplitN(e, "=", 2)
		ev := envVar{Name: parts[0]}
		if len(parts) == 2 {
			ev.Value = parts[1]
		}
		cs.Env = append(cs.Env, ev)
	}

	// ENTRYPOINT → command, CMD → args.
	if len(cfg.Entrypoint) > 0 {
		cs.Command = cfg.Entrypoint
	}
	if len(cfg.Cmd) > 0 {
		cs.Args = cfg.Cmd
	}

	// User: parse "uid" or "uid:gid" and set securityContext.
	if cfg.User != "" {
		var uid, gid int64
		n, _ := fmt.Sscanf(cfg.User, "%d:%d", &uid, &gid)
		if n >= 1 {
			noPrivEsc := false
			sc := &secCtx{
				RunAsUser:                &uid,
				AllowPrivilegeEscalation: &noPrivEsc,
			}
			if n == 2 {
				sc.RunAsGroup = &gid
			}
			cs.SecurityContext = sc
		}
	}

	// ExposedPorts: convert "port/proto" keys into containerPort entries.
	for p := range cfg.ExposedPorts {
		proto := "TCP"
		portStr := p
		if idx := strings.Index(p, "/"); idx != -1 {
			portStr = p[:idx]
			proto = strings.ToUpper(p[idx+1:])
		}
		var portNum int32
		fmt.Sscanf(portStr, "%d", &portNum)
		if portNum > 0 {
			cs.Ports = append(cs.Ports, containerPort{ContainerPort: portNum, Protocol: proto})
		}
	}

	snippet := containerSnippet{
		Spec: specSnippet{Containers: []containerSpec{cs}},
	}

	out, err := yaml.Marshal(snippet)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to marshal pod YAML template: %w", err)
	}

	yamlStr := string(out)
	return yamlStr, gen.GenerateSha256(imageRef), gen.GenerateSha256(yamlStr), nil
}

// deriveContainerName extracts the image name from a reference.
// e.g. "quay.io/sclorg/postgresql-15-c9s:latest" → "postgresql-15-c9s"
// Falls back to "app" if the reference cannot be parsed.
func deriveContainerName(imageRef string) string {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return "app"
	}
	n := path.Base(ref.Context().RepositoryStr())
	if n == "" || n == "." {
		return "app"
	}
	return n
}
