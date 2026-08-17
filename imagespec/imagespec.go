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

// Package imagespec generates a Kubernetes pod YAML template from OCI image metadata
// for use with the registryMapping feature of confidential-containers workload contracts.
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

// GenerateImageSpec fetches the OCI image config and generates a pod YAML snippet.
// Returns (yaml, imageUser, inputSHA, outputSHA, error).
// imageUser is a username (e.g. "postgres"), raw UID ("26"), or "no user specified".
func GenerateImageSpec(imageRef, containerName string, auth *AuthConfig) (string, string, string, string, error) {
	cfg, err := fetchImageConfig(imageRef, auth)
	if err != nil {
		return "", "", "", "", err
	}

	if containerName == "" {
		containerName = deriveContainerName(imageRef)
	}

	return generatePodYAMLTemplate(imageRef, cfg, containerName)
}

// fetchImageConfig pulls the OCI config layer from the registry (nil auth = public image).
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
		// Anonymous avoids credential-helper errors when Docker keychain helpers are not in PATH.
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

// resolveImageUser parses the OCI User field into a label and numeric uid/gid (-1 if absent).
func resolveImageUser(rawUser string) (label string, uid int64, gid int64) {
	if rawUser == "" {
		return "no user specified", -1, -1
	}

	var parsedUID, parsedGID int64
	n, _ := fmt.Sscanf(rawUser, "%d:%d", &parsedUID, &parsedGID)
	if n >= 1 {
		gidVal := int64(-1)
		if n == 2 {
			gidVal = parsedGID
		}
		return rawUser, parsedUID, gidVal
	}

	return rawUser, -1, -1
}

// inferUsernameFromEnv scans env for any key containing "USER" whose value looks like
// a Unix username (non-empty, ≤32 chars, no path/URL chars, not a pure integer).
func inferUsernameFromEnv(env []string) string {
	for _, e := range env {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key, val := parts[0], parts[1]

		if !strings.Contains(strings.ToUpper(key), "USER") {
			continue
		}
		if val == "" || len(val) > 32 {
			continue
		}
		if strings.ContainsAny(val, "/ \t:\\") {
			continue
		}
		if _, err := fmt.Sscanf(val, "%d", new(int64)); err == nil {
			continue
		}

		return val
	}
	return ""
}

// generatePodYAMLTemplate builds the pod YAML snippet from the OCI image config.
func generatePodYAMLTemplate(imageRef string, cfg *v1.Config, containerName string) (string, string, string, string, error) {
	cs := containerSpec{
		Name:       containerName,
		Image:      imageRef,
		WorkingDir: cfg.WorkingDir,
	}

	for _, e := range cfg.Env {
		parts := strings.SplitN(e, "=", 2)
		ev := envVar{Name: parts[0]}
		if len(parts) == 2 {
			ev.Value = parts[1]
		}
		cs.Env = append(cs.Env, ev)
	}

	if len(cfg.Entrypoint) > 0 {
		cs.Command = cfg.Entrypoint
	}
	if len(cfg.Cmd) > 0 {
		cs.Args = cfg.Cmd
	}

	// For numeric UIDs, prefer a username hint from env; UID goes into runAsUser.
	imageUser, uid, gid := resolveImageUser(cfg.User)
	if uid >= 0 {
		if hint := inferUsernameFromEnv(cfg.Env); hint != "" {
			imageUser = hint
		}
		noPrivEsc := false
		sc := &secCtx{
			RunAsUser:                &uid,
			AllowPrivilegeEscalation: &noPrivEsc,
		}
		if gid >= 0 {
			sc.RunAsGroup = &gid
		}
		cs.SecurityContext = sc
	}

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
		return "", "", "", "", fmt.Errorf("failed to marshal pod YAML template: %w", err)
	}

	yamlStr := fmt.Sprintf("# image user: %s\n%s", imageUser, string(out))
	return yamlStr, imageUser, gen.GenerateSha256(imageRef), gen.GenerateSha256(yamlStr), nil
}

// deriveContainerName extracts the image name from a reference, e.g. "postgresql-15-c9s".
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
