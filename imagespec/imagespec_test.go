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

package imagespec

import (
	"fmt"
	"strings"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// makeConfig creates a *v1.Config for testing generatePodYAMLTemplate.
func makeConfig(user string, env, entrypoint, cmd []string, ports map[string]struct{}, workingDir string) *v1.Config {
	cfg := &v1.Config{
		User:         user,
		Env:          env,
		Entrypoint:   entrypoint,
		Cmd:          cmd,
		WorkingDir:   workingDir,
		ExposedPorts: make(map[string]struct{}),
	}
	for p := range ports {
		cfg.ExposedPorts[p] = struct{}{}
	}
	return cfg
}

// TestGeneratePodYAMLTemplate_BasicFields ensures required keys appear in YAML.
func TestGeneratePodYAMLTemplate_BasicFields(t *testing.T) {
	cfg := makeConfig(
		"26:26",
		[]string{"POSTGRESQL_VERSION=15", "HOME=/var/lib/pgsql"},
		[]string{"container-entrypoint"},
		[]string{"run-postgresql"},
		map[string]struct{}{"5432/tcp": {}},
		"/opt/app-root/src",
	)

	out, inputSHA, outputSHA, err := generatePodYAMLTemplate("quay.io/sclorg/postgresql-15-c9s:latest", cfg, "postgres")
	require.NoError(t, err)

	assert.Contains(t, out, "spec:")
	assert.Contains(t, out, "containers:")
	assert.NotContains(t, out, "apiVersion:")
	assert.NotContains(t, out, "kind:")
	assert.NotContains(t, out, "metadata:")
	assert.Contains(t, out, "name: postgres")
	assert.Contains(t, out, "image: quay.io/sclorg/postgresql-15-c9s:latest")
	assert.Contains(t, out, "POSTGRESQL_VERSION")
	assert.Contains(t, out, "container-entrypoint")
	assert.Contains(t, out, "run-postgresql")
	assert.Contains(t, out, "runAsUser: 26")
	assert.Contains(t, out, "runAsGroup: 26")
	assert.Contains(t, out, "allowPrivilegeEscalation: false")
	assert.Contains(t, out, "containerPort: 5432")
	assert.Contains(t, out, "workingDir: /opt/app-root/src")
	assert.NotEmpty(t, inputSHA)
	assert.NotEmpty(t, outputSHA)
	assert.NotEqual(t, inputSHA, outputSHA)
}

// TestGeneratePodYAMLTemplate_DefaultContainerName verifies fallback to "app".
func TestGeneratePodYAMLTemplate_DefaultContainerName(t *testing.T) {
	cfg := makeConfig("", nil, nil, nil, nil, "")
	out, _, _, err := generatePodYAMLTemplate("quay.io/ramachandra_ch/redis@sha256:abc", cfg, "app")
	require.NoError(t, err)
	assert.Contains(t, out, "name: app")
	assert.NotContains(t, out, "apiVersion:")
}

// TestGeneratePodYAMLTemplate_UserUIDOnly verifies that "uid"-only user is parsed.
func TestGeneratePodYAMLTemplate_UserUIDOnly(t *testing.T) {
	cfg := makeConfig("26", nil, nil, nil, nil, "")
	out, _, _, err := generatePodYAMLTemplate("quay.io/sclorg/postgresql-15-c9s:latest", cfg, "postgres")
	require.NoError(t, err)
	assert.Contains(t, out, "runAsUser: 26")
	assert.Contains(t, out, "allowPrivilegeEscalation: false")
	assert.NotContains(t, out, "runAsGroup")
}

// TestGeneratePodYAMLTemplate_NoEntrypointNoCmd ensures command/args are omitted.
func TestGeneratePodYAMLTemplate_NoEntrypointNoCmd(t *testing.T) {
	cfg := makeConfig("", nil, nil, nil, nil, "")
	out, _, _, err := generatePodYAMLTemplate("example.com/img:tag", cfg, "myapp")
	require.NoError(t, err)
	assert.NotContains(t, out, "command:")
	assert.NotContains(t, out, "args:")
}

// TestGeneratePodYAMLTemplate_MultipleExposedPorts verifies multiple ports rendered.
func TestGeneratePodYAMLTemplate_MultipleExposedPorts(t *testing.T) {
	cfg := makeConfig("", nil, nil, nil, map[string]struct{}{
		"50000/tcp": {},
		"55000/tcp": {},
		"22/tcp":    {},
	}, "")
	out, _, _, err := generatePodYAMLTemplate("us.icr.io/hpvsonprem/testdb2:hpcc", cfg, "db2")
	require.NoError(t, err)
	assert.Contains(t, out, "containerPort: 50000")
	assert.Contains(t, out, "containerPort: 55000")
	assert.Contains(t, out, "containerPort: 22")
}

// TestFetchImageConfig_EmptyRef verifies an error for empty image reference.
func TestFetchImageConfig_EmptyRef(t *testing.T) {
	_, err := fetchImageConfig("", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "imageRef must not be empty")
}

// TestFetchImageConfig_InvalidRef verifies an error for malformed image reference.
func TestFetchImageConfig_InvalidRef(t *testing.T) {
	_, err := fetchImageConfig(":::invalid:::", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse image reference")
}

// TestGenerateImageSpec_EmptyRef verifies the public API returns an error for empty ref.
func TestGenerateImageSpec_EmptyRef(t *testing.T) {
	_, _, _, err := GenerateImageSpec("", "", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "imageRef must not be empty")
}

// TestGenerateImageSpec_InvalidRef verifies the public API returns an error for bad ref.
func TestGenerateImageSpec_InvalidRef(t *testing.T) {
	_, _, _, err := GenerateImageSpec(":::bad:::", "", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse image reference")
}

// TestGeneratePodYAMLTemplate_EnvWithoutValue verifies env without "=" marshals correctly.
func TestGeneratePodYAMLTemplate_EnvWithoutValue(t *testing.T) {
	cfg := makeConfig("", []string{"NOVALUE"}, nil, nil, nil, "")
	out, _, _, err := generatePodYAMLTemplate("example.com/img:tag", cfg, "test")
	require.NoError(t, err)
	assert.Contains(t, out, "NOVALUE")
}

// TestGeneratePodYAMLTemplate_PostgresInspectValues validates real-world postgres values.
func TestGeneratePodYAMLTemplate_PostgresInspectValues(t *testing.T) {
	envVars := []string{
		"NAME=s2i-core",
		"VERSION=9",
		"STI_SCRIPTS_URL=image:///usr/libexec/s2i",
		"STI_SCRIPTS_PATH=/usr/libexec/s2i",
		"APP_ROOT=/opt/app-root",
		"PATH=/opt/app-root/src/bin:/opt/app-root/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"PLATFORM=el9",
		"POSTGRESQL_VERSION=15",
		"POSTGRESQL_PREV_VERSION=13",
		"HOME=/var/lib/pgsql",
		"PGUSER=postgres",
		"APP_DATA=/opt/app-root",
		"SUMMARY=PostgreSQL is an advanced Object-Relational database management system",
		"DESCRIPTION=PostgreSQL is an advanced Object-Relational database management system (DBMS). The image contains the client and server programs that you'll need to create, run, maintain and access a PostgreSQL DBMS server.",
		"CONTAINER_SCRIPTS_PATH=/usr/share/container-scripts/postgresql",
		"ENABLED_COLLECTIONS=",
	}

	cfg := makeConfig(
		"26",
		envVars,
		[]string{"container-entrypoint"},
		[]string{"run-postgresql"},
		map[string]struct{}{"5432/tcp": {}},
		"/opt/app-root/src",
	)

	out, inputSHA, outputSHA, err := generatePodYAMLTemplate("quay.io/sclorg/postgresql-15-c9s:latest", cfg, "postgres")
	require.NoError(t, err)

	for _, ev := range envVars {
		parts := strings.SplitN(ev, "=", 2)
		assert.Contains(t, out, fmt.Sprintf("name: %s", parts[0]))
	}
	assert.Contains(t, out, "runAsUser: 26")
	assert.Contains(t, out, "allowPrivilegeEscalation: false")
	assert.Contains(t, out, "containerPort: 5432")
	assert.Contains(t, out, "- container-entrypoint")
	assert.Contains(t, out, "- run-postgresql")
	assert.NotEmpty(t, inputSHA)
	assert.NotEmpty(t, outputSHA)
}

// TestGeneratePodYAMLTemplate_UsesProvidedFakeImage verifies generatePodYAMLTemplate
// with a manually-constructed Config (does not call a live registry).
func TestGeneratePodYAMLTemplate_UsesProvidedFakeImage(t *testing.T) {
	_ = fake.FakeImage{}

	cfg := &v1.Config{
		User:         "999",
		Env:          []string{"REDIS_VERSION=7.0.0"},
		ExposedPorts: map[string]struct{}{"6379/tcp": {}},
	}

	out, _, _, err := generatePodYAMLTemplate("quay.io/ramachandra_ch/redis@sha256:8e845b2ad2eec813a04896d4e2e5588827e49d5394579c95f3651f0cb11c1cb0", cfg, "redis")
	require.NoError(t, err)
	assert.Contains(t, out, "runAsUser: 999")
	assert.Contains(t, out, "REDIS_VERSION")
	assert.Contains(t, out, "containerPort: 6379")
}

// TestDeriveContainerName verifies the image-name extraction logic.
func TestDeriveContainerName(t *testing.T) {
	cases := []struct {
		ref      string
		expected string
	}{
		{"quay.io/fedora/fedora:38", "fedora"},
		{"quay.io/ramachandra_ch/redis@sha256:8e845b2ad2eec813a04896d4e2e5588827e49d5394579c95f3651f0cb11c1cb0", "redis"},
		{"quay.io/sclorg/postgresql-15-c9s", "postgresql-15-c9s"},
		{"nginx:latest", "nginx"},
		{"", "app"},
		{"us.icr.io/hpvsonprem/daytradersealed:hpcc", "daytradersealed"},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.expected, deriveContainerName(tc.ref), "ref=%q", tc.ref)
	}
}
