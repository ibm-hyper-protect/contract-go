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

func TestGeneratePodYAMLTemplate_BasicFields(t *testing.T) {
	cfg := makeConfig(
		"26:26",
		[]string{"POSTGRESQL_VERSION=15", "HOME=/var/lib/pgsql"},
		[]string{"container-entrypoint"},
		[]string{"run-postgresql"},
		map[string]struct{}{"5432/tcp": {}},
		"/opt/app-root/src",
	)

	out, imageUser, inputSHA, outputSHA, err := generatePodYAMLTemplate("quay.io/sclorg/postgresql-15-c9s:latest", cfg, "postgres")
	require.NoError(t, err)

	assert.Equal(t, "26:26", imageUser)
	assert.Contains(t, out, "# image user: 26:26")
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

func TestGeneratePodYAMLTemplate_DefaultContainerName(t *testing.T) {
	cfg := makeConfig("", nil, nil, nil, nil, "")
	out, imageUser, _, _, err := generatePodYAMLTemplate("quay.io/ramachandra_ch/redis@sha256:abc", cfg, "app")
	require.NoError(t, err)
	assert.Equal(t, "no user specified", imageUser)
	assert.Contains(t, out, "# image user: no user specified")
	assert.Contains(t, out, "name: app")
	assert.NotContains(t, out, "apiVersion:")
}

func TestGeneratePodYAMLTemplate_UserUIDOnly(t *testing.T) {
	cfg := makeConfig("26", nil, nil, nil, nil, "")
	out, imageUser, _, _, err := generatePodYAMLTemplate("quay.io/sclorg/postgresql-15-c9s:latest", cfg, "postgres")
	require.NoError(t, err)
	assert.Equal(t, "26", imageUser)
	assert.Contains(t, out, "# image user: 26")
	assert.Contains(t, out, "runAsUser: 26")
	assert.Contains(t, out, "allowPrivilegeEscalation: false")
	assert.NotContains(t, out, "runAsGroup")
}

func TestGeneratePodYAMLTemplate_NoEntrypointNoCmd(t *testing.T) {
	cfg := makeConfig("", nil, nil, nil, nil, "")
	out, _, _, _, err := generatePodYAMLTemplate("example.com/img:tag", cfg, "myapp")
	require.NoError(t, err)
	assert.NotContains(t, out, "command:")
	assert.NotContains(t, out, "args:")
}

func TestGeneratePodYAMLTemplate_MultipleExposedPorts(t *testing.T) {
	cfg := makeConfig("", nil, nil, nil, map[string]struct{}{
		"50000/tcp": {},
		"55000/tcp": {},
		"22/tcp":    {},
	}, "")
	out, _, _, _, err := generatePodYAMLTemplate("us.icr.io/hpvsonprem/testdb2:hpcc", cfg, "db2")
	require.NoError(t, err)
	assert.Contains(t, out, "containerPort: 50000")
	assert.Contains(t, out, "containerPort: 55000")
	assert.Contains(t, out, "containerPort: 22")
}

func TestFetchImageConfig_EmptyRef(t *testing.T) {
	_, err := fetchImageConfig("", nil)
	assert.ErrorContains(t, err, "imageRef must not be empty")
}

func TestFetchImageConfig_InvalidRef(t *testing.T) {
	_, err := fetchImageConfig(":::invalid:::", nil)
	assert.ErrorContains(t, err, "failed to parse image reference")
}

func TestGenerateImageSpec_EmptyRef(t *testing.T) {
	_, _, _, _, err := GenerateImageSpec("", "", nil)
	assert.ErrorContains(t, err, "imageRef must not be empty")
}

func TestGenerateImageSpec_InvalidRef(t *testing.T) {
	_, _, _, _, err := GenerateImageSpec(":::bad:::", "", nil)
	assert.ErrorContains(t, err, "failed to parse image reference")
}

func TestGeneratePodYAMLTemplate_EnvWithoutValue(t *testing.T) {
	cfg := makeConfig("", []string{"NOVALUE"}, nil, nil, nil, "")
	out, _, _, _, err := generatePodYAMLTemplate("example.com/img:tag", cfg, "test")
	require.NoError(t, err)
	assert.Contains(t, out, "NOVALUE")
}

// TestGeneratePodYAMLTemplate_NamedUser: named USER string → comment only, no securityContext.
func TestGeneratePodYAMLTemplate_NamedUser(t *testing.T) {
	cfg := makeConfig("postgres", nil, nil, nil, nil, "")
	out, imageUser, _, _, err := generatePodYAMLTemplate("quay.io/sclorg/postgresql-15-c9s:latest", cfg, "postgres")
	require.NoError(t, err)
	assert.Equal(t, "postgres", imageUser)
	assert.Contains(t, out, "# image user: postgres")
	assert.NotContains(t, out, "securityContext:")
	assert.NotContains(t, out, "runAsUser:")
}

// TestGeneratePodYAMLTemplate_NoUser: empty USER → "no user specified", no securityContext.
func TestGeneratePodYAMLTemplate_NoUser(t *testing.T) {
	cfg := makeConfig("", nil, nil, nil, nil, "")
	out, imageUser, _, _, err := generatePodYAMLTemplate("example.com/img:tag", cfg, "app")
	require.NoError(t, err)
	assert.Equal(t, "no user specified", imageUser)
	assert.Contains(t, out, "# image user: no user specified")
	assert.NotContains(t, out, "securityContext:")
}

func TestResolveImageUser(t *testing.T) {
	cases := []struct {
		raw       string
		wantLabel string
		wantUID   int64
		wantGID   int64
	}{
		{"", "no user specified", -1, -1},
		{"26", "26", 26, -1},
		{"26:26", "26:26", 26, 26},
		{"0:0", "0:0", 0, 0},
		{"postgres", "postgres", -1, -1},
		{"redis", "redis", -1, -1},
		{"nobody", "nobody", -1, -1},
	}
	for _, tc := range cases {
		label, uid, gid := resolveImageUser(tc.raw)
		assert.Equal(t, tc.wantLabel, label, "raw=%q", tc.raw)
		assert.Equal(t, tc.wantUID, uid, "raw=%q uid", tc.raw)
		assert.Equal(t, tc.wantGID, gid, "raw=%q gid", tc.raw)
	}
}

// TestGeneratePodYAMLTemplate_PostgresInspectValues: real-world sclorg postgres env.
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

	out, imageUser, inputSHA, outputSHA, err := generatePodYAMLTemplate("quay.io/sclorg/postgresql-15-c9s:latest", cfg, "postgres")
	require.NoError(t, err)

	assert.Equal(t, "postgres", imageUser)
	assert.Contains(t, out, "# image user: postgres")
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

// TestGeneratePodYAMLTemplate_UsesProvidedFakeImage: numeric UID, no *USER* env key → UID as label.
func TestGeneratePodYAMLTemplate_UsesProvidedFakeImage(t *testing.T) {
	_ = fake.FakeImage{}

	cfg := &v1.Config{
		User:         "999",
		Env:          []string{"REDIS_VERSION=7.0.0"},
		ExposedPorts: map[string]struct{}{"6379/tcp": {}},
	}

	out, imageUser, _, _, err := generatePodYAMLTemplate("quay.io/ramachandra_ch/redis@sha256:8e845b2ad2eec813a04896d4e2e5588827e49d5394579c95f3651f0cb11c1cb0", cfg, "redis")
	require.NoError(t, err)
	assert.Equal(t, "999", imageUser)
	assert.Contains(t, out, "# image user: 999")
	assert.Contains(t, out, "runAsUser: 999")
	assert.Contains(t, out, "REDIS_VERSION")
	assert.Contains(t, out, "containerPort: 6379")
}

func TestInferUsernameFromEnv(t *testing.T) {
	cases := []struct {
		desc string
		env  []string
		want string
	}{
		{"pguser",            []string{"PGUSER=postgres", "HOME=/var/lib/pgsql"}, "postgres"},
		{"mysql_user",        []string{"MYSQL_USER=root"}, "root"},
		{"mariadb_user",      []string{"MARIADB_USER=myuser"}, "myuser"},
		{"app_user",          []string{"APP_USER=appuser"}, "appuser"},
		{"run_user",          []string{"RUN_USER=runner"}, "runner"},
		{"mongodb_username",  []string{"MONGODB_USERNAME=mongodb"}, "mongodb"},
		{"custom_svc_user",   []string{"MY_SVC_USER=myapp"}, "myapp"},
		{"username_key",      []string{"USERNAME=admin"}, "admin"},
		{"no_user_key",       []string{"REDIS_VERSION=7.0.0"}, ""},
		{"empty_env",         []string{}, ""},
		{"empty_value",       []string{"PGUSER="}, ""},
		{"path_value",        []string{"APP_USER=/home/app"}, ""},
		{"url_value",         []string{"APP_USER=http://x.com"}, ""},
		{"integer_value",     []string{"APP_USER=1001"}, ""},
		{"too_long",          []string{"APP_USER=averylongusernamethatexceedsthirtytwocharacters"}, ""},
		{"first_wins",        []string{"APP_USER=first", "RUN_USER=second"}, "first"},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, inferUsernameFromEnv(tc.env), "case %q", tc.desc)
	}
}

// TestGeneratePodYAMLTemplate_NumericUIDWithEnvHint: PGUSER present → username as label, UID in runAsUser.
func TestGeneratePodYAMLTemplate_NumericUIDWithEnvHint(t *testing.T) {
	cfg := makeConfig("26", []string{"PGUSER=postgres", "HOME=/var/lib/pgsql"}, nil, nil, nil, "")
	out, imageUser, _, _, err := generatePodYAMLTemplate("quay.io/sclorg/postgresql-15-c9s:latest", cfg, "postgres")
	require.NoError(t, err)
	assert.Equal(t, "postgres", imageUser)
	assert.Contains(t, out, "# image user: postgres")
	assert.Contains(t, out, "runAsUser: 26")
	assert.Contains(t, out, "allowPrivilegeEscalation: false")
}

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
