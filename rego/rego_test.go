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

package rego

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sampleFile returns the path to a file under samples/.
func sampleFile(parts ...string) string {
	return filepath.Join(append([]string{".."}, parts...)...)
}

// mustDecodeBase64 decodes a standard base64 string, failing the test on error.
func mustDecodeBase64(t *testing.T, s string) string {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	require.NoError(t, err, "base64 decode failed")
	return string(b)
}

// ─── GenerateRegoPolicy ───────────────────────────────────────────────────────

// TestGenerateRegoPolicy_Minimal verifies the basic policy structure from a no-command pod.
func TestGenerateRegoPolicy_Minimal(t *testing.T) {
	podYAML, err := os.ReadFile(sampleFile("samples", "hpcc", "minimal-pod.yaml"))
	require.NoError(t, err)

	policy, inputB64, outputB64, err := GenerateRegoPolicy(string(podYAML), "")
	require.NoError(t, err)
	assert.Contains(t, policy, "package agent_policy")
	assert.Contains(t, policy, `^quay\\.io/prometheus/busybox:latest$`)
	// base64 round-trips
	assert.Equal(t, string(podYAML), mustDecodeBase64(t, inputB64), "inputB64 must decode back to podYAML")
	assert.Equal(t, policy, mustDecodeBase64(t, outputB64), "outputB64 must decode back to policy")
}

// TestGenerateRegoPolicy_MultiContainer verifies both init and main container image rules
// are generated, and that sha256-digest images with special characters are correctly escaped.
func TestGenerateRegoPolicy_MultiContainer(t *testing.T) {
	podYAML, err := os.ReadFile(sampleFile("samples", "hpcc", "multi-container-pod.yaml"))
	require.NoError(t, err)

	policy, _, _, err := GenerateRegoPolicy(string(podYAML), "")
	require.NoError(t, err)
	// init container image rule present
	assert.Contains(t, policy, `regex.match("^quay\\.io/prometheus/busybox:latest$", image_name)`)
	// main container sha256-digest image — dots and @ escaped correctly
	assert.Contains(t, policy, `regex.match("^quay\\.io/openshift-release-dev/ocp-v4\\.0-art-dev@sha256:`)
}

func TestGenerateRegoPolicy_EmptyYAML(t *testing.T) {
	_, _, _, err := GenerateRegoPolicy("", "")
	assert.ErrorIs(t, err, errEmptyParameter)
}

func TestGenerateRegoPolicy_InvalidYAML(t *testing.T) {
	_, _, _, err := GenerateRegoPolicy("invalid: yaml: content:", "")
	assert.Error(t, err)
}

func TestGenerateRegoPolicy_NoValidContainers(t *testing.T) {
	// Pod with containers that all have blank images — should return errNoContainers.
	podYAML := `
apiVersion: v1
kind: Pod
metadata:
  name: no-image-pod
spec:
  containers:
  - name: empty-image
    image: ""
`
	_, _, _, err := GenerateRegoPolicy(podYAML, "")
	assert.ErrorIs(t, err, errNoContainers)
}

func TestGenerateCommandRule_EmptyImage(t *testing.T) {
	_, _, err := generateCommandRule("mycontainer", "", []string{"/bin/sh"}, []string{"-c", "echo hi"})
	assert.ErrorIs(t, err, errEmptyImage)
}

// ─── escapeRegex ─────────────────────────────────────────────────────────────

func TestEscapeRegex(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"quay.io/prometheus/busybox:latest", "quay\\\\.io/prometheus/busybox:latest"},
		{"quay.io/openshift-release-dev/ocp-v4.0-art-dev@sha256:abc123", "quay\\\\.io/openshift-release-dev/ocp-v4\\\\.0-art-dev@sha256:abc123"},
		{"test[image]", "test\\\\[image\\\\]"},
		{"test(image)", "test\\\\(image\\\\)"},
		{"test*image", "test\\\\*image"},
		{"test+image", "test\\\\+image"},
		{"test?image", "test\\\\?image"},
		{"test^image$", "test^image$"},
		{"test{image}", "test\\\\{image\\\\}"},
		{"test|image", "test\\\\|image"},
		{"test\\image", "test\\\\\\image"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.want, escapeRegex(tt.input))
		})
	}
}

// ─── generateImageRule ────────────────────────────────────────────────────────

func TestGenerateImageRule(t *testing.T) {
	tests := []struct {
		image string
		want  []string
	}{
		{
			"quay.io/prometheus/busybox:latest",
			[]string{
				"allow_image(image_name) if {",
				`regex.match("^quay\\.io/prometheus/busybox:latest$", image_name)`,
			},
		},
		{
			"quay.io/openshift-release-dev/ocp-v4.0-art-dev@sha256:abc123",
			[]string{
				"allow_image(image_name) if {",
				`regex.match("^quay\\.io/openshift-release-dev/ocp-v4\\.0-art-dev@sha256:abc123$", image_name)`,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.image, func(t *testing.T) {
			result := generateImageRule(tt.image)
			for _, w := range tt.want {
				assert.Contains(t, result, w)
			}
		})
	}
}

// ─── generateCommandRule ──────────────────────────────────────────────────────

func TestGenerateCommandRule(t *testing.T) {
	tests := []struct {
		name    string
		image   string
		command []string
		args    []string
		want    []string
	}{
		{
			name:    "simple command with args",
			image:   "quay.io/prometheus/busybox:latest",
			command: []string{"/bin/sh"},
			args:    []string{"-c", "nginx -g 'daemon off;'"},
			want: []string{
				"allow_command(image_name, args) if {",
				`regex.match("^quay\\.io/prometheus/busybox:latest$", image_name)`,
				"count(args) == 3",
				`args[0] == "/bin/sh"`,
				`args[1] == "-c"`,
				`args[2] == "nginx -g 'daemon off;'"`,
			},
		},
		{
			name:    "command with quotes",
			image:   "quay.io/prometheus/busybox:latest",
			command: []string{"/bin/bash"},
			args:    []string{"-c", `echo "Hello World"`},
			want: []string{
				"allow_command(image_name, args) if {",
				`regex.match("^quay\\.io/prometheus/busybox:latest$", image_name)`,
				"count(args) == 3",
				`args[0] == "/bin/bash"`,
				`args[1] == "-c"`,
				"args[2] == `echo \"Hello World\"`",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, _, err := generateCommandRule("test-container", tt.image, tt.command, tt.args)
			require.NoError(t, err)
			for _, w := range tt.want {
				assert.Contains(t, result, w)
			}
		})
	}
}

// ─── scriptFuncName ──────────────────────────────────────────────────────────

func TestScriptFuncName(t *testing.T) {
	tests := []struct {
		name  string
		index int
		want  string
	}{
		{"my-init-container", 2, "validate_my_init_container_script_2"},
		{"busybox-init-masked", 2, "validate_busybox_init_masked_script_2"},
		{"simple", 0, "validate_simple_script_0"},
		{"", 1, "validate_container_script_1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, scriptFuncName(tt.name, tt.index))
		})
	}
}

// ─── generateCommandRule — script extraction ──────────────────────────────────

func TestGenerateCommandRule_MultilineScript(t *testing.T) {
	script := "set -e\necho hello\necho world\n"
	rule, validators, err := generateCommandRule("busybox-init-masked", "quay.io/prometheus/busybox:latest",
		[]string{"/bin/sh"}, []string{"-c", script})
	require.NoError(t, err)

	assert.Contains(t, rule, "validate_busybox_init_masked_script_2(args[2])")
	assert.NotContains(t, rule, "set -e")
	require.Len(t, validators, 1)
	assert.Contains(t, validators[0], "validate_busybox_init_masked_script_2(script) if {")
	assert.Contains(t, validators[0], script)
}

func TestGenerateCommandRule_SimpleArgNoValidator(t *testing.T) {
	rule, validators, err := generateCommandRule("app", "quay.io/prometheus/busybox:latest",
		[]string{"/bin/bash"}, []string{"-c", "sleep 90"})
	require.NoError(t, err)

	assert.Contains(t, rule, `args[2] == "sleep 90"`)
	assert.Empty(t, validators)
}

// ─── Policy structure invariants ──────────────────────────────────────────────

// TestCreateContainerRequest_AlwaysRequiresBothRules verifies the wiring rule requires
// both allow_image and allow_command for pods with and without explicit commands.
func TestCreateContainerRequest_AlwaysRequiresBothRules(t *testing.T) {
	files := []string{
		sampleFile("samples", "hpcc", "minimal-pod.yaml"),         // no command/args
		sampleFile("samples", "hpcc", "multi-container-pod.yaml"), // with command/args
	}
	const fullWiring = "CreateContainerRequest if {\n" +
		"    allow_image(input.OCI.Annotations[\"io.kubernetes.cri-o.ImageName\"])\n" +
		"    allow_command(input.OCI.Annotations[\"io.kubernetes.cri-o.ImageName\"], input.OCI.Process.Args)\n" +
		"}"
	const wiringWithoutCommand = "CreateContainerRequest if {\n" +
		"    allow_image(input.OCI.Annotations[\"io.kubernetes.cri-o.ImageName\"])\n" +
		"}"
	for _, f := range files {
		podYAML, err := os.ReadFile(f)
		require.NoError(t, err)

		policy, _, _, err := GenerateRegoPolicy(string(podYAML), "")
		require.NoError(t, err)
		assert.Contains(t, policy, fullWiring)
		// The 3-line wiring block must appear exactly once; the 2-line variant must not exist.
		assert.Equal(t, 1, strings.Count(policy, fullWiring))
		assert.Zero(t, strings.Count(policy, wiringWithoutCommand),
			"wiring rule must always include allow_command")
	}
}

// TestNoCommandPod_PermissiveAllowCommand verifies containers with no command/args get a
// permissive allow_command rule (image-only, no count constraint).
func TestNoCommandPod_PermissiveAllowCommand(t *testing.T) {
	podYAML, err := os.ReadFile(sampleFile("samples", "hpcc", "minimal-pod.yaml"))
	require.NoError(t, err)

	policy, _, _, err := GenerateRegoPolicy(string(podYAML), "")
	require.NoError(t, err)
	assert.Contains(t, policy, `regex.match("^quay\\.io/prometheus/busybox:latest$", image_name)`)
	assert.NotContains(t, policy, `regex.match("^quay\\.io/prometheus/busybox:latest$", image_name)`+"\n    count(args)")
	assert.Contains(t, policy, "allow_image(image_name) if")
}

// TestCommandPod_StrictAllowCommand verifies a container with explicit args generates a
// strict allow_command with count(args) and per-index arg checks.
func TestCommandPod_StrictAllowCommand(t *testing.T) {
	podYAML, err := os.ReadFile(sampleFile("samples", "hpcc", "multi-container-pod.yaml"))
	require.NoError(t, err)

	policy, _, _, err := GenerateRegoPolicy(string(podYAML), "")
	require.NoError(t, err)
	assert.Contains(t, policy, "count(args) == 3")
	assert.Contains(t, policy, "allow_command(image_name, args) if {")
}

// TestMultiContainerPod_DeduplicatesImages verifies that when init and main containers
// share an image, only one allow_image rule body is generated.
func TestMultiContainerPod_DeduplicatesImages(t *testing.T) {
	podYAML, err := os.ReadFile(sampleFile("samples", "hpcc", "kata-cc-pod.yaml"))
	require.NoError(t, err)

	policy, _, _, err := GenerateRegoPolicy(string(podYAML), "")
	require.NoError(t, err)
	// Both containers share quay.io/prometheus/busybox:latest — dedup means exactly one allow_image rule body.
	assert.Equal(t, 1, strings.Count(policy,
		"allow_image(image_name) if {\n    regex.match(\"^quay\\\\.io/prometheus/busybox:latest$\", image_name)\n}"))
}

// TestGenerateRegoPolicy_InsertionBeforeSandbox verifies generated allow_image rules
// appear before the default CreateSandboxRequest definition in the policy.
func TestGenerateRegoPolicy_InsertionBeforeSandbox(t *testing.T) {
	podYAML, err := os.ReadFile(sampleFile("samples", "hpcc", "kata-cc-pod.yaml"))
	require.NoError(t, err)

	policy, _, _, err := GenerateRegoPolicy(string(podYAML), "")
	require.NoError(t, err)

	allowImageStart := strings.Index(policy, `regex.match("^quay\\.io/prometheus/busybox`)
	sandboxDefault := strings.Index(policy, "default CreateSandboxRequest")
	assert.Greater(t, allowImageStart, -1, "allow_image rule must be present")
	assert.Less(t, allowImageStart, sandboxDefault, "allow_image rules must appear before default CreateSandboxRequest")
}

// ─── Template coverage ────────────────────────────────────────────────────────

func TestTemplate_CoversAllModuleQueryNames(t *testing.T) {
	names := []string{
		"AddARPNeighborsRequest", "AddSwapPathRequest", "AddSwapRequest",
		"CheckRequest", "CloseStdinRequest", "CopyFileRequest",
		"CreateContainerRequest", "CreateSandboxRequest", "DestroySandboxRequest",
		"ExecProcessRequest", "GetDiagnosticDataRequest", "GetIPTablesRequest",
		"GetMetricsRequest", "GetOOMEventRequest", "GuestDetailsRequest",
		"ListInterfacesRequest", "ListRoutesRequest",
		"MemAgentCompactConfig", "MemAgentMemcgConfig", "MemHotplugByProbeRequest",
		"OnlineCPUMemRequest", "PauseContainerRequest", "ReadStreamRequest",
		"RemoveContainerRequest", "RemoveStaleVirtiofsShareMountsRequest",
		"ReseedRandomDevRequest", "ResizeVolumeRequest", "ResumeContainerRequest",
		"SetGuestDateTimeRequest", "SetIPTablesRequest", "SetPolicyRequest",
		"SignalProcessRequest", "StartContainerRequest", "StatsContainerRequest",
		"TtyWinResizeRequest", "UpdateContainerRequest", "UpdateEphemeralMountsRequest",
		"UpdateInterfaceRequest", "UpdateRoutesRequest", "VolumeStatsRequest",
		"WaitProcessRequest", "WriteStreamRequest",
	}
	podYAML, err := os.ReadFile(sampleFile("samples", "hpcc", "minimal-pod.yaml"))
	require.NoError(t, err)

	policy, _, _, err := GenerateRegoPolicy(string(podYAML), "")
	require.NoError(t, err)
	for _, name := range names {
		assert.True(t,
			strings.Contains(policy, "default "+name+" :=") || strings.Contains(policy, name+" if {"),
			"template must define %q", name)
	}
}

func TestTemplate_NoDeadRules(t *testing.T) {
	dead := []string{
		"GetVolumeStatsRequest", "WriteStdinRequest", "ReadStdoutRequest",
		"ReadStderrRequest", "VersionRequest", "PullImageRequest",
		"StartTracingRequest", "StopTracingRequest",
	}
	podYAML, err := os.ReadFile(sampleFile("samples", "hpcc", "minimal-pod.yaml"))
	require.NoError(t, err)

	policy, _, _, err := GenerateRegoPolicy(string(podYAML), "")
	require.NoError(t, err)
	for _, name := range dead {
		assert.False(t, strings.Contains(policy, "default "+name),
			"dead rule %q must not appear in the template", name)
	}
}

// ─── kata-cc-pod end-to-end (hpcc sample) ────────────────────────────────────

// kataCCPolicy is a shared helper that reads kata-cc-pod.yaml and generates its policy once.
func kataCCPolicy(t *testing.T) string {
	t.Helper()
	podYAML, err := os.ReadFile(sampleFile("samples", "hpcc", "kata-cc-pod.yaml"))
	require.NoError(t, err)
	policy, _, _, err := GenerateRegoPolicy(string(podYAML), "")
	require.NoError(t, err)
	return policy
}

func TestKataCCPod_GeneratePolicy(t *testing.T) {
	policy := kataCCPolicy(t)

	assert.Equal(t, 1, strings.Count(policy, "package agent_policy"))
	assert.Contains(t, policy,
		"CreateContainerRequest if {\n"+
			"    allow_image(input.OCI.Annotations[\"io.kubernetes.cri-o.ImageName\"])\n"+
			"    allow_command(input.OCI.Annotations[\"io.kubernetes.cri-o.ImageName\"], input.OCI.Process.Args)\n"+
			"}")
	assert.Equal(t, 1, strings.Count(policy, "CreateContainerRequest if {"))
	assert.Contains(t, policy,
		`regex.match("^quay\\.io/openshift-release-dev/ocp-v4\\.0-art-dev@sha256:[a-f0-9]{64}$", image_name)`)
}

func TestKataCCPod_InitContainer(t *testing.T) {
	policy := kataCCPolicy(t)

	assert.Contains(t, policy, `regex.match("^quay\\.io/prometheus/busybox:latest$", image_name)`)
	assert.Contains(t, policy, `count(args) == 3`)
	assert.Contains(t, policy, `args[0] == "/bin/sh"`)
	assert.Contains(t, policy, `args[1] == "-c"`)
	assert.Contains(t, policy, "echo \"Check resolv.conf\"\ncat /etc/resolv.conf\n")
}

func TestKataCCPod_MainContainer(t *testing.T) {
	policy := kataCCPolicy(t)

	assert.Contains(t, policy, `count(args) == 4`)
	assert.Contains(t, policy, `args[2] == "sleep 90"`)
	assert.Contains(t, policy, `echo "Container started"; sleep 90; echo "Crashing now"; exit 1`)
}

func TestKataCCPod_PolicyStructure(t *testing.T) {
	policy := kataCCPolicy(t)

	busyboxIdx := strings.Index(policy, `regex.match("^quay\\.io/prometheus/busybox`)
	sandboxIdx := strings.Index(policy, "default CreateSandboxRequest")
	ocpIdx := strings.Index(policy, `regex.match("^quay\\.io/openshift-release-dev`)
	assert.Less(t, busyboxIdx, sandboxIdx, "generated rules must appear before default CreateSandboxRequest")
	assert.Less(t, ocpIdx, busyboxIdx, "OCP baseline must appear before pod image rules")
}

func TestKataCCPod_PauseContainerSemantics(t *testing.T) {
	policy := kataCCPolicy(t)

	assert.Contains(t, policy, "default PauseContainerRequest := false")
	assert.False(t, strings.Contains(policy, "PauseContainerRequest if {"))
}

// ─── Multiline script end-to-end ──────────────────────────────────────────────

// TestMultilineScript_PolicyOutput verifies the kata-cc-pod init container's multiline
// script is extracted into a named validator function.
func TestMultilineScript_PolicyOutput(t *testing.T) {
	policy := kataCCPolicy(t)

	assert.Contains(t, policy, "validate_busybox_init_masked_script_2(args[2])")
	assert.Contains(t, policy, "validate_busybox_init_masked_script_2(script) if {")
	assert.Contains(t, policy, "echo \"Check resolv.conf\"")

	cmdIdx := strings.Index(policy, "allow_command(image_name, args) if {")
	validatorIdx := strings.Index(policy, "validate_busybox_init_masked_script_2(script) if {")
	assert.Greater(t, validatorIdx, cmdIdx)
}

// ─── Benchmark ────────────────────────────────────────────────────────────────

func BenchmarkGenerateRegoPolicy(b *testing.B) {
	podYAML, err := os.ReadFile(sampleFile("samples", "hpcc", "minimal-pod.yaml"))
	require.NoError(b, err)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _, _ = GenerateRegoPolicy(string(podYAML), "")
	}
}
