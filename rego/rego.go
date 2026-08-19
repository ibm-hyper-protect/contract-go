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
	_ "embed"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"
)

var (
	// errEmptyParameter is returned when a required string parameter is blank.
	errEmptyParameter = errors.New("required parameter is empty")
	// errNoContainers is returned when the pod spec contains no containers with a non-empty image.
	errNoContainers = errors.New("pod spec contains no containers with a valid image")
	// errEmptyImage is returned when generateCommandRule is called with a blank image.
	errEmptyImage = errors.New("container image must not be empty")
)

const marker = "# --- generator inserts CreateContainerRequest, allow_image, and allow_command rules here ---"

//go:embed sample-policy.rego
var defaultTemplate string

// containerEntry holds pre-generated rules for one pod container.
type containerEntry struct {
	image            string
	imageRule        string
	commandRule      string
	scriptValidators []string
}

// GenerateRegoPolicy generates an OPA v1 Rego policy from a Kubernetes pod YAML.
// It extracts container images and commands from the pod spec and generates
// allow_image() and allow_command() rules inserted at the marker in the template.
// If templatePath is empty, the embedded sample-policy.rego is used.
//
// Returns:
//   - policy: the generated Rego policy as a plain string
//   - podYAMLBase64: standard base64 encoding of the input pod YAML
//   - policyBase64: standard base64 encoding of the generated policy
//   - error: non-nil if the pod YAML is empty, unparseable, or the template cannot be read
func GenerateRegoPolicy(podYAML string, templatePath string) (policy, podYAMLBase64, policyBase64 string, err error) {
	if strings.TrimSpace(podYAML) == "" {
		return "", "", "", errEmptyParameter
	}

	var pod corev1.Pod
	if e := yaml.Unmarshal([]byte(podYAML), &pod); e != nil {
		return "", "", "", fmt.Errorf("failed to unmarshal pod YAML: %w", e)
	}

	tmpl, e := readTemplate(templatePath)
	if e != nil {
		return "", "", "", fmt.Errorf("failed to read template: %w", e)
	}

	entries := extractContainerEntries(&pod)
	if len(entries) == 0 {
		return "", "", "", errNoContainers
	}
	policy = generatePolicy(
		tmpl,
		imageRulesFrom(entries),
		commandRulesFrom(entries),
		scriptValidatorsFrom(entries),
	)
	podYAMLBase64 = base64.StdEncoding.EncodeToString([]byte(podYAML))
	policyBase64 = base64.StdEncoding.EncodeToString([]byte(policy))
	return policy, podYAMLBase64, policyBase64, nil
}

func readTemplate(templatePath string) (string, error) {
	if templatePath == "" {
		return defaultTemplate, nil
	}
	content, err := os.ReadFile(templatePath)
	if err != nil {
		return "", fmt.Errorf("failed to read template file: %w", err)
	}
	return string(content), nil
}

// extractContainerEntries builds one containerEntry per container (init first, then main).
// Containers with command/args get a strict allow_command; those without get a permissive
// allow_command (image-only, no arg constraint) to admit ENTRYPOINT-only images.
func extractContainerEntries(pod *corev1.Pod) []containerEntry {
	var entries []containerEntry
	all := append(append([]corev1.Container{}, pod.Spec.InitContainers...), pod.Spec.Containers...)
	for _, c := range all {
		if c.Image == "" {
			continue
		}
		e := containerEntry{
			image:     c.Image,
			imageRule: generateImageRule(c.Image),
		}
		if len(c.Command) > 0 || len(c.Args) > 0 {
			rule, validators, err := generateCommandRule(c.Name, c.Image, c.Command, c.Args)
			if err != nil {
				// image was already validated non-empty above; this path is unreachable
				// in normal flow but guards against direct internal calls.
				continue
			}
			e.commandRule, e.scriptValidators = rule, validators
		} else {
			e.commandRule = generatePermissiveCommandRule(c.Image)
		}
		entries = append(entries, e)
	}
	return entries
}

// imageRulesFrom returns deduplicated allow_image() rules from pre-computed entries.
func imageRulesFrom(entries []containerEntry) []string {
	seen := make(map[string]bool)
	var rules []string
	for _, e := range entries {
		if !seen[e.image] {
			seen[e.image] = true
			rules = append(rules, e.imageRule)
		}
	}
	return rules
}

// commandRulesFrom returns allow_command() rules from pre-computed entries.
func commandRulesFrom(entries []containerEntry) []string {
	var rules []string
	for _, e := range entries {
		if e.commandRule != "" {
			rules = append(rules, e.commandRule)
		}
	}
	return rules
}

// scriptValidatorsFrom returns named script validator rules from pre-computed entries.
func scriptValidatorsFrom(entries []containerEntry) []string {
	var validators []string
	for _, e := range entries {
		validators = append(validators, e.scriptValidators...)
	}
	return validators
}

// generateImageRule creates an allow_image() rule with an anchored regex.
func generateImageRule(image string) string {
	return fmt.Sprintf(`allow_image(image_name) if {
    regex.match("^%s$", image_name)
}`, escapeRegex(image))
}

// generatePermissiveCommandRule creates an allow_command() rule that validates only
// the image name. Used for containers with no command/args in the pod spec — they rely
// on the image's baked-in ENTRYPOINT/CMD whose args are not predictable at generation time.
func generatePermissiveCommandRule(image string) string {
	return fmt.Sprintf(`allow_command(image_name, args) if {
    regex.match("^%s$", image_name)
}`, escapeRegex(image))
}

// generateCommandRule creates a strict allow_command() rule and any named script validator
// functions for multiline script args.
//
// CRI-O sets OCI.Process.Args = pod.command + pod.args, so both slices are concatenated.
// Simple args are inlined; multiline args (containing \n) are extracted to named validators.
// Returns an error if image is empty.
func generateCommandRule(containerName string, image string, command []string, args []string) (string, []string, error) {
	if image == "" {
		return "", nil, errEmptyImage
	}
	escapedImage := escapeRegex(image)
	fullCommand := make([]string, len(command)+len(args))
	copy(fullCommand, command)
	copy(fullCommand[len(command):], args)

	var argChecks []string
	var scriptValidators []string

	for i, arg := range fullCommand {
		if strings.Contains(arg, "\n") {
			funcName := scriptFuncName(containerName, i)
			argChecks = append(argChecks, fmt.Sprintf("    %s(args[%d])", funcName, i))
			escapedScript := strings.ReplaceAll(arg, "`", "` + \"`\" + `")
			scriptValidators = append(scriptValidators, fmt.Sprintf(
				"%s(script) if {\n    script == `%s`\n}", funcName, escapedScript))
		} else if strings.Contains(arg, `"`) || strings.Contains(arg, `\`) {
			escapedArg := strings.ReplaceAll(arg, "`", "` + \"`\" + `")
			argChecks = append(argChecks, fmt.Sprintf("    args[%d] == `%s`", i, escapedArg))
		} else {
			argChecks = append(argChecks, fmt.Sprintf(`    args[%d] == "%s"`, i, arg))
		}
	}

	rule := fmt.Sprintf(`allow_command(image_name, args) if {
    regex.match("^%s$", image_name)
    count(args) == %d
%s
}`, escapedImage, len(fullCommand), strings.Join(argChecks, "\n"))

	return rule, scriptValidators, nil
}

// scriptFuncName derives a valid OPA identifier from a container name and arg index.
// Hyphens are replaced with underscores; non-word characters are dropped.
func scriptFuncName(containerName string, argIndex int) string {
	safe := strings.ReplaceAll(containerName, "-", "_")
	var b strings.Builder
	for _, r := range safe {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			b.WriteRune(r)
		}
	}
	name := b.String()
	if name == "" {
		name = "container"
	}
	return fmt.Sprintf("validate_%s_script_%d", name, argIndex)
}

// escapeRegex escapes regex special characters for use inside a Rego double-quoted
// regex.match() string. Backslash is escaped first to prevent double-escaping.
func escapeRegex(s string) string {
	specialChars := []string{"\\", ".", "*", "+", "?", "{", "}", "(", ")", "|", "[", "]"}
	result := s
	for _, char := range specialChars {
		result = strings.ReplaceAll(result, char, "\\\\"+char)
	}
	return result
}

// generatePolicy replaces the generator marker in the template with the generated rules.
// If the marker is absent (custom template), rules are appended at the end.
//
// Insertion order at the marker:
//  1. CreateContainerRequest — wires allow_image + allow_command
//  2. OCP baseline allow_image — admits pause/infra containers (digest-pinned)
//  3. Pod allow_image rules — one per unique image
//  4. OCP baseline allow_command — permissive, digest-pinned
//  5. Pod allow_command rules — strict or permissive per container
//  6. Script validators — one per multiline script arg
func generatePolicy(template string, imageRules, commandRules, scriptValidators []string) string {

	markerIdx := strings.Index(template, marker)
	if markerIdx == -1 {
		return appendRulesToEnd(template, imageRules, commandRules, scriptValidators)
	}

	markerLineEnd := markerIdx + len(marker)
	if markerLineEnd < len(template) && template[markerLineEnd] == '\n' {
		markerLineEnd++
	}

	var s strings.Builder

	s.WriteString("CreateContainerRequest if {\n")
	s.WriteString("    allow_image(input.OCI.Annotations[\"io.kubernetes.cri-o.ImageName\"])\n")
	s.WriteString("    allow_command(input.OCI.Annotations[\"io.kubernetes.cri-o.ImageName\"], input.OCI.Process.Args)\n")
	s.WriteString("}\n\n")

	s.WriteString("# Image allowlist\n")
	s.WriteString("# OCP baseline: allows the Kata pause/infra container and OCP system containers.\n")
	s.WriteString("allow_image(image_name) if {\n")
	s.WriteString("    regex.match(\"^quay\\\\.io/openshift-release-dev/ocp-v4\\\\.0-art-dev@sha256:[a-f0-9]{64}$\", image_name)\n")
	s.WriteString("}\n\n")
	for _, rule := range imageRules {
		s.WriteString(rule)
		s.WriteString("\n\n")
	}

	s.WriteString("# Command allowlist\n")
	s.WriteString("# OCP baseline: pause/infra and system containers — args not constrained.\n")
	s.WriteString("allow_command(image_name, args) if {\n")
	s.WriteString("    regex.match(\"^quay\\\\.io/openshift-release-dev/ocp-v4\\\\.0-art-dev@sha256:[a-f0-9]{64}$\", image_name)\n")
	s.WriteString("}\n\n")
	for _, rule := range commandRules {
		s.WriteString(rule)
		s.WriteString("\n\n")
	}

	if len(scriptValidators) > 0 {
		s.WriteString("# Script validators\n")
		for _, v := range scriptValidators {
			s.WriteString(v)
			s.WriteString("\n\n")
		}
	}

	var out strings.Builder
	out.WriteString(template[:markerIdx])
	out.WriteString(s.String())
	out.WriteString(template[markerLineEnd:])
	return out.String()
}

// appendRulesToEnd appends generated rules to a custom template that has no marker.
func appendRulesToEnd(template string, imageRules, commandRules, scriptValidators []string) string {
	var b strings.Builder
	b.WriteString(template)
	b.WriteString("\n\n# Auto-generated rules from pod specification\n")
	b.WriteString("\nCreateContainerRequest if {\n")
	b.WriteString("    allow_image(input.OCI.Annotations[\"io.kubernetes.cri-o.ImageName\"])\n")
	b.WriteString("    allow_command(input.OCI.Annotations[\"io.kubernetes.cri-o.ImageName\"], input.OCI.Process.Args)\n")
	b.WriteString("}\n")
	if len(imageRules) > 0 {
		b.WriteString("\n# Auto-generated image allowlist rules\n")
		for _, rule := range imageRules {
			b.WriteString(rule)
			b.WriteString("\n\n")
		}
	}
	if len(commandRules) > 0 {
		b.WriteString("# Auto-generated command validation rules\n")
		for _, rule := range commandRules {
			b.WriteString(rule)
			b.WriteString("\n\n")
		}
	}
	if len(scriptValidators) > 0 {
		b.WriteString("# Auto-generated script validators\n")
		for _, v := range scriptValidators {
			b.WriteString(v)
			b.WriteString("\n\n")
		}
	}
	return b.String()
}
