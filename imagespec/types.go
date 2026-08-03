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

// AuthConfig holds optional registry credentials for private image access.
type AuthConfig struct {
	Username string
	Password string
}

// containerSnippet wraps the containers list under a "spec:" key so the
// output can be pasted directly into a StatefulSet / Deployment manifest.
type containerSnippet struct {
	Spec specSnippet `yaml:"spec"`
}

type specSnippet struct {
	Containers []containerSpec `yaml:"containers"`
}

type containerSpec struct {
	Name            string          `yaml:"name"`
	Image           string          `yaml:"image"`
	SecurityContext *secCtx         `yaml:"securityContext,omitempty"`
	Env             []envVar        `yaml:"env,omitempty"`
	Command         []string        `yaml:"command,omitempty"`
	Args            []string        `yaml:"args,omitempty"`
	WorkingDir      string          `yaml:"workingDir,omitempty"`
	Ports           []containerPort `yaml:"ports,omitempty"`
}

type secCtx struct {
	RunAsUser                *int64 `yaml:"runAsUser,omitempty"`
	RunAsGroup               *int64 `yaml:"runAsGroup,omitempty"`
	AllowPrivilegeEscalation *bool  `yaml:"allowPrivilegeEscalation,omitempty"`
}

type envVar struct {
	Name  string `yaml:"name"`
	Value string `yaml:"value"`
}

type containerPort struct {
	ContainerPort int32  `yaml:"containerPort"`
	Protocol      string `yaml:"protocol,omitempty"`
}
