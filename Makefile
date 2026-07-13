# Copyright (c) 2025 IBM Corp.
# All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

default: test

help:
	@echo "Available targets:"
	@echo "  help             - Display this help message"
	@echo "  install-deps     - Download Go module dependencies"
	@echo "  test             - Run all tests with verbose output"
	@echo "  test-cover       - Run tests with coverage report"
	@echo "  update-packages  - Update all Go module dependencies"
	@echo "  tidy             - Tidy Go module dependencies"
	@echo "  clean            - Remove build artifacts"
	@echo "  fmt              - Format all Go source files"

install-deps:
	go mod download

test:
	go test ./... -v

test-cover:
	go test -coverprofile build/cover.out ./...
	go tool cover -html=build/cover.out

update-packages:
	go get -u all

tidy:
	go mod tidy

clean:
	find ./build ! -name '.gitkeep' -type f -delete

fmt:
	go fmt ./...

.PHONY: default help install-deps test test-cover update-packages tidy clean fmt
