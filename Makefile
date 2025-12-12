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
