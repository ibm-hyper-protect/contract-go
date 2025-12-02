default: test

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

.PHONY: default install-deps test test-cover update-packages tidy clean fmt
