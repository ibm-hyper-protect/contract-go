default: test

test: 
	go test ./...

test-cover:
	go test -coverprofile build/cover.out ./...
	go tool cover -html=build/cover.out

update-packages:
	go get -u all

tidy:
	go mod tidy

.PHONY: default test test-cover update-packages tidy