@echo off
mkdir build 2> NUL
set GOOS=linux
go build -o build/contract-go-linux main.go
docker run --rm -it -v %cd%/build:/go/bin -p 8000:8000 odedp/go-binsize-viz -b /go/bin/contract-go-linux

