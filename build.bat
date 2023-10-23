@echo off
mkdir build 2> NUL
go build -ldflags="-s -w" -o build/contract-go.exe main.go