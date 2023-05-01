#!/bin/sh
set -e

echo Install GoMock
go install github.com/golang/mock/mockgen@v1.6.0

echo Generate GoMock helper files
mockgen --build_flags=--mod=mod -destination mock/capabilities/capabilities_mock.go -package capabilities github.com/kubewarden/policy-sdk-go/pkg/capabilities WapcClient
