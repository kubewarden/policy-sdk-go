#!/bin/sh
set -e

echo Install easyjson
go get github.com/mailru/easyjson && go install github.com/mailru/easyjson/...@latest
go get github.com/mailru/easyjson/gen
go get github.com/mailru/easyjson/jlexer
go get github.com/mailru/easyjson/jwriter

echo Temporarily remove vendor directory
# easyjson doesn't work nicely when a project uses the vendor directory
rm -rf vendor

echo Generate easyjson helper files
easyjson -all \
  capabilities/types.go \
  protocol/types.go

echo Update vendor directory
go mod tidy
go mod vendor
