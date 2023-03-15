#!/bin/sh

echo Install easyjson
go get github.com/mailru/easyjson && go install github.com/mailru/easyjson/...@latest

echo Generate easyjson helper files
easyjson -all \
  capabilities/types.go \
  protocol/types.go

echo "Don't forget to run \`go mod tidy\`"
