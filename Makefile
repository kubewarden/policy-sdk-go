ROOT_DIR:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
BIN_DIR := $(abspath $(ROOT_DIR)/bin)

GOLANGCI_LINT_VER := v1.59.1
GOLANGCI_LINT_BIN := golangci-lint
GOLANGCI_LINT := $(BIN_DIR)/$(GOLANGCI_LINT_BIN)

# Run go fmt against code
fmt:
	go fmt ./...

# Run go vet against code
vet:
	go vet ./...

deps:
	go get github.com/golangci/golangci-lint/cmd/golangci-lint
	go install github.com/vektra/mockery/v2@v2.43.2

generate-mocks:
	mockery

golangci-lint: $(GOLANGCI_LINT) ## Install a local copy of golang ci-lint.
$(GOLANGCI_LINT): ## Install golangci-lint.
	GOBIN=$(BIN_DIR) go install github.com/golangci/golangci-lint/cmd/golangci-lint@$(GOLANGCI_LINT_VER)

.PHONY: lint
lint: $(GOLANGCI_LINT)
	go vet ./...
	$(GOLANGCI_LINT) run

.PHONY: lint-fix
lint-fix: $(GOLANGCI_LINT)
	$(GOLANGCI_LINT) run --fix

# Run tests
test: fmt vet
	go test ./... -coverprofile cover.out

