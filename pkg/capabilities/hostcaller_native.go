//go:build !wasi && !wasip1
// +build !wasi,!wasip1

// note well: we have to use the tinygo wasi target, because the wasm one is
// meant to be used inside of the browser

package capabilities

import (
	"encoding/json"
	"errors"
)

// MockWapcClient is implements the `host.WapcClient` interface.
// It's purpose is to be used by the unit tests of policies that leverage
// host capabilities
type MockWapcClient struct {
	Err             error
	PayloadResponse []byte
}

// HostCall implements the `host.WapcClient` interface
func (m *MockWapcClient) HostCall(binding, namespace, operation string, payload []byte) (response []byte, err error) {
	return m.PayloadResponse, m.Err
}

// NewFailingMockWapcClient creates a new MockWapcClient that simulates a host
// failing whenever one of its capabilities is invoked by the policy.
// The error returned by the host is the one provided at construction time
func NewFailingMockWapcClient(err error) *MockWapcClient {
	return &MockWapcClient{
		PayloadResponse: []byte{},
		Err:             err,
	}
}

// NewSuccessfulMockWapcClient creates  a new MockWapcClient that simulates a
// host successfully completing a request made by the policy.
// The response is going to be the `responseObj` serialized to JSON.
// Use the right response type object that is defined inside of the `types.go`
// file of this package.
//
// This function can fail if the `responseObj` provided by the user cannot be
// encoded to JSON.
func NewSuccessfulMockWapcClient(responseObj interface{}) (*MockWapcClient, error) {
	payload, err := json.Marshal(responseObj)
	if err != nil {
		return nil, err
	}

	return &MockWapcClient{
		PayloadResponse: payload,
		Err:             nil,
	}, nil
}

// NewHost creates a Host that has a mock waPC client.
func NewHost() Host {
	err := errors.New("Native code should overwrite the default `Host.Client` with one created via `NewSuccessfulMockWapcClient` or `NewFailingMockWapcClient`")

	return Host{
		Client: NewFailingMockWapcClient(err),
	}
}
