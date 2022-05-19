//go:build !wasi
// +build !wasi

// note well: we have to use the tinygo wasi target, because the wasm one is
// meant to be used inside of the browser

package host_capabilities

import (
	"encoding/json"
	"errors"
)

type MockWapcClient struct {
	err             error
	payloadResponse []byte
}

// Create a new MockWapcClient that simulates a host failing
// whenever one of its capabilities is invoked by the policy.
// The error returned by the host is the one provided at construction time
func NewFailingMockWapcClient(err error) *MockWapcClient {
	return &MockWapcClient{
		payloadResponse: []byte{},
		err:             err,
	}
}

// Create a new MockWapcClient that simulates a host successfully
// completing a request made by the policy.
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
		payloadResponse: payload,
		err:             nil,
	}, nil
}

func (m *MockWapcClient) HostCall(binding, namespace, operation string, payload []byte) (response []byte, err error) {
	return m.payloadResponse, m.err
}

// NewHost creates a Host that has a mock waPC client.
func NewHost() Host {
	err := errors.New("Native code should overwrite the default `Host.Client` with one created via `NewSuccessfulMockWapcClient` or `NewFailingMockWapcClient`")

	return Host{
		Client: NewFailingMockWapcClient(err),
	}
}
